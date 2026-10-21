"""
Offline evaluation: TrustLex vs. the B1 lexical linter vs. the B2 runtime
keyword filter, over the labelled corpus and the attack set.

    python eval/run_eval.py [--out DIR] [--seed SEED]

Outputs (in eval/results/ by default):
    detection.csv      one row per program: ground truth and each method's verdict
    leaks.csv          one row per (program, attack, condition)
    sanitizer.csv      one row per attack: what survives the default sanitizer
    eval_summary.json  metrics and metadata

TrustLex's analysis is exact for this language, so it is expected to score
perfectly on detection; the comparison exists to show where the baselines
fail. No network access is used.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from baselines import b1_findings, b2_flags, b2_match  # noqa: E402
from common import (  # noqa: E402
    DEFAULT_SEED, canary, confusion, load_attacks, load_benign, metadata, results_dir, structural_markers,
    with_canary,
)
from corpus_loader import load_corpus  # noqa: E402
from naive import naive_render, system_text  # noqa: E402

from codegen import BindError, SanitizerConfig, clean, compile_source, default_sanitizer  # noqa: E402


def _values(inputs: list[str], text: str) -> dict[str, str]:
    """The attacker controls every input of the program."""
    return {name: text for name in inputs}


def _input_names(source: str) -> list[str]:
    from parser_ast import InputDecl, parse
    return [s.name for s in parse(source, "<eval>").program.statements if isinstance(s, InputDecl)]


def _system_wrappers(compiled) -> int:
    """How many <untrusted_input> pairs TrustLex itself puts in the system text."""
    from codegen import SlotPart
    return sum(
        1 for m in compiled.messages if m.role == "system" for p in m.parts
        if isinstance(p, SlotPart) and (p.sanitize or (compiled.delimit_untrusted
                                                       and compiled.inputs[p.input]["trust"] != "VALIDATED"))
    )


def _leak_row(program, attack, condition, outcome, system: str | None, payload: str, token: str,
              wrappers: int = 0) -> dict:
    markers = structural_markers(system, wrappers) if system is not None else []
    return {
        "program": program.name, "category": program.category, "truth": "unsafe" if program.unsafe else "safe",
        "attack": attack["id"], "attack_category": attack["category"], "condition": condition,
        "outcome": outcome,
        "canary_in_system": int(system is not None and token in system),
        "raw_text_in_system": int(system is not None and payload in system),
        "structural_leak": int(bool(markers)),
        "markers": "; ".join(markers),
        "b2_flagged": int(system is not None and b2_flags(system)) if condition == "naive" else "",
    }


def evaluate(out: Path, seed: str = DEFAULT_SEED) -> dict:
    corpus = load_corpus()
    attacks = load_attacks()
    benign = load_benign()

    compiled_by_name = {}
    detection_rows, leak_rows = [], []
    b2_program_flag = defaultdict(bool)

    for program in corpus:
        checked, compiled = compile_source(program.source, program.path.name)
        compiled_by_name[program.name] = compiled
        inputs = _input_names(program.source)
        for attack in attacks:
            token = canary("run_eval", program.name, attack["id"], seed=seed)
            payload = with_canary(attack, token)
            values = _values(inputs, payload)

            naive_system = system_text(naive_render(program.source, values))
            row = _leak_row(program, attack, "naive", "rendered", naive_system, payload, token)
            leak_rows.append(row)
            b2_program_flag[program.name] |= bool(row["b2_flagged"])

            if compiled is None:
                leak_rows.append(_leak_row(program, attack, "trustlex", "blocked-compile", None, payload, token))
                continue
            try:
                rendered = compiled.render(values)
            except BindError as exc:
                leak_rows.append(_leak_row(program, attack, "trustlex", f"blocked-bind {exc.code}", None, payload, token))
                continue
            leak_rows.append(_leak_row(program, attack, "trustlex", "rendered", system_text(rendered), payload, token,
                                       _system_wrappers(compiled)))

        detection_rows.append({
            "program": program.name, "category": program.category,
            "truth": "unsafe" if program.unsafe else "safe",
            "trustlex": "unsafe" if compiled is None else "safe",
            "trustlex_codes": " ".join(d.code for d in checked.diagnostics.errors),
            "b1": "unsafe" if b1_findings(program.source) else "safe",
            "b1_findings": " ".join(b1_findings(program.source)),
            "b2": "unsafe" if b2_program_flag[program.name] else "safe",
        })

    # B2 false positives on benign inputs (rendered naively, like the attacks).
    benign_rows = []
    for program in corpus:
        inputs = _input_names(program.source)
        for item in benign:
            system = system_text(naive_render(program.source, _values(inputs, item["text"])))
            if item["text"] in system:
                benign_rows.append({"program": program.name, "benign": item["id"], "flagged": b2_flags(system),
                                    "match": b2_match(system) or ""})

    # What survives the default sanitizer on its own: clean(), then spotlight().
    sanitize = default_sanitizer(SanitizerConfig(), {"x": {"source": "user"}})
    sanitizer_rows = []
    for attack in attacks:
        payload = with_canary(attack, canary("sanitizer", attack["id"], seed=seed))
        cleaned = clean(payload)
        sanitizer_rows.append({
            "attack": attack["id"], "attack_category": attack["category"], "notes": attack["notes"],
            "changed_by_clean": int(cleaned != payload),
            "structural_markers_before": "; ".join(structural_markers(payload)),
            "structural_markers_after": "; ".join(structural_markers(sanitize(payload, "x"), wrappers=1)),
            "survives_structurally": int(bool(structural_markers(sanitize(payload, "x"), wrappers=1))),
            "b2_flags_after_clean": int(b2_flags(cleaned)),
        })

    _write_csv(out / "detection.csv", detection_rows)
    _write_csv(out / "leaks.csv", leak_rows)
    _write_csv(out / "sanitizer.csv", sanitizer_rows)
    summary = _summarize(corpus, attacks, benign, detection_rows, leak_rows, benign_rows, sanitizer_rows, seed)
    (out / "eval_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def _write_csv(path: Path, rows: list[dict]):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _rate(rows, key) -> dict:
    n = len(rows)
    k = sum(int(r[key]) for r in rows)
    return {"n": n, "count": k, "rate": round(k / n, 4) if n else 0.0}


def _summarize(corpus, attacks, benign, detection, leaks, benign_rows, sanitizer_rows, seed) -> dict:
    truth = [r["truth"] == "unsafe" for r in detection]
    methods = {m: confusion(truth, [r[m] == "unsafe" for r in detection]) for m in ("trustlex", "b1", "b2")}

    naive = [r for r in leaks if r["condition"] == "naive"]
    trust = [r for r in leaks if r["condition"] == "trustlex"]
    trust_rendered = [r for r in trust if r["outcome"] == "rendered"]
    outcomes = Counter(r["outcome"].split()[0] for r in trust)

    leaking_naive = [r for r in naive if r["canary_in_system"]]
    b2_by_category = {}
    for category in sorted({a["category"] for a in attacks}):
        rows = [r for r in leaking_naive if r["attack_category"] == category]
        b2_by_category[category] = _rate(rows, "b2_flagged")

    def by(rows, key):
        return {k: {"canary_in_system": _rate([r for r in rows if r[key] == k], "canary_in_system"),
                    "structural_leak": _rate([r for r in rows if r[key] == k], "structural_leak")}
                for k in sorted({r[key] for r in rows})}

    return {
        "metadata": metadata(seed=seed, script="eval/run_eval.py"),
        "corpus": {
            "programs": len(corpus), "unsafe": sum(c.unsafe for c in corpus), "safe": sum(not c.unsafe for c in corpus),
            "by_category": dict(Counter(c.category for c in corpus)),
            "attacks": len(attacks), "attack_categories": dict(Counter(a["category"] for a in attacks)),
            "benign_inputs": len(benign),
        },
        "detection": methods,
        "detection_note": "TrustLex's analysis is exact for this straight-line language, so a perfect score is "
                          "expected; the comparison shows where the baselines fail.",
        "leaks": {
            "naive": {"pairs": len(naive), "canary_in_system": _rate(naive, "canary_in_system"),
                      "raw_text_in_system": _rate(naive, "raw_text_in_system"),
                      "structural_leak": _rate(naive, "structural_leak")},
            "trustlex": {"pairs": len(trust), "outcomes": dict(outcomes),
                         "canary_in_system": _rate(trust, "canary_in_system"),
                         "raw_text_in_system": _rate(trust, "raw_text_in_system"),
                         "structural_leak": _rate(trust, "structural_leak"),
                         "rendered_only": {"canary_in_system": _rate(trust_rendered, "canary_in_system"),
                                           "raw_text_in_system": _rate(trust_rendered, "raw_text_in_system"),
                                           "structural_leak": _rate(trust_rendered, "structural_leak")}},
            "naive_by_attack_category": by(naive, "attack_category"),
            "trustlex_by_attack_category": by(trust, "attack_category"),
        },
        "b2": {
            "catch_rate_on_leaking_pairs": _rate(leaking_naive, "b2_flagged"),
            "catch_rate_by_attack_category": b2_by_category,
            "benign_false_positive": _rate(benign_rows, "flagged"),
            "benign_false_positive_by_input": {
                b["id"]: _rate([r for r in benign_rows if r["benign"] == b["id"]], "flagged") for b in benign},
        },
        "sanitizer": {
            "attacks": len(sanitizer_rows),
            "changed_by_clean": sum(r["changed_by_clean"] for r in sanitizer_rows),
            "survive_structurally": [r["attack"] for r in sanitizer_rows if r["survives_structurally"]],
            "text_survives_by_design": [r["attack"] for r in sanitizer_rows if not r["structural_markers_before"]],
            "b2_still_flags_after_clean": [r["attack"] for r in sanitizer_rows if r["b2_flags_after_clean"]],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, help="output directory (default: eval/results)")
    parser.add_argument("--seed", default=DEFAULT_SEED, help="seed for the per-trial canaries")
    args = parser.parse_args(argv)
    out = results_dir(args.out)
    s = evaluate(out, args.seed)

    print(f"corpus: {s['corpus']['programs']} programs ({s['corpus']['unsafe']} unsafe), "
          f"{s['corpus']['attacks']} attacks, {s['corpus']['benign_inputs']} benign inputs")
    print(f"{'method':<10} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'prec':>6} {'rec':>6} {'F1':>6}")
    for name, m in s["detection"].items():
        print(f"{name:<10} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3} {m['tn']:>3} "
              f"{m['precision']:>6.2f} {m['recall']:>6.2f} {m['f1']:>6.2f}")
    leaks = s["leaks"]
    print(f"structural leaks into system: naive {leaks['naive']['structural_leak']['rate']:.1%}, "
          f"TrustLex {leaks['trustlex']['structural_leak']['rate']:.1%} "
          f"(outcomes {leaks['trustlex']['outcomes']})")
    print(f"canary in system: naive {leaks['naive']['canary_in_system']['rate']:.1%}, "
          f"TrustLex {leaks['trustlex']['canary_in_system']['rate']:.1%}")
    print(f"B2 catches {s['b2']['catch_rate_on_leaking_pairs']['rate']:.1%} of leaking pairs; "
          f"false positives on benign inputs: {s['b2']['benign_false_positive']['rate']:.1%}")
    print(f"attacks surviving the default sanitizer structurally: {s['sanitizer']['survive_structurally'] or 'none'}")
    print(f"wrote {out}/detection.csv, leaks.csv, sanitizer.csv, eval_summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
