"""Write the paper's live-result tables (paper/ieee/shared/tab_*.tex) from the results.

Tensor Trust and LLMail-Inject runs are scored with their own success rules
(native_metrics.py); our 32 attacks with the canary judge corrected by the blind
second judge (rejudge.py). A value is marked \\pending{} (red) while its run is
partial or still running, or while a judge-scored run has unjudged successes.

    python eval/paper_tables.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import mcnemar  # noqa: E402
from native_metrics import paired_p, replay_results, run_results  # noqa: E402
from rejudge import REPLAY, RESULTS, load_labels, row_key  # noqa: E402

SHARED = Path(__file__).resolve().parents[1] / "paper" / "ieee" / "shared"
MODELS = [("allam-2-7b", "allam-2-7b"), ("qwen/qwen3.8-27b", "qwen3.8-27b"), ("openai/gpt-oss-20b", "gpt-oss-20b"),
          ("openai/gpt-oss-120b", "gpt-oss-120b"), ("gemma-4-26b-a4b-it", "gemma-4-26b"),
          ("llama3.1:8b", "llama-3.1-8b"), ("mistral:7b", "mistral-7b")]
LAYOUTS = ["A", "B", "Bt", "S"]


def runs() -> dict:
    """(scenario, attack_set, model) -> csv path."""
    out = {}
    for path in RESULTS.glob("*.json"):
        meta = json.loads(path.read_text(encoding="utf-8"))["metadata"]
        out[(meta["scenario"], meta["attack_set"], meta["model"])] = path.with_suffix(".csv")
    return out


def fmt_p(p: float) -> str:
    return "$<$.001" if p < 0.001 else f"{p:.3f}".lstrip("0")


def cell(value: str, pending: bool) -> str:
    return f"\\pending{{{value}}}" if pending else value


def utility(csv_path: Path, condition: str) -> int:
    rows = [r for r in csv.DictReader(csv_path.open(encoding="utf-8"))
            if r["kind"] == "benign" and r["condition"] == condition and not r["error"]]
    return round(100 * sum(int(r["utility"] or 0) for r in rows) / max(len(rows), 1))


def judged(csv_path: Path) -> tuple[dict, bool]:
    """condition -> {item: success} from the corrected judge, and whether any success is unjudged."""
    labels, by, missing = load_labels(), {}, False
    for r in csv.DictReader(csv_path.open(encoding="utf-8")):
        if r["kind"] != "attack" or r["error"]:
            continue
        ok = r["success"] == "1"
        if ok:
            label = labels.get(row_key({"run": csv_path.stem, **r}), {}).get("label")
            missing |= label not in ("COMPLIED", "MENTIONED")
            ok = label != "MENTIONED"
        by.setdefault(r["condition"], {})[r["item"]] = ok
    return by, missing


def rate(items: dict) -> str:
    return f"{100 * sum(items.values()) / len(items):.1f}"


def official(path: Path | None):
    if path is None or not path.exists():
        return None
    res = run_results(path)
    return res["by"], bool(res["meta"].get("partial"))


def indirect_cells(path, scored) -> list[str]:
    if scored is None:
        return [cell("--", True)] * 7
    by, pend = scored
    c = next(k for k in by if k.startswith("C"))
    out = [cell(rate(by[x]), pend) for x in LAYOUTS]
    out.append(cell(f"\\textbf{{{rate(by[c])}}}", pend))
    out.append(cell(fmt_p(paired_p(by["B"], by[c])), pend))
    out.append(cell(f"{utility(path, 'B')}/{utility(path, c)}", pend))
    return out


def write_indirect(index: dict):
    lines = []
    for model, name in MODELS:
        tt = index.get(("indirect", "tensor_trust_test", model))
        lm = index.get(("email", "llmail_test", model))
        row = indirect_cells(tt, official(tt))
        row += indirect_cells(lm, official(lm)) if lm else ["--"] * 7
        lines.append(f"{name:16} & " + " & ".join(row) + r" \\")
    tex = (SHARED / "tab_indirect.tex").read_text(encoding="utf-8")
    head, rest = tex.split("\\midrule\n", 1)
    tail = rest[rest.index("\\bottomrule"):]
    (SHARED / "tab_indirect.tex").write_text(head + "\\midrule\n" + "\n".join(lines) + "\n" + tail, encoding="utf-8")


def write_direct(index: dict):
    lines = []
    for model, name in MODELS:
        tt = index.get(("direct", "tensor_trust_test", model))
        ours = index.get(("direct", "trustlex", model))
        if tt is None and ours is None:
            continue
        rows = []
        for label, path, scorer in (("TT (165)", tt, "official"), ("Ours (32)", ours, "judge")):
            if path is None or not path.exists():
                rows.append(f" & {label} & " + " & ".join([cell("--", True)] * 6) + r" \\")
                continue
            by, pend = official(path) if scorer == "official" else judged(path)
            c = next(k for k in by if k.startswith("C"))
            vals = [cell(rate(by[x]), pend) for x in LAYOUTS] + [cell(f"\\textbf{{{rate(by[c])}}}", pend)]
            vals.append(r"\textbf{0}" if "D" in by and not any(by["D"].values()) else cell(rate(by.get("D", {0: 0})), pend))
            rows.append(f" & {label} & " + " & ".join(vals) + r" \\")
        lines.append("\\multirow{2}{*}{" + name + "}" + rows[0] + "\n" + rows[1])
    tex = (SHARED / "tab_direct.tex").read_text(encoding="utf-8")
    head, rest = tex.split("\\midrule\n", 1)
    tail = rest[rest.index("\\bottomrule"):]
    (SHARED / "tab_direct.tex").write_text(head + "\\midrule\n" + "\n\\midrule\n".join(lines) + "\n" + tail,
                                           encoding="utf-8")


def write_replay():
    files = {"allam-2-7b": "replay_openai_compat_allam-2-7b", "llama-3.1-8b": "replay_datamark_openai_compat_llama3.1_8b",
             "gemma-4-26b": "replay_datamark_gemini_gemma-4-26b-a4b-it"}
    res = {k: replay_results(REPLAY / f"{v}.jsonl")["by"] for k, v in files.items()}
    apps = [("career-ops", "career-ops"), ("deeptutor", "DeepTutor"), ("project-nomad", "project-nomad"),
            ("hermes-agent", "hermes-agent"), ("open-design", "open-design"), ("agent-browser", "agent-browser"),
            ("openhuman", "openhuman")]
    lines = []
    for app, shown in apps:
        vals = []
        for m in files:
            vals += [rate(res[m][(app, "original")]), rate(res[m][(app, "fixed")])]
        lines.append(f"{shown:13} & " + " & ".join(vals) + r" \\")
    pooled, ps = [], []
    for m in files:
        o = {(a, i): s for (a, lay), it in res[m].items() if lay == "original" for i, s in it.items()}
        f = {(a, i): s for (a, lay), it in res[m].items() if lay == "fixed" for i, s in it.items()}
        pooled += [rate(o), rate(f)]
        ps.append(f"\\multicolumn{{2}}{{c}}{{{fmt_p(paired_p(o, f))}}}")
    lines.append("\\midrule")
    lines.append("Pooled        & " + " & ".join(pooled) + r" \\")
    lines.append("$p$           & " + " & ".join(ps) + r" \\")
    tex = (SHARED / "tab_replay.tex").read_text(encoding="utf-8")
    head, rest = tex.split("\\midrule\n", 1)
    tail = rest[rest.index("\\bottomrule"):]
    (SHARED / "tab_replay.tex").write_text(head + "\\midrule\n" + "\n".join(lines) + "\n" + tail, encoding="utf-8")


def main():
    index = runs()
    write_indirect(index)
    write_direct(index)
    write_replay()
    print("wrote", ", ".join(p.name for p in sorted(SHARED.glob("tab_*.tex"))))


if __name__ == "__main__":
    main()
