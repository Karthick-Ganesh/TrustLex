"""Write result files for runs that cannot finish (daily quotas), from the cache.

A run interrupted by quota errors leaves gaps that later passes fill out of
order, so the completed attacks are not a prefix of the attack file and
`llm_asr.py --limit` would drop many of them. This script instead keeps every
attack and benign input whose trial is cached in *every* condition (the paired
set that interim.py scores), judges the replies with llm_asr's judge, and writes
the CSV and JSON under the name the full run would use; the JSON metadata
records that the run is partial. No request is sent.

    python eval/snapshot_partial.py                 (Groq models, Tensor Trust indirect)
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import DEFAULT_SEED, load_attacks, load_benign, metadata  # noqa: E402
from llm_asr import condition_labels, judge, parse_conditions, plan_trials, summarize, trustlex_verdicts  # noqa: E402
from orchestrate_v2 import MODELS, TT_TEST, V2  # noqa: E402
from providers import cache_key  # noqa: E402

OUT = V2 / "test"


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text)


def snapshot(m: dict, scenario: str, attacks_path: Path, conditions: str, cache: dict) -> None:
    conds = parse_conditions(conditions, scenario)
    attacks, benign = load_attacks(attacks_path), load_benign()
    trials = plan_trials(attacks, benign, conds, 1, m["model"], DEFAULT_SEED, scenario)
    replies = {}
    for t in trials:
        if t.blocked:
            replies[id(t)] = None
        else:
            key = cache_key(m["provider"], m["model"], t.system, t.messages, 0.0)
            if key in cache:
                replies[id(t)] = cache[key]
    by_item = {}
    for t in trials:
        by_item.setdefault((t.kind, t.item["id"]), []).append(t)
    complete = {k for k, ts in by_item.items() if all(id(t) in replies for t in ts)}
    labels = condition_labels(scenario)
    rows = []
    for t in trials:
        if (t.kind, t.item["id"]) not in complete:
            continue
        reply = replies[id(t)]
        rows.append({
            "scenario": scenario, "condition": t.condition, "condition_label": labels[t.condition], "kind": t.kind,
            "item": t.item["id"], "category": t.item.get("category", "benign"), "repeat": t.repeat,
            "canary": t.canary if t.kind == "attack" else "", "blocked": t.blocked, "cached": 1, "error": "",
            **judge(t, reply), "reply": (reply or "")[:500],
        })
    n_attacks = sum(1 for k in complete if k[0] == "attack")
    n_benign = sum(1 for k in complete if k[0] == "benign")
    print(f"{m['model']}: {n_attacks} attacks and {n_benign} benign inputs complete in every condition", flush=True)
    if not n_attacks:
        return
    attack_set = attacks_path.stem if attacks_path.name != "attacks.jsonl" else None
    summary = {
        "metadata": metadata(script="eval/snapshot_partial.py", scenario=scenario, provider=m["provider"],
                             model=m["model"], base_url=m["base_url"], temperature=0.0, max_tokens=m["max_tokens"],
                             repeats=1, limit=None, seed=DEFAULT_SEED, attack_set=attack_set or "trustlex",
                             attacks=n_attacks, benign=n_benign, conditions=conds, requests_sent=0, errors=0,
                             partial=True, trustlex_verdicts=trustlex_verdicts(scenario, conds)),
        "conditions": summarize(rows, labels),
    }
    prefix = "asr" + (f"_{scenario}" if scenario != "direct" else "") + (f"_{attack_set}" if attack_set else "")
    stem = f"{prefix}_{_slug(m['provider'])}_{_slug(m['model'])}"
    with (OUT / f"{stem}.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (OUT / f"{stem}.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  wrote {OUT / stem}.csv and .json", flush=True)


def main():
    cache = {}
    for line in (OUT / "cache.jsonl").open(encoding="utf-8"):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        cache[entry["key"]] = entry["response"]
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    for m in MODELS:
        if m["provider"] == "openai_compat":
            snapshot(m, "indirect", TT_TEST, f"A,B,Bt,{winner},S", cache)


if __name__ == "__main__":
    main()
