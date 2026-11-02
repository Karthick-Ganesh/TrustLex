"""Interim results of a running llm_asr job, read from the reply cache.

Rebuilds the job's trial plan, looks up every reply already cached, and
scores it with llm_asr's judge. Trials are interleaved, so the attacks done
so far are paired across all conditions.

    python eval/interim.py --provider openai_compat --model llama3.1:8b \\
        --scenario indirect --attacks eval/external/llmail/llmail_test.jsonl --conditions A,B,Bt,Cdm,S
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import DEFAULT_SEED, EVAL, load_attacks, load_benign, mcnemar, wilson  # noqa: E402
from llm_asr import judge, parse_conditions, plan_trials  # noqa: E402
from providers import cache_key  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--provider", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--scenario", default="indirect")
    p.add_argument("--attacks", type=Path, required=True)
    p.add_argument("--conditions", required=True)
    p.add_argument("--cache", type=Path, default=EVAL / "results" / "v2" / "test" / "cache.jsonl")
    args = p.parse_args(argv)

    cache = {}
    for line in args.cache.open(encoding="utf-8"):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        cache[entry["key"]] = entry["response"]
    conditions = parse_conditions(args.conditions, args.scenario)
    trials = plan_trials(load_attacks(args.attacks), load_benign(), conditions, 1, args.model, DEFAULT_SEED,
                         args.scenario)
    done = {}
    for t in trials:
        if t.blocked:
            done[(t.condition, t.kind, t.item["id"])] = {"success": 0, "utility": "", "blocked": True}
            continue
        key = cache_key(args.provider, args.model, t.system, t.messages, 0.0)
        if key in cache:
            done[(t.condition, t.kind, t.item["id"])] = judge(t, cache[key])
    # Only items that every condition has finished are compared (paired).
    items = {(kind, item) for (_, kind, item) in done}
    complete = sorted(i for i in items if all((c, *i) in done for c in conditions))
    attacks = [i for k, i in complete if k == "attack"]
    benign = [i for k, i in complete if k == "benign"]
    print(f"{args.model} [{args.scenario}, {args.attacks.stem}]: {len(attacks)} attacks and {len(benign)} benign "
          f"inputs complete in every condition")
    succ = {c: [int(done[(c, "attack", i)]["success"] or 0) for i in attacks] for c in conditions}
    for c in conditions:
        k, n = sum(succ[c]), len(attacks)
        lo, hi = wilson(k, n)
        util = [done[(c, "benign", i)]["utility"] for i in benign]
        u = sum(int(x) for x in util if x != "")
        print(f"  {c:4} ASR {100 * k / max(n, 1):5.1f}%  [{lo:.2f}, {hi:.2f}]  ({k}/{n})   "
              f"utility {100 * u / max(len(util), 1):5.1f}%")
    target = next((c for c in conditions if c.startswith("C")), None)
    if target:
        for base in [c for c in conditions if c != target and c != "D"]:
            b = sum(1 for x, y in zip(succ[base], succ[target]) if x and not y)
            c_ = sum(1 for x, y in zip(succ[base], succ[target]) if y and not x)
            print(f"  {base} vs {target}: exact McNemar p = {mcnemar(b, c_):.4f}  ({b} vs {c_} discordant)")


if __name__ == "__main__":
    main()
