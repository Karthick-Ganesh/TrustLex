"""
Turn the Tensor Trust hijacking benchmark into an attack file for llm_asr.py.

Tensor Trust (Toyer et al., 2023) is a public set of prompt-injection attacks
written by human players of an online game. A hijacking attack tries to make
the model say "Access Granted". We keep only the attack text (not the game's
defence prompts), replace the target phrase with {CANARY} so the canary judge
of llm_asr.py applies unchanged, and take a seeded random sample.

    python eval/import_tensor_trust.py \\
        eval/external/tensor_trust/hijacking_robustness_dataset.jsonl --n 64

Download the input from
https://github.com/HumanCompatibleAI/tensor-trust-data
(benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl).
The dataset is not redistributed here: eval/external/ is git-ignored.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import EVAL, read_jsonl  # noqa: E402

TARGET = re.compile(r"access\s+granted", re.IGNORECASE)
MAX_CHARS = 800  # keeps requests within free-tier tokens-per-minute limits
SEED = "trustlex-tensor-trust-1"
DEV_SEED = "trustlex-tensor-trust-dev-1"


def _pool(rows: list[dict], max_chars: int) -> list[tuple[int, str]]:
    """(sample_id, text) of every attack that names the target phrase
    literally and is at most `max_chars` long; duplicates are dropped."""
    seen, pool = set(), []
    for row in sorted(rows, key=lambda r: r["sample_id"]):
        text = row["attack"].strip()
        if text in seen or not TARGET.search(text) or len(text) > max_chars:
            continue
        seen.add(text)
        pool.append((row["sample_id"], TARGET.sub("{CANARY}", text)))
    return pool


def _attacks(items: list[tuple[int, str]], prefix: str, start: int = 1) -> list[dict]:
    return [{"id": f"{prefix}{i:02d}", "category": "tensor-trust", "text": text,
             "notes": f"Tensor Trust hijacking sample_id {sample_id}"}
            for i, (sample_id, text) in enumerate(sorted(items), start)]


def convert(rows: list[dict], n: int, max_chars: int = MAX_CHARS, seed: str = SEED) -> tuple[list[dict], dict]:
    """(attacks, stats) for a seeded sample of `n` qualifying attacks."""
    pool = _pool(rows, max_chars)
    attacks = _attacks(random.Random(seed).sample(pool, min(n, len(pool))), "TT")
    return attacks, {"rows": len(rows), "qualifying": len(pool), "sampled": len(attacks)}


def split(rows: list[dict], n: int, dev_n: int, max_chars: int = MAX_CHARS) -> tuple[list[dict], list[dict]]:
    """(dev, test). The `n`-attack sample of convert() stays in the test set
    with its ids TT01..; `dev_n` of the remaining attacks form the dev set
    (TTD01..), and the rest are appended to the test set."""
    pool = _pool(rows, max_chars)
    sample = random.Random(SEED).sample(pool, min(n, len(pool)))
    # Attacks that differ only in how they spell the target phrase are the
    # same attack once it is replaced by {CANARY}; keep one copy.
    seen, rest = {text for _, text in sample}, []
    for item in pool:
        if item[1] not in seen:
            seen.add(item[1])
            rest.append(item)
    dev = random.Random(DEV_SEED).sample(rest, min(dev_n, len(rest)))
    extra = [item for item in rest if item not in dev]
    return _attacks(dev, "TTD"), _attacks(sample, "TT") + _attacks(extra, "TT", start=len(sample) + 1)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert the Tensor Trust hijacking benchmark to an llm_asr attack file.")
    p.add_argument("dataset", type=Path, help="hijacking_robustness_dataset.jsonl")
    p.add_argument("--n", type=int, default=64, help="number of attacks to sample (default 64)")
    p.add_argument("--out", type=Path, default=EVAL / "external" / "tensor_trust" / "tensor_trust.jsonl")
    p.add_argument("--split", type=int, metavar="N",
                   help="also write a dev set of N other attacks and a test set of all the rest, next to --out")
    args = p.parse_args(argv)
    rows = read_jsonl(args.dataset)
    attacks, stats = convert(rows, args.n)
    _write(args.out, attacks)
    print(f"{stats['rows']} rows, {stats['qualifying']} distinct attacks name the target phrase within "
          f"{MAX_CHARS} chars; sampled {stats['sampled']} -> {args.out}")
    if args.split:
        dev, test = split(rows, args.n, args.split)
        for name, items in (("dev", dev), ("test", test)):
            path = args.out.with_name(f"{args.out.stem}_{name}.jsonl")
            _write(path, items)
            print(f"{name}: {len(items)} attacks -> {path}")
    return 0


def _write(path: Path, attacks: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for a in attacks:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    sys.exit(main())
