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


def convert(rows: list[dict], n: int, max_chars: int = MAX_CHARS, seed: str = SEED) -> tuple[list[dict], dict]:
    """(attacks, stats). An attack qualifies if it names the target phrase
    literally and is at most `max_chars` long; duplicates are dropped."""
    seen, pool = set(), []
    for row in sorted(rows, key=lambda r: r["sample_id"]):
        text = row["attack"].strip()
        if text in seen or not TARGET.search(text) or len(text) > max_chars:
            continue
        seen.add(text)
        pool.append((row["sample_id"], TARGET.sub("{CANARY}", text)))
    sample = random.Random(seed).sample(pool, min(n, len(pool)))
    attacks = [{"id": f"TT{i:02d}", "category": "tensor-trust", "text": text,
                "notes": f"Tensor Trust hijacking sample_id {sample_id}"}
               for i, (sample_id, text) in enumerate(sorted(sample), 1)]
    return attacks, {"rows": len(rows), "qualifying": len(pool), "sampled": len(attacks)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert the Tensor Trust hijacking benchmark to an llm_asr attack file.")
    p.add_argument("dataset", type=Path, help="hijacking_robustness_dataset.jsonl")
    p.add_argument("--n", type=int, default=64, help="number of attacks to sample (default 64)")
    p.add_argument("--out", type=Path, default=EVAL / "external" / "tensor_trust" / "tensor_trust.jsonl")
    args = p.parse_args(argv)
    attacks, stats = convert(read_jsonl(args.dataset), args.n)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for a in attacks:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    print(f"{stats['rows']} rows, {stats['qualifying']} distinct attacks name the target phrase within "
          f"{MAX_CHARS} chars; sampled {stats['sampled']} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
