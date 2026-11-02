"""
Turn Microsoft's LLMail-Inject challenge data into an attack file for llm_asr.py.

LLMail-Inject (Abdelnabi et al., 2025) collected attack e-mails written by
challenge participants against an LLM e-mail assistant guarded by
prompt-injection defences. The goal of every attack is the same: make the
assistant send an e-mail to contact@contact.com whose body is
"confirmation". We use the phase-2 submissions that the organisers labelled
`api_triggered` (the attack made the defended assistant call the send-mail
API), keep those that spell the target body literally and are at most
`max_chars` long, replace the body with {CANARY} so the canary judge of
llm_asr.py applies unchanged, drop duplicates, and take a seeded sample.

    python eval/import_llmail.py \\
        eval/external/llmail/labelled_unique_submissions_phase2.json --n 200

Download the input from https://huggingface.co/datasets/microsoft/llmail-inject-challenge
(data/labelled_unique_submissions_phase2.json, MIT licence). It is not
redistributed here: eval/external/ is git-ignored.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import EVAL  # noqa: E402

TARGET = re.compile(r"\bconfirmation\b", re.IGNORECASE)
MAX_CHARS = 1500  # keeps requests within free-tier tokens-per-minute limits and local context windows
SEED = "trustlex-llmail-1"


def convert(labels: dict[str, dict], n: int, max_chars: int = MAX_CHARS, seed: str = SEED) -> tuple[list[dict], dict]:
    """(attacks, stats) from the labelled phase-2 file: {attack text: {"reason": ...}}."""
    successful = [text for text, info in labels.items() if info.get("reason") == "api_triggered"]
    seen, pool = set(), []
    for text in sorted(successful):
        text = text.strip()
        if len(text) > max_chars or not TARGET.search(text) or "contact@contact.com" not in text.lower():
            continue
        attack = TARGET.sub("{CANARY}", text)
        if attack in seen:
            continue
        seen.add(attack)
        pool.append(attack)
    sample = sorted(random.Random(seed).sample(pool, min(n, len(pool))))
    attacks = [{"id": f"LM{i:03d}", "category": "llmail-inject", "text": text,
                "notes": "LLMail-Inject phase 2, labelled api_triggered"} for i, text in enumerate(sample, 1)]
    return attacks, {"submissions": len(labels), "api_triggered": len(successful),
                     "qualifying": len(pool), "sampled": len(attacks)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert LLMail-Inject phase-2 submissions to an llm_asr attack file.")
    p.add_argument("labels", type=Path, help="labelled_unique_submissions_phase2.json")
    p.add_argument("--n", type=int, default=200, help="number of attacks to sample (default 200)")
    p.add_argument("--out", type=Path, default=EVAL / "external" / "llmail" / "llmail_test.jsonl")
    args = p.parse_args(argv)
    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    attacks, stats = convert(labels, args.n)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for a in attacks:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    print(f"{stats['submissions']} unique submissions, {stats['api_triggered']} triggered the API, "
          f"{stats['qualifying']} distinct ones spell the target literally within {MAX_CHARS} chars; "
          f"sampled {stats['sampled']} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
