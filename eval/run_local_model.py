"""The v2 test jobs for one more local model served by Ollama (no quota).

Same jobs, conditions and variant as llama3.1:8b in run_local_v2.py, ordered
so that the headline comparisons finish first: Tensor Trust indirect, LLMail
(e-mail scenario), our attacks indirect, the direct scenario, then the layout
replay. Trials are interleaved, so a run stopped early still has paired data.

    python eval/run_local_model.py mistral:7b      (run it in the background)
"""
from __future__ import annotations

import json
import sys

from orchestrate_v2 import OURS, TT_TEST, V2
from run_local_v2 import LLMAIL, LOCAL, jobs


def main():
    model = sys.argv[1]
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    plan = [("indirect", TT_TEST), ("email", LLMAIL), ("indirect", OURS), ("direct", TT_TEST), ("direct", OURS),
            "replay"]
    jobs({**LOCAL, "model": model}, winner, plan)


if __name__ == "__main__":
    main()
