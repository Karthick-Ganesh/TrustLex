"""Spotlighting ablation for conference variant 3: layout Bsp (spotlighting written by
hand, without TrustLex's sanitizer) on Tensor Trust and LLMail-Inject.

The other layouts' replies are cached, so each run sends only the Bsp trials and
rewrites the result files with Bsp added. Local models run one after another on
the GPU (after the local ALLaM run has finished); gemma runs in parallel over its API.

    python eval/run_ablation.py        (run it in the background)
"""
from __future__ import annotations

import json
import threading
import time

from orchestrate_v2 import EVAL, MODELS, TT_TEST, V2, log, run_asr, slug, until_complete
from run_local_v2 import LLMAIL, LOCAL

LOCAL_MODELS = ["allam-7b-instruct-q4", "llama3.1:8b", "mistral:7b"]
GEMMA = next(m for m in MODELS if m["provider"] == "gemini")


def ablate(m: dict, conditions: str):
    for scenario, attacks in (("indirect", TT_TEST), ("email", LLMAIL)):
        until_complete(m, f"ablation {scenario}/{attacks.stem}",
                       lambda: run_asr(m, scenario, attacks, conditions, V2 / "test"))


def local_worker(conditions: str):
    allam_log = EVAL / "results" / f"v2_orch_{slug('allam-7b-instruct-q4')}.log"
    while "all jobs complete" not in allam_log.read_text(encoding="utf-8"):
        time.sleep(60)
    for model in LOCAL_MODELS:
        ablate({**LOCAL, "model": model}, conditions)


def main():
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    conditions = f"A,B,Bt,{winner},S,Bsp"
    threads = [threading.Thread(target=local_worker, args=(conditions,)),
               threading.Thread(target=ablate, args=({**GEMMA, "rpm": 12}, conditions))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("ablation finished", flush=True)


if __name__ == "__main__":
    main()
