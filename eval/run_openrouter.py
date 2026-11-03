"""Complete the quota-limited v2 runs.

  gpt-oss-20b, gpt-oss-120b   OpenRouter, pinned to Groq (the host of the first runs)
  qwen3.8-27b                 OpenRouter, pinned to DeepInfra at bf16
  allam-2-7b                  Groq's free tier, resumed from the cache (not on OpenRouter)

Each OpenRouter model runs Tensor Trust indirect and LLMail-Inject (e-mail) in full,
with the conditions and variant of the other models; allam also replays the
case-study layouts with the datamarking sanitizer. Replies are cached, so a pass
that fails part-way is resumed by the next.

    python eval/run_openrouter.py      (run it in the background)
"""
from __future__ import annotations

import json
import subprocess
import threading
import time

from orchestrate_v2 import EVAL, MODELS, PYTHON, ROOT, TT_TEST, V2, log, run_asr, slug
from run_local_v2 import LLMAIL, replay

OPENROUTER = [
    {"model": "openai/gpt-oss-20b", "route": "groq", "quantization": None, "max_tokens": 1024},
    {"model": "openai/gpt-oss-120b", "route": "groq", "quantization": None, "max_tokens": 1024},
    {"model": "qwen/qwen3.8-27b", "route": "deepinfra", "quantization": "bf16", "max_tokens": 1024},
]
RPM = 60
# allam on Groq's free tier: 6,000 tokens/minute, 7,000 requests/day. A Tensor Trust trial is
# about 650 tokens, an LLMail trial about 1,450, so these rates stay under the minute budget.
ALLAM_RPM = {"indirect": 8, "email": 4}
ALLAM_PASSES, ALLAM_WAIT_MINUTES = 400, 15


def openrouter_pass(m: dict, scenario: str, attacks, conditions: str) -> int | None:
    cmd = [PYTHON, "-I", "-X", "utf8", str(EVAL / "llm_asr.py"), "--provider", "openrouter", "--route", m["route"],
           "--model", m["model"], "--scenario", scenario, "--attacks", str(attacks), "--conditions", conditions,
           "--rpm", str(RPM), "--max-tokens", str(m["max_tokens"]), "--out", str(V2 / "test"), "--yes",
           "--max-consecutive-errors", "20"]
    if m["quantization"]:
        cmd += ["--quantization", m["quantization"]]
    with (EVAL / "results" / f"v2_or_{slug(m['model'])}.log").open("a", encoding="utf-8") as f:
        code = subprocess.call(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
    if code != 0:
        return None
    name = f"openrouter-{m['route']}" + (f"-{m['quantization']}" if m["quantization"] else "")
    prefix = f"asr_{scenario}_{attacks.stem}"
    path = V2 / "test" / f"{prefix}_{slug(name)}_{slug(m['model'])}.json"
    return json.loads(path.read_text(encoding="utf-8"))["metadata"]["errors"] if path.exists() else None


def openrouter_worker(m: dict, conditions: str, jobs=(("indirect", TT_TEST), ("email", LLMAIL))):
    for scenario, attacks in jobs:
        for n in range(1, 11):
            errors = openrouter_pass(m, scenario, attacks, conditions)
            log(m["model"], f"openrouter {scenario}/{attacks.stem}: pass {n} -> {errors}")
            if errors == 0:
                break
            time.sleep(120)
    log(m["model"], "openrouter jobs complete")


def allam_worker(conditions: str):
    m = next(x for x in MODELS if x["model"] == "allam-2-7b")
    for scenario, attacks in (("indirect", TT_TEST), ("email", LLMAIL)):
        for n in range(1, ALLAM_PASSES + 1):
            errors = run_asr({**m, "rpm": ALLAM_RPM[scenario]}, scenario, attacks, conditions, V2 / "test")
            log(m["model"], f"{scenario}/{attacks.stem}: pass {n} -> {errors}")
            if errors == 0:
                break
            time.sleep(ALLAM_WAIT_MINUTES * 60)
    replay({**m, "rpm": ALLAM_RPM["indirect"]}, "trustlex-datamark/1")
    log(m["model"], "all jobs complete")


def main():
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    conditions = f"A,B,Bt,{winner},S"
    # qwen's LLMail part may already run as its own process; pass --skip-qwen-email to leave it out
    import sys
    skip = "--skip-qwen-email" in sys.argv
    threads = [threading.Thread(target=openrouter_worker, args=(m, conditions) if not (skip and "qwen" in m["model"])
                                else (m, conditions, (("indirect", TT_TEST),))) for m in OPENROUTER]
    threads.append(threading.Thread(target=allam_worker, args=(conditions,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("all runs finished", flush=True)


if __name__ == "__main__":
    main()
