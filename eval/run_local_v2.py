"""Second wave of the v2 live runs: the local model and the LLMail-Inject attacks.

Uses the variant chosen by orchestrate_v2.py (eval/results/v2/decision.json)
and its retry logic. Two workers run in parallel:

  local   llama3.1:8b served by Ollama on this machine (no quota):
          LLMail (e-mail scenario), Tensor Trust indirect, layout replay, our attacks
          indirect, then the direct scenario with both attack sets
  gemma   waits until orchestrate_v2.py has finished its gemma jobs, then
          LLMail (e-mail scenario) and the layout replay

    python eval/run_local_v2.py      (run it in the background)
"""
from __future__ import annotations

import json
import subprocess
import threading
import time

from orchestrate_v2 import EVAL, MODELS, OURS, PYTHON, ROOT, TT_TEST, V2, log, run_asr, slug, until_complete

LLMAIL = EVAL / "external" / "llmail" / "llmail_test.jsonl"
LOCAL = {"model": "llama3.1:8b", "provider": "openai_compat", "base_url": "http://127.0.0.1:11434/v1",
         "key_env": "", "rpm": 0, "max_tokens": 256}
GEMMA = next(m for m in MODELS if m["provider"] == "gemini")


def replay(m: dict, sanitizer: str):
    cmd = [PYTHON, "-X", "utf8", str(ROOT / "paper" / "case_study" / "replay.py"), "--provider", m["provider"],
           "--model", m["model"], "--key-env", m["key_env"], "--sanitizer", sanitizer, "--limit", "30",
           "--rpm", str(m["rpm"]), "--max-tokens", str(m["max_tokens"]), "--yes"]
    if m["base_url"]:
        cmd += ["--base-url", m["base_url"]]
    with (EVAL / "results" / f"v2_orch_{slug(m['model'])}.log").open("a", encoding="utf-8") as f:
        subprocess.call(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
    log(m["model"], f"replay ({sanitizer}) done")


def jobs(m: dict, winner: str, plan):
    out = V2 / "test"
    for step in plan:
        if step == "replay":
            replay(m, "trustlex-datamark/1" if winner == "Cdm" else "trustlex-default/1")
            continue
        scenario, attacks = step
        conditions = f"A,B,Bt,{winner},S" + (",D" if scenario == "direct" else "")
        label = f"{scenario}/{attacks.stem}"
        until_complete(m, label, lambda: run_asr(m, scenario, attacks, conditions, out))
    log(m["model"], "all jobs complete")


def gemma_after_first_wave(winner: str):
    path = EVAL / "results" / f"v2_orch_{slug(GEMMA['model'])}.log"
    while "all jobs complete" not in path.read_text(encoding="utf-8"):
        time.sleep(120)
    jobs(GEMMA, winner, [("email", LLMAIL), "replay"])


def main():
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    local_plan = [("email", LLMAIL), ("indirect", TT_TEST), "replay", ("indirect", OURS),
                  ("direct", TT_TEST), ("direct", OURS)]
    threads = [threading.Thread(target=jobs, args=(LOCAL, winner, local_plan)),
               threading.Thread(target=gemma_after_first_wave, args=(winner,))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("second wave finished", flush=True)


if __name__ == "__main__":
    main()
