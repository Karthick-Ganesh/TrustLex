"""Unattended driver for the v2 live runs.

1. Waits for the two development runs (allam-2-7b and qwen3.8-27b, indirect
   scenario, 40 Tensor Trust dev attacks, conditions B, Bt, C0, C, Cdm).
2. Chooses the TrustLex variant by a rule fixed before any dev result was
   seen: the lowest mean attack success over the dev models among the
   variants whose utility on every dev model is at most 5 points below
   condition B; ties within 0.5 points go to C, then Cdm, then C0. The
   decision and its inputs are written to eval/results/v2/decision.json.
3. Runs the test jobs of every model in parallel (one worker per model,
   jobs in order: indirect then direct, Tensor Trust test set then our
   attacks), with every condition. A job whose run ends with provider
   errors (an exhausted daily quota) is re-run every 20 minutes until it
   completes; trials are interleaved and replies cached, so a re-run only
   sends what is missing, and the results stay paired at any stopping point.
4. Before its test jobs, the allam worker runs the case-study layout replay.

    python eval/orchestrate_v2.py        (run it in the background)
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

EVAL = Path(__file__).resolve().parent
ROOT = EVAL.parent
PYTHON = sys.executable
V2 = EVAL / "results" / "v2"
TT_DEV = EVAL / "external" / "tensor_trust" / "tensor_trust_dev.jsonl"
TT_TEST = EVAL / "external" / "tensor_trust" / "tensor_trust_test.jsonl"
OURS = EVAL / "attacks" / "attacks.jsonl"
GROQ = {"provider": "openai_compat", "base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY"}
MODELS = [
    {"model": "allam-2-7b", **GROQ, "rpm": 5, "max_tokens": 256, "dev": True, "replay": True},
    {"model": "qwen/qwen3.8-27b", **GROQ, "rpm": 4, "max_tokens": 1024, "dev": True},
    {"model": "openai/gpt-oss-20b", **GROQ, "rpm": 4, "max_tokens": 1024},
    {"model": "openai/gpt-oss-120b", **GROQ, "rpm": 4, "max_tokens": 1024},
    {"model": "gemma-4-26b-a4b-it", "provider": "gemini", "base_url": None, "key_env": "GEMINI_API_KEY",
     "rpm": 8, "max_tokens": 1024},
]
VARIANTS = ("C", "Cdm", "C0")  # tie-break order
RETRY_MINUTES = 20
MAX_PASSES = 60


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "model"


def log(name: str, message: str):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
    with (EVAL / "results" / f"v2_orch_{slug(name)}.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[{name}] {line}", flush=True)


def result_path(out: Path, m: dict, scenario: str, attacks: Path) -> Path:
    attack_set = "" if attacks == OURS else slug(attacks.stem)
    prefix = "asr" + (f"_{scenario}" if scenario != "direct" else "") + (f"_{attack_set}" if attack_set else "")
    return out / f"{prefix}_{m['provider']}_{slug(m['model'])}.json"


def run_asr(m: dict, scenario: str, attacks: Path, conditions: str, out: Path) -> int | None:
    """One pass; returns the number of provider errors, or None if it crashed."""
    cmd = [PYTHON, "-I", "-X", "utf8", str(EVAL / "llm_asr.py"), "--provider", m["provider"], "--model", m["model"],
           "--key-env", m["key_env"], "--scenario", scenario, "--attacks", str(attacks), "--conditions", conditions,
           "--rpm", str(m["rpm"]), "--max-tokens", str(m["max_tokens"]), "--out", str(out), "--yes",
           "--max-consecutive-errors", "8"]
    if m["base_url"]:
        cmd += ["--base-url", m["base_url"]]
    with (EVAL / "results" / f"v2_orch_{slug(m['model'])}.log").open("a", encoding="utf-8") as f:
        code = subprocess.call(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
    path = result_path(out, m, scenario, attacks)
    if code != 0 or not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))["metadata"]["errors"]


def until_complete(m: dict, label: str, attempt):
    for n in range(1, MAX_PASSES + 1):
        errors = attempt()
        log(m["model"], f"{label}: pass {n} -> {'crashed' if errors is None else f'{errors} errors'}")
        if errors == 0:
            return
        time.sleep(RETRY_MINUTES * 60)
    log(m["model"], f"{label}: gave up after {MAX_PASSES} passes")


def wait_for_dev() -> dict:
    paths = {m["model"]: V2 / "dev" / f"asr_indirect_tensor_trust_dev_{m['provider']}_{slug(m['model'])}.json"
             for m in MODELS if m.get("dev")}
    while not all(p.exists() for p in paths.values()):
        time.sleep(60)
    return {model: json.loads(p.read_text(encoding="utf-8"))["conditions"] for model, p in paths.items()}


def choose_variant(dev: dict) -> dict:
    table = {}
    for v in VARIANTS:
        asrs = [c[v]["asr"] for c in dev.values() if v in c and c[v]["asr"] is not None]
        utility_ok = all(c[v]["utility"] >= c["B"]["utility"] - 0.05 for c in dev.values() if v in c and "B" in c)
        table[v] = {"mean_asr": sum(asrs) / len(asrs) if asrs else None, "utility_ok": utility_ok,
                    "per_model": {model: {"asr": c[v]["asr"], "utility": c[v]["utility"]} for model, c in dev.items() if v in c}}
    eligible = [v for v in VARIANTS if table[v]["utility_ok"] and table[v]["mean_asr"] is not None]
    best = min((table[v]["mean_asr"] for v in eligible), default=None)
    winner = next((v for v in eligible if table[v]["mean_asr"] <= best + 0.005), "C") if eligible else "C"
    return {"winner": winner, "rule": __doc__.split("2. ", 1)[1].split("\n3.", 1)[0].strip(), "variants": table,
            "baseline_B": {model: {"asr": c["B"]["asr"], "utility": c["B"]["utility"]} for model, c in dev.items()}}


def stop_old_test_runs():
    """The test runs started before this driver ran only A/B/Bt; their replies are cached.
    They run inside shell loops, so the loops are stopped too, in a few rounds in
    case a loop starts its next job in between."""
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'llm_asr.py' -and "
              "$_.CommandLine -match 'v2/test' -and $_.CommandLine -notmatch 'max-consecutive-errors' -and "
              "$_.CommandLine -notmatch 'orchestrate' } | "
              "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -Confirm:$false -ErrorAction SilentlyContinue }")
    for _ in range(4):
        subprocess.call(["powershell.exe", "-NoProfile", "-Command", script])
        time.sleep(3)


def worker(m: dict, winner: str):
    out = V2 / "test"
    if m.get("replay"):
        replay = [PYTHON, "-X", "utf8", str(ROOT / "paper" / "case_study" / "replay.py"), "--provider", m["provider"],
                  "--model", m["model"], "--key-env", m["key_env"], "--base-url", m["base_url"], "--limit", "30",
                  "--rpm", str(m["rpm"]), "--yes"]
        with (EVAL / "results" / f"v2_orch_{slug(m['model'])}.log").open("a", encoding="utf-8") as f:
            subprocess.call(replay, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
        log(m["model"], "replay done")
    for scenario in ("indirect", "direct"):
        conditions = f"A,B,Bt,{winner},S" + (",D" if scenario == "direct" else "")
        for attacks in (TT_TEST, OURS):
            label = f"{scenario}/{attacks.stem}"
            until_complete(m, label, lambda: run_asr(m, scenario, attacks, conditions, out))
    log(m["model"], "all jobs complete")


def main():
    print("waiting for the development runs ...", flush=True)
    decision = choose_variant(wait_for_dev())
    (V2 / "decision.json").write_text(json.dumps(decision, indent=2), encoding="utf-8")
    print(f"variant chosen: {decision['winner']}", flush=True)
    stop_old_test_runs()
    threads = [threading.Thread(target=worker, args=(m, decision["winner"]), name=m["model"]) for m in MODELS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("all workers finished", flush=True)


if __name__ == "__main__":
    main()
