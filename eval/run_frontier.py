"""Frontier models through OpenRouter, each pinned to its own lab's API: Tensor Trust
(retrieval) and LLMail-Inject (e-mail), with the same layouts as the other models.

claude-haiku-5.5 is run for reference only: the paper includes it only on request.

    python eval/run_frontier.py        (run it in the background)
"""
from __future__ import annotations

import json
import threading

from orchestrate_v2 import V2
from run_openrouter import openrouter_worker

FRONTIER = [
    {"model": "openai/gpt-4o-mini", "route": "openai", "quantization": None, "max_tokens": 1024},
    {"model": "google/gemini-3.1-flash-lite", "route": "google-ai-studio", "quantization": None, "max_tokens": 1024},
    {"model": "anthropic/claude-haiku-5.5", "route": "anthropic", "quantization": None, "max_tokens": 1024},
]


def main():
    winner = json.loads((V2 / "decision.json").read_text(encoding="utf-8"))["winner"]
    threads = [threading.Thread(target=openrouter_worker, args=(m, f"A,B,Bt,{winner},S")) for m in FRONTIER]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("frontier runs finished", flush=True)


if __name__ == "__main__":
    main()
