"""Shared helpers for the evaluation scripts: paths, data files, canaries,
metadata, and the structural leak checks."""

from __future__ import annotations

import datetime
import hashlib
import json
import platform
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

EVAL = Path(__file__).resolve().parent
ROOT = EVAL.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from codegen import _ROLE_TOKENS  # noqa: E402

ATTACKS = EVAL / "attacks" / "attacks.jsonl"
BENIGN = EVAL / "attacks" / "benign.jsonl"
DEFAULT_SEED = "trustlex-eval-1"


def results_dir(path: Path | None = None) -> Path:
    out = path or (EVAL / "results")
    out.mkdir(parents=True, exist_ok=True)
    return out


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_attacks(path: Path = ATTACKS) -> list[dict]:
    return read_jsonl(path)


def load_benign(path: Path = BENIGN) -> list[dict]:
    return read_jsonl(path)


def canary(*parts, seed: str = DEFAULT_SEED) -> str:
    """A random-looking token such as TLX-7F3A9C, derived from `parts` so that
    every trial gets its own canary but re-runs (and the cache) are stable."""
    digest = hashlib.sha256("\x1f".join(map(str, (seed, *parts))).encode("utf-8")).hexdigest()
    return "TLX-" + digest[:6].upper()


def with_canary(attack: dict, token: str) -> str:
    return attack["text"].replace("{CANARY}", token)


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def metadata(**extra) -> dict:
    return {
        "date": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "git_commit": git_commit(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        **extra,
    }


# ---- structural leak checks ------------------------------------------------

_TURN = re.compile(r"(?:^|\n)[ \t]*(?:system|user|assistant|human)[ \t]*:", re.IGNORECASE)
_OPEN = re.compile(r"<\s*untrusted_input\b", re.IGNORECASE)
_CLOSE = re.compile(r"<\s*/\s*untrusted_input\b", re.IGNORECASE)


def _normalized(text: str) -> str:
    # What a model may read: compatibility forms folded, line separators as newlines.
    return unicodedata.normalize("NFKC", text).replace(" ", "\n").replace(" ", "\n")


def structural_markers(text: str, wrappers: int = 0) -> list[str]:
    """Structural injection markers in `text`: chat-template role tokens, a
    forged transcript turn at a line start, or <untrusted_input> tags beyond
    the `wrappers` pairs the renderer itself emitted (a delimiter break-out,
    even a balanced one). Checked on the NFKC form."""
    norm = _normalized(text)
    found = [f"role-token {m.group()}" for m in _ROLE_TOKENS.finditer(norm)]
    found += [f"forged-turn {m.group().strip()}" for m in _TURN.finditer(norm)]
    opens, closes = len(_OPEN.findall(norm)), len(_CLOSE.findall(norm))
    if opens != wrappers or closes != wrappers:
        found.append(f"delimiter-tags ({opens} open, {closes} close, {wrappers} expected)")
    return found


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% confidence interval for a proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion(truth: list[bool], predicted: list[bool]) -> dict:
    """Confusion matrix and P/R/F1 with `unsafe` as the positive class."""
    tp = sum(t and p for t, p in zip(truth, predicted))
    fp = sum(not t and p for t, p in zip(truth, predicted))
    fn = sum(t and not p for t, p in zip(truth, predicted))
    tn = sum(not t and not p for t, p in zip(truth, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}
