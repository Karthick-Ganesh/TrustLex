"""Load the labelled evaluation corpus in eval/corpus/.

Every program starts with three headers:

    # about: one-line description
    # expect: ok | the exact TrustLex error codes, in order
    # category: one of UNSAFE_CATEGORIES or SAFE_CATEGORIES
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import load_scenario  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"

UNSAFE_CATEGORIES = (
    "direct-insert", "interp-normal", "interp-triple", "multi-hop", "concat",
    "partial-sanitize", "rag-tool-system", "reassign-after-sanitize",
)
SAFE_CATEGORIES = (
    "instruction-only", "sanitized-single", "sanitized-multi-hop", "lookalike-literal",
    "sanitized-concat", "realistic",
)


@dataclass(frozen=True)
class CorpusProgram:
    path: Path
    about: str
    expect: tuple[str, ...]  # ("ok",) or error codes
    category: str

    @property
    def name(self) -> str:
        return self.path.stem

    @property
    def unsafe(self) -> bool:
        """Ground truth: the program should be rejected."""
        return self.expect != ("ok",)

    @property
    def source(self) -> str:
        return self.path.read_text(encoding="utf-8")


def load_program(path: Path) -> CorpusProgram:
    scenario = load_scenario(path)
    category = next((line.removeprefix("# category:").strip()
                     for line in path.read_text(encoding="utf-8").splitlines()[:10]
                     if line.startswith("# category:")), None)
    if scenario is None or category is None:
        raise ValueError(f"{path.name}: missing `# expect:` or `# category:` header")
    if category not in UNSAFE_CATEGORIES + SAFE_CATEGORIES:
        raise ValueError(f"{path.name}: unknown category {category!r}")
    program = CorpusProgram(path, scenario.about, tuple(scenario.expect), category)
    if program.unsafe != (category in UNSAFE_CATEGORIES):
        raise ValueError(f"{path.name}: `# expect:` disagrees with the category {category!r}")
    return program


def load_corpus(directory: Path = CORPUS) -> list[CorpusProgram]:
    return [load_program(p) for p in sorted(directory.glob("*.tlx"))]
