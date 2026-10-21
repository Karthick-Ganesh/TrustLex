"""
Two baselines that TrustLex is compared against.

B1, lexical linter (static, no dataflow). Flags a program as unsafe if,
inside the source text of a `system { ... }` block, an identifier declared
with `input` appears inside `insert(...)` or in a `{...}` interpolation.
`sanitize(name)` is recognised textually and counts as safe. The linter
works on text: it does not follow `var` hops, strip comments, understand
escaped braces, or know about validated types. That is the point.

B2, runtime keyword filter. Renders the program naively with an input value
and flags the result if a regex blocklist of known injection phrases matches
the system message, the way simple guardrail filters work.
"""

from __future__ import annotations

import re

_INPUT_DECL = re.compile(r"^[ \t]*input[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_SYSTEM_OPEN = re.compile(r"\bsystem\s*\{")
_INSERT = re.compile(r"\binsert\s*\(")
_HOLE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_BARE_SANITIZE = re.compile(r"\bsanitize\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)")


def _system_blocks(source: str) -> list[str]:
    """Text of every system block, found by brace counting."""
    blocks = []
    for m in _SYSTEM_OPEN.finditer(source):
        depth, i = 1, m.end()
        while i < len(source) and depth:
            depth += {"{": 1, "}": -1}.get(source[i], 0)
            i += 1
        blocks.append(source[m.end():i - 1])
    return blocks


def _insert_args(block: str) -> list[str]:
    """The argument text of each insert(...) call, with nested parentheses."""
    args = []
    for m in _INSERT.finditer(block):
        depth, i = 1, m.end()
        while i < len(block) and depth:
            depth += {"(": 1, ")": -1}.get(block[i], 0)
            i += 1
        args.append(block[m.end():i - 1])
    return args


def b1_findings(source: str) -> list[str]:
    """Input names B1 sees reaching a system block (empty: judged safe)."""
    inputs = set(_INPUT_DECL.findall(source))
    found = []
    for block in _system_blocks(source):
        for arg in _insert_args(block):
            unsanitized = _BARE_SANITIZE.sub("", arg)
            found += [n for n in inputs if re.search(rf"\b{n}\b", unsanitized)]
        found += [n for n in _HOLE.findall(block) if n in inputs]
    return sorted(set(found))


def b1_flags(source: str) -> bool:
    return bool(b1_findings(source))


BLOCKLIST = [
    r"ignore\s+(?:all|any|the|your)?\s*(?:previous|prior|above|earlier)",
    r"ignore\s+all",
    r"disregard\s+(?:all|your|the)?\s*(?:previous|prior|earlier|above)?\s*(?:rules|instructions)",
    r"forget\s+(?:everything|all|your)",
    r"\bsystem\s*:",
    r"\bassistant\s*:",
    r"<\|",
    r"\|>",
    r"\[/?INST\]",
    r"<</?SYS>>",
    r"you\s+are\s+now",
    r"new\s+instructions",
    r"</?\s*untrusted_input",
    r"developer\s+mode",
    r"jailbreak",
]
_BLOCKLIST = re.compile("|".join(f"(?:{p})" for p in BLOCKLIST), re.IGNORECASE)


def b2_match(text: str) -> str | None:
    """The first blocklist match in `text`, or None."""
    m = _BLOCKLIST.search(text)
    return m.group() if m else None


def b2_flags(system_text: str) -> bool:
    return b2_match(system_text) is not None
