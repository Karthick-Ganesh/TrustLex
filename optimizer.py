"""
TrustLex - Module 5: Token Optimization.

A rule-based pass over the compiled IR that removes redundant whitespace and
empty parts from developer-authored text, so the prompt costs fewer tokens.

    generate() -> CompiledPrompt --optimize(level)--> CompiledPrompt' + OptimizationReport

Untrusted content is out of reach by construction: at compile time input
values do not exist, only slots. The optimizer rewrites TextPart strings and
nothing else; every slot keeps its input, position and sanitize flag.

The rules are applied repeatedly until none of them changes the text (a
fixpoint), which makes the optimizer idempotent.

Semantics preservation is defined as *whitespace equivalence*: two messages
are equivalent when they have the same role, the same slot sequence, and the
same text once all whitespace is removed (slots compared as atoms). Every
rule only deletes or replaces whitespace, and optimize() re-checks the
equivalence of every message it rewrites, so a faulty rule fails loudly
instead of changing a prompt.

To make slots behave as content in line-based rules (the space in
"Question: <slot>" is not trailing whitespace), each message is encoded as a
single string in which every slot is a private-use sentinel character, the
rules run as plain string rewrites, and the result is decoded back into parts.

Levels:
    -O0  no changes
    -O1  safe (default): merge/drop empty parts, normalize newlines, strip
         trailing whitespace, dedent common indentation, keep at most one
         blank line, trim message ends, drop empty messages
    -O2  aggressive: additionally strip all indentation, collapse runs of
         spaces, and remove blank lines (can flatten code samples or lists)

Known limitation: dedent works per message, not per string literal, because
code generation merges the text of adjacent block items. A block mixing an
indented triple-quoted string with unindented strings is not dedented at -O1.

Comments never reach the IR; the lexer drops them. The report still counts
them so that the reported savings are complete.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field, replace

from codegen import CodegenError, CompiledPrompt, Message, SlotPart, TextPart, compile_source

LEVELS = (0, 1, 2)
MAX_PASSES = 16


class OptimizerError(Exception):
    """A rule broke whitespace equivalence (an optimizer bug)."""


# --------------------------------------------------------------------------
# Token estimation
# --------------------------------------------------------------------------

# A BPE-style pre-tokenizer: contractions, words, short digit runs, punctuation
# runs and whitespace. Real tokenizers merge further, so this is an estimate.
_PRETOKEN = re.compile(
    r"'(?:s|t|re|ve|m|ll|d)| ?[^\W\d_]+| ?\d{1,3}| ?[^\s\w]+|\s+(?!\S)|\s+",
    re.UNICODE,
)


def estimate_tokens(text: str) -> int:
    return len(_PRETOKEN.findall(text))


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

_TRAILING_WS = re.compile(r"[^\S\n]+(?=\n|\Z)")
_LEADING_WS = re.compile(r"[^\S\n]*")
_INDENTATION = re.compile(r"(?m)^[^\S\n]+")
_INLINE_WS = re.compile(r"[^\S\n]+")
_EXTRA_BLANK_LINES = re.compile(r"\n{3,}")
_BLANK_LINES = re.compile(r"\n{2,}")


def _dedent(s: str, sentinel: str) -> str:
    lines = s.split("\n")
    # Lines that are blank or start with a slot have no indentation to share.
    prefixes = [
        _LEADING_WS.match(line).group()
        for line in lines
        if line.strip() and not line.startswith(sentinel)
    ]
    common = os.path.commonprefix(prefixes) if prefixes else ""
    if not common:
        return s
    return "\n".join(line[len(common):] if line.startswith(common) else line for line in lines)


@dataclass(frozen=True)
class Rule:
    name: str
    level: int
    description: str
    apply: object  # (text, sentinel) -> text


RULES = [
    Rule("normalize-newlines", 1, "\\r\\n and \\r become \\n",
         lambda s, _: s.replace("\r\n", "\n").replace("\r", "\n")),
    Rule("strip-trailing-ws", 1, "remove whitespace at the end of each line",
         lambda s, _: _TRAILING_WS.sub("", s)),
    Rule("dedent", 1, "remove indentation common to all lines",
         _dedent),
    Rule("strip-indentation", 2, "remove all leading indentation",
         lambda s, _: _INDENTATION.sub("", s)),
    Rule("collapse-inline-spaces", 2, "runs of spaces and tabs become one space",
         lambda s, _: _INLINE_WS.sub(" ", s)),
    Rule("collapse-blank-lines", 1, "keep at most one blank line in a row",
         lambda s, _: _EXTRA_BLANK_LINES.sub("\n\n", s)),
    Rule("remove-blank-lines", 2, "remove blank lines",
         lambda s, _: _BLANK_LINES.sub("\n", s)),
    Rule("trim-message", 1, "remove whitespace at the start and end of a message",
         lambda s, _: s.strip()),
]

# Rules that work on parts or messages rather than on the encoded text.
MERGE_TEXT = "merge-text"
DROP_EMPTY_MESSAGES = "drop-empty-messages"


# --------------------------------------------------------------------------
# Encoding messages as strings with slot sentinels
# --------------------------------------------------------------------------

def _sentinel(parts) -> str:
    """A private-use character that occurs in none of the message's text."""
    text = "".join(p.text for p in parts if isinstance(p, TextPart))
    for code in range(0xE000, 0xF8FF + 1):
        if chr(code) not in text:
            return chr(code)
    raise OptimizerError("no free private-use character to stand for slots")


def _encode(parts, sentinel: str) -> tuple[str, list[SlotPart]]:
    slots = [p for p in parts if isinstance(p, SlotPart)]
    return "".join(sentinel if isinstance(p, SlotPart) else p.text for p in parts), slots


def _decode(text: str, slots: list[SlotPart], sentinel: str) -> tuple:
    pieces = text.split(sentinel)
    if len(pieces) != len(slots) + 1:
        raise OptimizerError("a rule added or removed a slot")
    parts = []
    for i, piece in enumerate(pieces):
        if piece:
            parts.append(TextPart(piece))
        if i < len(slots):
            parts.append(slots[i])
    return tuple(parts)


def _squeeze(text: str) -> str:
    return re.sub(r"\s+", "", text)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

@dataclass
class RuleStats:
    name: str
    level: int
    applications: int = 0  # messages (or parts, for merge-text) changed
    chars_saved: int = 0


@dataclass
class MessageStats:
    role: str
    line: int
    chars_before: int
    chars_after: int
    tokens_before: int
    tokens_after: int
    dropped: bool = False


@dataclass
class OptimizationReport:
    level: int
    token_counter: str
    rules: list[RuleStats] = field(default_factory=list)
    messages: list[MessageStats] = field(default_factory=list)
    comment_count: int = 0
    comment_chars: int = 0

    @property
    def chars_before(self) -> int:
        return sum(m.chars_before for m in self.messages)

    @property
    def chars_after(self) -> int:
        return sum(m.chars_after for m in self.messages)

    @property
    def tokens_before(self) -> int:
        return sum(m.tokens_before for m in self.messages)

    @property
    def tokens_after(self) -> int:
        return sum(m.tokens_after for m in self.messages)

    def format(self) -> str:
        def delta(before, after):
            pct = f"{(after - before) / before:+.0%}" if before else "  -"
            return f"{before:>6} → {after:<6} {pct:>5}"

        out = [f"TrustLex optimizer -O{self.level}   (tokens: {self.token_counter}; input slots not counted)", ""]
        out.append(f"{'MESSAGE':<22} {'CHARS':<21} TOKENS")
        for m in self.messages:
            name = f"{m.role} (line {m.line})" + (" dropped" if m.dropped else "")
            out.append(f"{name:<22} {delta(m.chars_before, m.chars_after)}  {delta(m.tokens_before, m.tokens_after)}")
        out.append(f"{'TOTAL':<22} {delta(self.chars_before, self.chars_after)}  {delta(self.tokens_before, self.tokens_after)}")
        out.append("")
        out.append(f"{'RULE':<24} {'LEVEL':<6} {'APPLIED':>7} {'CHARS SAVED':>12}")
        for r in self.rules:
            out.append(f"{r.name:<24} {'-O' + str(r.level):<6} {r.applications:>7} {r.chars_saved:>12}")
        out.append("")
        out.append(f"comments removed during lexing: {self.comment_count} ({self.comment_chars} chars)")
        return "\n".join(out)


# --------------------------------------------------------------------------
# Optimizer
# --------------------------------------------------------------------------

def _text_of(parts) -> str:
    return "".join(p.text for p in parts if isinstance(p, TextPart))


def optimize(compiled: CompiledPrompt, level: int = 1, token_counter=None,
             comments=()) -> tuple[CompiledPrompt, OptimizationReport]:
    """Return an optimized copy of `compiled` and a report. The input is not
    modified. `token_counter(text) -> int` replaces the built-in estimate;
    `comments` (lexer.Comment objects) are only counted in the report."""
    if level not in LEVELS:
        raise ValueError(f"optimization level must be one of {LEVELS}")
    count = token_counter or estimate_tokens
    counter_name = getattr(token_counter, "__name__", "custom counter") if token_counter else "≈ regex pre-tokenizer estimate"

    active = [r for r in RULES if r.level <= level]
    stats = {name: RuleStats(name, 1) for name in (MERGE_TEXT,)}
    stats.update({r.name: RuleStats(r.name, r.level) for r in active})
    stats[DROP_EMPTY_MESSAGES] = RuleStats(DROP_EMPTY_MESSAGES, 1)
    report = OptimizationReport(
        level, counter_name,
        comment_count=len(comments), comment_chars=sum(len(c.text) for c in comments),
    )

    messages = []
    for message in compiled.messages:
        before_text = _text_of(message.parts)
        parts = message.parts
        if level >= 1:
            parts = _optimize_parts(parts, active, stats)
        after_text = _text_of(parts)
        dropped = level >= 1 and not after_text and not any(isinstance(p, SlotPart) for p in parts)
        if dropped:
            stats[DROP_EMPTY_MESSAGES].applications += 1
        else:
            messages.append(replace(message, parts=parts))
        report.messages.append(MessageStats(
            message.role, message.line, len(before_text), len(after_text),
            count(before_text), count(after_text), dropped,
        ))

    if level >= 1:
        order = [MERGE_TEXT] + [r.name for r in active] + [DROP_EMPTY_MESSAGES]
        report.rules = [stats[name] for name in order]

    optimized = replace(compiled, messages=messages, optimization=level)
    optimized.verify()
    return optimized, report


def _optimize_parts(parts, rules, stats) -> tuple:
    sentinel = _sentinel(parts)
    text, slots = _encode(parts, sentinel)

    # Encoding already merged adjacent text parts and dropped empty ones.
    text_parts = sum(1 for p in parts if isinstance(p, TextPart))
    stats[MERGE_TEXT].applications += text_parts - sum(1 for p in _decode(text, slots, sentinel) if isinstance(p, TextPart))

    # Apply the rules until nothing changes. Rules interact (trim-message can
    # remove the indentation that kept dedent from applying), so a single pass
    # is not idempotent. This terminates: \r -> \n and tab -> space apply at
    # most once, and every other rewrite strictly shortens the text.
    original = text
    for _ in range(MAX_PASSES):
        before_pass = text
        for rule in rules:
            rewritten = rule.apply(text, sentinel)
            if rewritten != text:
                stats[rule.name].applications += 1
                stats[rule.name].chars_saved += len(text) - len(rewritten)
                text = rewritten
        if text == before_pass:
            break
    else:  # pragma: no cover - would mean a non-terminating rule
        raise OptimizerError("rules did not reach a fixpoint")

    if _squeeze(text) != _squeeze(original):
        raise OptimizerError("optimization changed non-whitespace content")
    return _decode(text, slots, sentinel)


# --------------------------------------------------------------------------
# Debug entry point: python optimizer.py FILE.tlx [-O0|-O1|-O2]
# --------------------------------------------------------------------------

def _show(message: Message) -> str:
    return "".join(
        p.text if isinstance(p, TextPart) else f"⟨{p.input}{' sanitized' if p.sanitize else ''}⟩"
        for p in message.parts
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="optimizer.py", description="Optimize a TrustLex program's compiled prompt.")
    parser.add_argument("file")
    parser.add_argument("-O", dest="level", type=int, choices=LEVELS, default=1)
    parser.add_argument("--ir", action="store_true", help="print the optimized IR instead of a before/after view")
    args = parser.parse_args(argv[1:])

    with open(args.file, encoding="utf-8") as f:
        checked, compiled = compile_source(f.read(), args.file)
    if compiled is None:
        print(checked.diagnostics.render(color=sys.stderr.isatty()), file=sys.stderr)
        print("\n" + checked.diagnostics.summary(), file=sys.stderr)
        return 1

    optimized, report = optimize(compiled, args.level, comments=checked.comments)
    if args.ir:
        print(optimized.to_json(indent=2))
        return 0
    kept = iter(optimized.messages)
    for before, stats in zip(compiled.messages, report.messages):
        after = None if stats.dropped else next(kept)
        print(f"── {before.role} (line {before.line}) ──")
        print(f"before: {_show(before)!r}")
        print(f"after:  {_show(after)!r}" if after else "after:  (dropped)")
    print()
    print(report.format())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except CodegenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
