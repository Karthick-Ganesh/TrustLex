"""
TrustLex diagnostics: source locations and rich, snippet-based error reports.

Every phase of the compiler (lexer, parser, security checker) reports problems
through a shared DiagnosticBag so the CLI can render them uniformly:

    error[TL-S010]: UNTRUSTED data from input `user_msg` reaches a `system` block
      --> injection.tlx:13:12
       |
    13 |     insert(note)
       |            ^~~~ `note` carries UNTRUSTED data
       |
      ::: injection.tlx:5:7
       |
     5 | input user_msg
       |       -------- `user_msg` is UNTRUSTED input
       = help: sanitize the value before it enters the block: `insert(sanitize(note))`

A diagnostic can carry secondary locations (`related`, e.g. the steps of a
taint path) and machine-applicable fixes (`fixes`, see apply_edits).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from enum import Enum

TAB_WIDTH = 4


class SourceFile:
    """A named source text with an index of line start offsets."""

    def __init__(self, name: str, text: str):
        self.name = name
        self.text = text
        self._line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    @property
    def line_count(self) -> int:
        return len(self._line_starts)

    def location(self, offset: int) -> tuple[int, int]:
        """Map a 0-based character offset to a 1-based (line, column)."""
        index = bisect.bisect_right(self._line_starts, offset) - 1
        return index + 1, offset - self._line_starts[index] + 1

    def span(self, start: int, end: int) -> SourceSpan:
        """Build a span covering text[start:end] (end is exclusive)."""
        line, col = self.location(start)
        end_line, end_col = self.location(end)
        return SourceSpan(self.name, line, col, end_line, end_col, start, end, self)

    def line_text(self, line: int) -> str:
        start = self._line_starts[line - 1]
        end = self.text.find("\n", start)
        if end == -1:
            end = len(self.text)
        return self.text[start:end].rstrip("\r")


@dataclass(frozen=True)
class SourceSpan:
    """A half-open region of a source file; lines and columns are 1-based."""

    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    offset: int
    end_offset: int
    source: SourceFile | None = field(default=None, compare=False, repr=False)

    @property
    def length(self) -> int:
        return self.end_offset - self.offset

    @property
    def text(self) -> str:
        """The source text this span covers ("" when the source is unknown)."""
        return self.source.text[self.offset:self.end_offset] if self.source else ""

    def cover(self, other: SourceSpan) -> SourceSpan:
        """Smallest span containing both self and other."""
        first = self if self.offset <= other.offset else other
        last = self if self.end_offset >= other.end_offset else other
        return SourceSpan(
            self.file, first.line, first.col, last.end_line, last.end_col,
            first.offset, last.end_offset, self.source,
        )

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


@dataclass(frozen=True)
class Related:
    """A secondary location shown under the main snippet."""

    span: SourceSpan
    message: str


@dataclass(frozen=True)
class Edit:
    """Replace the text under `span` with `text` (empty span: insert)."""

    span: SourceSpan
    text: str


@dataclass(frozen=True)
class Fix:
    """A machine-applicable remediation: one or more non-overlapping edits."""

    message: str
    edits: tuple[Edit, ...]


def apply_edits(text: str, edits) -> str:
    """Apply non-overlapping edits to `text`."""
    ordered = sorted(edits, key=lambda e: (e.span.offset, e.span.end_offset))
    for a, b in zip(ordered, ordered[1:]):
        if b.span.offset < a.span.end_offset:
            raise ValueError(f"overlapping edits at {a.span} and {b.span}")
    for edit in reversed(ordered):
        text = text[:edit.span.offset] + edit.text + text[edit.span.end_offset:]
    return text


_ANSI = {
    Severity.ERROR: "1;31",
    Severity.WARNING: "1;33",
    Severity.NOTE: "1;36",
    "gutter": "1;34",
    "secondary": "1;34",
    "hint": "1;32",
    "bold": "1",
}


def _paint(text: str, style, color: bool) -> str:
    return f"\033[{_ANSI[style]}m{text}\033[0m" if color else text


@dataclass
class Diagnostic:
    code: str
    severity: Severity
    message: str
    span: SourceSpan
    hint: str | None = None
    label: str | None = None
    notes: list[str] = field(default_factory=list)
    related: list[Related] = field(default_factory=list)
    fixes: list[Fix] = field(default_factory=list)

    def render(self, color: bool = False) -> str:
        sev = self.severity
        out = [_paint(f"{sev.value}[{self.code}]", sev, color) + _paint(f": {self.message}", "bold", color)]

        lines = [self.span.line] + [r.span.line for r in self.related]
        width = max(len(str(n)) for n in lines)
        pad = " " * width
        bar = _paint(f"{pad} |", "gutter", color)

        out.append(_paint(f"{pad}--> ", "gutter", color) + str(self.span))
        if self.span.source is not None:
            out.append(bar)
            out += self._snippet(self.span, width, "^", "~", self.label, sev, color)
        for rel in self.related:
            if rel.span.source is None:
                out.append(_paint(f"{pad}::: ", "gutter", color) + f"{rel.span}: {rel.message}")
                continue
            out.append(bar)
            out.append(_paint(f"{pad}::: ", "gutter", color) + str(rel.span))
            out.append(bar)
            out += self._snippet(rel.span, width, "-", "-", rel.message, "secondary", color)

        prefix = _paint(f"{pad} =", "gutter", color)
        for note in self.notes:
            out.append(f"{prefix} note: {note}")
        for fix in self.fixes:
            out.append(f"{prefix} " + _paint("help", "hint", color) + f": {fix.message}")
        if self.hint:
            out.append(f"{prefix} " + _paint("hint", "hint", color) + f": {self.hint}")
        return "\n".join(out)

    @staticmethod
    def _snippet(span, width, first, rest, label, style, color) -> list[str]:
        text = span.source.line_text(span.line)
        # Columns count characters; tabs are expanded only for display.
        before = text[: span.col - 1].expandtabs(TAB_WIDTH)
        last = span.end_col - 1 if span.end_line == span.line else len(text)
        through = text[:last].expandtabs(TAB_WIDTH)
        marks = first + rest * max(len(through) - len(before) - 1, 0)
        suffix = f" {label}" if label else ""
        return [
            _paint(f"{span.line:>{width}} |", "gutter", color) + f" {text.expandtabs(TAB_WIDTH)}",
            _paint(f"{' ' * width} |", "gutter", color) + " " + " " * len(before) + _paint(marks + suffix, style, color),
        ]


class DiagnosticBag:
    """Collects diagnostics from every compiler phase."""

    def __init__(self):
        self.items: list[Diagnostic] = []

    def add(self, diagnostic: Diagnostic) -> Diagnostic:
        self.items.append(diagnostic)
        return diagnostic

    def report(self, severity: Severity, code, message, span, **details) -> Diagnostic:
        return self.add(Diagnostic(code, severity, message, span, **details))

    def error(self, code, message, span, **details) -> Diagnostic:
        return self.report(Severity.ERROR, code, message, span, **details)

    def warning(self, code, message, span, **details) -> Diagnostic:
        return self.report(Severity.WARNING, code, message, span, **details)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.items if d.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.items if d.severity is Severity.WARNING]

    @property
    def has_errors(self) -> bool:
        return any(d.severity is Severity.ERROR for d in self.items)

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def render(self, color: bool = False) -> str:
        ordered = sorted(self.items, key=lambda d: (d.span.file, d.span.offset))
        return "\n\n".join(d.render(color) for d in ordered)

    def summary(self) -> str:
        return f"{len(self.errors)} error(s), {len(self.warnings)} warning(s)"
