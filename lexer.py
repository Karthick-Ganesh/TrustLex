"""
TrustLex - Module 1: Lexical Analysis.

Turns TrustLex source into a stream of tokens annotated with an exact source
span and their *intrinsic provenance*: the trust level a token carries by
virtue of what it is, independent of control flow.

    string literal          -> TRUSTED       (developer-authored text)
    input NAME              -> UNTRUSTED     (external injection vector)
    input NAME from rag|tool-> SEMI_TRUSTED  (retrieved / tool output)
    input NAME from user    -> UNTRUSTED
    var NAME                -> TRUSTED declaration site
    any other identifier    -> unresolved    (decided by Module 3)

The lexer only seeds trust at sites where it is fixed by the grammar. Trust
that depends on assignments and interpolation (`x = x + user_msg`) is computed
later by the flow-sensitive analysis in Module 3, starting from the
declaration table built here.

String literals are split into text and `{name}` interpolation holes during
lexing, so later phases can trace taint through interpolation and point at the
exact hole that leaks untrusted data.
"""

from __future__ import annotations

import re
import sys
from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum

import ply.lex as lex

from diagnostics import DiagnosticBag, SourceFile, SourceSpan


# --------------------------------------------------------------------------
# Trust lattice and provenance
# --------------------------------------------------------------------------

class TrustLevel(IntEnum):
    """Trust lattice: TRUSTED ⊑ SANITIZED ⊑ SEMI_TRUSTED ⊑ UNTRUSTED.

    The order is by taint: higher means less trustworthy. The join of two
    levels is the less trusted one, so combining trusted and untrusted text
    yields untrusted text.

    SANITIZED is never produced by the lexer. It is the level of external
    data that passed through sanitize(): still distinguishable from
    developer-authored text, but cleared for privileged blocks.
    """

    TRUSTED = 0
    SANITIZED = 1
    SEMI_TRUSTED = 2
    UNTRUSTED = 3

    @classmethod
    def bottom(cls) -> TrustLevel:
        return cls.TRUSTED

    @classmethod
    def top(cls) -> TrustLevel:
        return cls.UNTRUSTED

    def join(self, other: TrustLevel) -> TrustLevel:
        return TrustLevel(max(self, other))

    def meet(self, other: TrustLevel) -> TrustLevel:
        return TrustLevel(min(self, other))

    def leq(self, other: TrustLevel) -> bool:
        """self ⊑ other: data at `self` may flow wherever `other` may."""
        return self <= other

    def __str__(self) -> str:
        return self.name


# Trust assigned by `input NAME from <tag>`. Unknown tags fail closed to
# UNTRUSTED; the parser reports them.
SOURCE_TAGS = {
    "user": TrustLevel.UNTRUSTED,
    "rag": TrustLevel.SEMI_TRUSTED,
    "tool": TrustLevel.SEMI_TRUSTED,
}


class Origin(Enum):
    LITERAL = "literal"
    INPUT_DECL = "input-decl"
    VAR_DECL = "var-decl"
    SOURCE_TAG = "source-tag"
    REFERENCE = "reference"


@dataclass(frozen=True)
class Provenance:
    trust: TrustLevel | None  # None: not decidable lexically
    origin: Origin
    span: SourceSpan
    name: str | None = None
    source_tag: str | None = None


# --------------------------------------------------------------------------
# Token payloads
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TextPart:
    text: str
    span: SourceSpan


@dataclass(frozen=True)
class HolePart:
    name: str
    span: SourceSpan


@dataclass(frozen=True)
class InterpolatedString:
    """Value of a STRING token: decoded text interleaved with `{name}` holes."""

    parts: tuple[TextPart | HolePart, ...]
    raw: str
    triple: bool

    @property
    def holes(self) -> list[HolePart]:
        return [p for p in self.parts if isinstance(p, HolePart)]

    @property
    def is_plain(self) -> bool:
        return not self.holes

    @property
    def text(self) -> str:
        """Decoded text of the literal segments (holes omitted)."""
        return "".join(p.text for p in self.parts if isinstance(p, TextPart))

    def display(self) -> str:
        """Template form, with literal braces re-escaped."""
        return "".join(
            p.text.replace("{", "{{").replace("}", "}}") if isinstance(p, TextPart) else "{" + p.name + "}"
            for p in self.parts
        )


@dataclass(frozen=True)
class Comment:
    text: str
    span: SourceSpan
    block: bool


class TLToken(lex.LexToken):
    """A PLY token extended with a source span and intrinsic provenance."""

    def __init__(self, type, value, lineno, lexpos, span, provenance=None):
        self.type = type
        self.value = value
        self.lineno = lineno
        self.lexpos = lexpos
        self.span = span
        self.provenance = provenance

    @property
    def trust(self) -> TrustLevel | None:
        return self.provenance.trust if self.provenance else None

    def __repr__(self) -> str:
        return f"TLToken({self.type}, {self.value!r}, {self.span})"


class _PartBuilder:
    """Accumulates the text and hole parts of one string literal."""

    def __init__(self, source: SourceFile, start: int):
        self.source = source
        self.parts: list[TextPart | HolePart] = []
        self.buf: list[str] = []
        self.buf_start = start

    def text(self, s: str):
        self.buf.append(s)

    def flush(self, end: int):
        if self.buf:
            self.parts.append(TextPart("".join(self.buf), self.source.span(self.buf_start, end)))
            self.buf = []
        self.buf_start = end

    def hole(self, name: str, start: int, end: int):
        self.flush(start)
        self.parts.append(HolePart(name, self.source.span(start, end)))
        self.buf_start = end


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "{": "{", "}": "}"}
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_TOKEN_START = re.compile(r'[\sA-Za-z_"#{}()=+;]|/\*')
_BRACE_HINT = "for a literal brace write `{{` or `}}` (or `\\{` / `\\}`)"


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------

class TrustLexer:
    """PLY-based TrustLex tokenizer with trust seeding.

    Exposes PLY's `input()` / `token()` interface so it can be handed
    directly to a ply.yacc parser.
    """

    reserved = {
        "system": "SYSTEM",
        "instruction": "INSTRUCTION",
        "var": "VAR",
        "input": "INPUT",
        "insert": "INSERT",
        "sanitize": "SANITIZE",
        "from": "FROM",
    }

    tokens = (
        "IDENT", "STRING",
        "LBRACE", "RBRACE", "LPAREN", "RPAREN", "EQUALS", "PLUS", "SEMI",
    ) + tuple(reserved.values())

    t_ignore = " \t\r"

    t_LBRACE = r"\{"
    t_RBRACE = r"\}"
    t_LPAREN = r"\("
    t_RPAREN = r"\)"
    t_EQUALS = r"="
    t_PLUS = r"\+"
    t_SEMI = r";"

    def __init__(self, filename: str = "<input>", diagnostics: DiagnosticBag | None = None):
        self.filename = filename
        self.diagnostics = diagnostics if diagnostics is not None else DiagnosticBag()
        self._lexer = lex.lex(module=self)
        self.input("")

    # ---- PLY rules (function rules match in definition order) ----

    def t_newline(self, t):
        r"\n+"
        t.lexer.lineno += len(t.value)

    def t_comment(self, t):
        r"\#[^\n]*"
        self.comments.append(Comment(t.value, self._span(t.lexpos, t.lexpos + len(t.value)), block=False))

    def t_block_comment(self, t):
        r"/\*"
        data = t.lexer.lexdata
        close = data.find("*/", t.lexpos + 2)
        if close == -1:
            self.diagnostics.error(
                "TL-L003", "unterminated block comment", self._span(t.lexpos, t.lexpos + 2),
                hint="close the comment with `*/`", label="comment starts here",
            )
            end = len(data)
        else:
            end = close + 2
        text = data[t.lexpos:end]
        self.comments.append(Comment(text, self._span(t.lexpos, end), block=True))
        t.lexer.lineno += text.count("\n")
        t.lexer.lexpos = end

    def t_STRING(self, t):
        r'"(?:"")?'
        return self._scan_string(t)

    def t_IDENT(self, t):
        r"[A-Za-z_][A-Za-z0-9_]*"
        t.type = self.reserved.get(t.value, "IDENT")
        return t

    def t_error(self, t):
        data = t.lexer.lexdata
        start = end = t.lexpos
        while end < len(data) and not _TOKEN_START.match(data, end):
            end += 1
        bad = data[start:end]
        if "'" in bad:
            hint = 'TrustLex strings use double quotes: "..."'
        elif bad[0].isdigit():
            hint = "identifiers cannot start with a digit; quote numeric values as strings"
        else:
            hint = "remove these characters or move them inside a string literal"
        self.diagnostics.error(
            "TL-L001", f"illegal character{'s' if len(bad) > 1 else ''} {bad!r}",
            self._span(start, end), hint=hint,
        )
        t.lexer.skip(end - start)

    # ---- string literals ----

    def _scan_string(self, t):
        data = t.lexer.lexdata
        n = len(data)
        start = t.lexpos
        opener = t.value
        triple = opener == '"""'
        i = start + len(opener)
        parts = _PartBuilder(self.source, i)
        closed = False

        while i < n:
            c = data[i]
            if c == '"' and (not triple or data.startswith('"""', i)):
                parts.flush(i)
                i += len(opener)
                closed = True
                break
            if c == "\n" and not triple:
                break
            if c == "\\":
                if i + 1 >= n:
                    i = n
                    break
                nxt = data[i + 1]
                if nxt == "\n":
                    pass  # line continuation
                elif nxt in _ESCAPES:
                    parts.text(_ESCAPES[nxt])
                else:
                    self.diagnostics.error(
                        "TL-L004", f"invalid escape sequence '\\{nxt}'", self._span(i, i + 2),
                        hint='valid escapes are \\n \\t \\r \\\\ \\" \\{ \\}; write \\\\ for a literal backslash',
                    )
                    parts.text("\\" + nxt)
                i += 2
                continue
            if c == "{":
                if data.startswith("{{", i):
                    parts.text("{")
                    i += 2
                    continue
                i = self._scan_hole(data, i, parts)
                continue
            if c == "}":
                if data.startswith("}}", i):
                    parts.text("}")
                    i += 2
                    continue
                self.diagnostics.error("TL-L005", "unmatched '}' in string literal", self._span(i, i + 1), hint=_BRACE_HINT)
                parts.text("}")
                i += 1
                continue
            parts.text(c)
            i += 1

        if not closed:
            parts.flush(i)
            if triple:
                self.diagnostics.error(
                    "TL-L002", "unterminated triple-quoted string literal", self._span(start, start + 3),
                    hint='close the string with `"""`', label="string starts here",
                )
            else:
                self.diagnostics.error(
                    "TL-L002", "unterminated string literal", self._span(start, i),
                    hint='close the string with a matching `"` on the same line, or use """...""" for multi-line text',
                    label="string starts here",
                )

        raw = data[start:i]
        t.value = InterpolatedString(tuple(parts.parts), raw, triple)
        t.lexer.lineno += raw.count("\n")
        t.lexer.lexpos = i
        return t

    def _scan_hole(self, data: str, i: int, parts: _PartBuilder) -> int:
        """Scan `{name}` starting at data[i] == '{'; return the position after it."""
        j = i + 1
        while j < len(data) and data[j] not in '}"\n':
            j += 1
        if j >= len(data) or data[j] != "}":
            self.diagnostics.error("TL-L005", "unclosed '{' in string literal", self._span(i, i + 1), hint=_BRACE_HINT)
            parts.text("{")
            return i + 1

        name = data[i + 1:j]
        span = self._span(i, j + 1)
        if not name:
            self.diagnostics.error("TL-L005", "empty interpolation '{}'", span, hint=_BRACE_HINT)
        elif not _IDENT_RE.match(name):
            self.diagnostics.error(
                "TL-L005", f"'{{{name}}}' is not a valid interpolation", span,
                hint=f"interpolations must name a variable, e.g. {{user_msg}}; {_BRACE_HINT}",
            )
        elif name in self.reserved:
            self.diagnostics.error(
                "TL-L006", f"keyword '{name}' cannot be interpolated", span,
                hint="interpolate a variable name; rename the variable if it clashes with a keyword",
            )
        else:
            parts.hole(name, i, j + 1)
            return j + 1
        parts.text(data[i:j + 1])
        return j + 1

    # ---- public interface ----

    def input(self, text: str):
        self.source = SourceFile(self.filename, text)
        self.comments: list[Comment] = []
        self.declarations: dict[str, list[Provenance]] = {}
        self._pending: deque[TLToken] = deque()
        self._prev_type: str | None = None
        self._lexer.input(text)
        self._lexer.lineno = 1

    def token(self) -> TLToken | None:
        tok = self._pending.popleft() if self._pending else self._next_raw()
        if tok is None:
            return None
        tok.provenance = self._seed(tok)
        self._prev_type = tok.type
        return tok

    def tokenize(self, text: str) -> list[TLToken]:
        self.input(text)
        return list(self)

    def __iter__(self):
        while (tok := self.token()) is not None:
            yield tok

    # ---- internals ----

    def _span(self, start: int, end: int) -> SourceSpan:
        return self.source.span(start, end)

    def _next_raw(self) -> TLToken | None:
        raw = self._lexer.token()
        if raw is None:
            return None
        length = len(raw.value.raw) if raw.type == "STRING" else len(raw.value)
        span = self._span(raw.lexpos, raw.lexpos + length)
        return TLToken(raw.type, raw.value, span.line, raw.lexpos, span)

    def _peek(self, k: int) -> TLToken | None:
        while len(self._pending) <= k:
            tok = self._next_raw()
            if tok is None:
                return None
            self._pending.append(tok)
        return self._pending[k]

    def _seed(self, tok: TLToken) -> Provenance | None:
        if tok.type == "STRING":
            return Provenance(TrustLevel.TRUSTED, Origin.LITERAL, tok.span)
        if tok.type != "IDENT":
            return None

        name = tok.value
        if self._prev_type == "INPUT":
            trust, tag = TrustLevel.UNTRUSTED, None
            nxt, tag_tok = self._peek(0), self._peek(1)
            if nxt is not None and nxt.type == "FROM" and tag_tok is not None and tag_tok.type == "IDENT":
                tag = tag_tok.value
                trust = SOURCE_TAGS.get(tag, TrustLevel.UNTRUSTED)
            prov = Provenance(trust, Origin.INPUT_DECL, tok.span, name, tag)
        elif self._prev_type == "VAR":
            prov = Provenance(TrustLevel.TRUSTED, Origin.VAR_DECL, tok.span, name)
        elif self._prev_type == "FROM":
            return Provenance(None, Origin.SOURCE_TAG, tok.span, name)
        else:
            return Provenance(None, Origin.REFERENCE, tok.span, name)

        self.declarations.setdefault(name, []).append(prov)
        return prov


# --------------------------------------------------------------------------
# Debug entry point: python lexer.py FILE.tlx
# --------------------------------------------------------------------------

def _describe(tok: TLToken) -> str:
    if tok.type == "STRING":
        text = tok.value.display().replace("\n", "\\n")
        text = text if len(text) <= 48 else text[:45] + "..."
        return f'"{text}"'
    return str(tok.value)


def format_tokens(tokens: list[TLToken]) -> str:
    """A table of tokens with their location and seeded trust."""
    rows = [f"{'LOC':<8} {'TYPE':<12} {'TRUST':<13} {'ORIGIN':<16} TEXT"]
    for tok in tokens:
        prov = tok.provenance
        trust = str(prov.trust) if prov and prov.trust is not None else "-"
        origin = prov.origin.value if prov else "-"
        if prov and prov.source_tag:
            origin += f"({prov.source_tag})"
        loc = f"{tok.span.line}:{tok.span.col}"
        rows.append(f"{loc:<8} {tok.type:<12} {trust:<13} {origin:<16} {_describe(tok)}")
    return "\n".join(rows)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python lexer.py FILE.tlx", file=sys.stderr)
        return 2
    path = argv[1]
    with open(path, encoding="utf-8") as f:
        text = f.read()

    lexer = TrustLexer(path)
    tokens = lexer.tokenize(text)

    print(format_tokens(tokens))
    print(f"\n{len(tokens)} tokens, {len(lexer.comments)} comments, "
          f"declarations: {', '.join(lexer.declarations) or 'none'}")
    if len(lexer.diagnostics):
        print("\n" + lexer.diagnostics.render(color=sys.stdout.isatty()))
        print("\n" + lexer.diagnostics.summary())
    return 1 if lexer.diagnostics.has_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
