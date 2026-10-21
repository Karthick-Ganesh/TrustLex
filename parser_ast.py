"""
TrustLex - Module 2: Syntax Analysis.

An LALR(1) grammar (PLY yacc) that turns the token stream from Module 1 into
a typed abstract syntax tree. Every node carries a source span.

Grammar (semicolons are optional; a lone `;` is an empty statement):

    program    : stmt_list
    stmt_list  : stmt_list stmt | <empty>
    stmt       : var_decl | input_decl | assign | block | SEMI
    var_decl   : VAR IDENT EQUALS expr
    input_decl : INPUT IDENT | INPUT IDENT FROM IDENT
    assign     : IDENT EQUALS expr
    block      : (SYSTEM | INSTRUCTION) LBRACE items RBRACE
    items      : items item | <empty>
    item       : STRING | INSERT LPAREN expr RPAREN | SEMI
    expr       : expr PLUS term | term
    term       : STRING | IDENT | SANITIZE LPAREN expr RPAREN | LPAREN expr RPAREN

Additional error productions recognise common mistakes (a bare variable in a
block, a stray string, `insert` outside a block, ...) and report them with a
targeted hint. The `error` token resynchronises at the next statement or
block item so that one run reports every syntax error.

String interpolation holes (`"... {x} ..."`) become VarRef nodes, so the
security checker sees interpolation and `insert(x)` as the same kind of flow.
"""

from __future__ import annotations

import io
import sys
from dataclasses import dataclass, field, fields
from enum import Enum

import ply.yacc as yacc

from diagnostics import DiagnosticBag, SourceFile, SourceSpan
from lexer import SOURCE_TAGS, HolePart, InterpolatedString, TLToken, TrustLevel, TrustLexer


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------

def node(cls):
    """Declare an AST node: a dataclass compared by identity, so later
    phases can key side tables (trust facts, ...) by node."""
    return dataclass(eq=False)(cls)


@node
class Node:
    span: SourceSpan = field(kw_only=True, repr=False)


class Expr(Node):
    pass


class Stmt(Node):
    pass


class BlockItem(Node):
    pass


class BlockKind(Enum):
    SYSTEM = "system"
    INSTRUCTION = "instruction"


@node
class TextSegment(Node):
    text: str


@node
class VarRef(Expr):
    name: str
    interpolated: bool = False  # written as {name} inside a string literal


@node
class StringLit(Expr):
    parts: list[TextSegment | VarRef]
    triple: bool = False

    @property
    def holes(self) -> list[VarRef]:
        return [p for p in self.parts if isinstance(p, VarRef)]

    def display(self) -> str:
        return "".join(
            p.text.replace("{", "{{").replace("}", "}}") if isinstance(p, TextSegment) else "{" + p.name + "}"
            for p in self.parts
        )


@node
class Concat(Expr):
    left: Expr
    right: Expr


@node
class Sanitize(Expr):
    expr: Expr


@node
class VarDecl(Stmt):
    name: str
    name_span: SourceSpan = field(repr=False)
    value: Expr


@node
class InputDecl(Stmt):
    name: str
    name_span: SourceSpan = field(repr=False)
    trust: TrustLevel
    source_tag: str | None = None


@node
class Assign(Stmt):
    name: str
    name_span: SourceSpan = field(repr=False)
    value: Expr


@node
class TextItem(BlockItem):
    text: StringLit


@node
class InsertItem(BlockItem):
    expr: Expr


@node
class Block(Stmt):
    kind: BlockKind
    items: list[BlockItem]
    keyword_span: SourceSpan = field(repr=False)


@node
class Program(Node):
    statements: list[Stmt]


def iter_children(n: Node):
    """Yield the direct child nodes of `n` in field order."""
    for f in fields(n):
        value = getattr(n, f.name)
        if isinstance(value, Node):
            yield value
        elif isinstance(value, list):
            yield from (v for v in value if isinstance(v, Node))


class NodeVisitor:
    """Dispatches to visit_<NodeClass>; falls back to visiting children."""

    def visit(self, n: Node):
        return getattr(self, "visit_" + type(n).__name__, self.generic_visit)(n)

    def generic_visit(self, n: Node):
        for child in iter_children(n):
            self.visit(child)


class NodeTransformer(NodeVisitor):
    """Visitor that replaces each child with the result of visiting it.

    Returning None from a visit method removes a node from a list field;
    returning a list splices several nodes in its place.
    """

    def generic_visit(self, n: Node):
        for f in fields(n):
            value = getattr(n, f.name)
            if isinstance(value, Node):
                setattr(n, f.name, self.visit(value))
            elif isinstance(value, list):
                new = []
                for item in value:
                    if not isinstance(item, Node):
                        new.append(item)
                        continue
                    result = self.visit(item)
                    if result is None:
                        continue
                    if isinstance(result, list):
                        new.extend(result)
                    else:
                        new.append(result)
                setattr(n, f.name, new)
        return n


def _preview(text: str, limit: int = 40) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _label(n: Node) -> str:
    if isinstance(n, Program):
        return "Program"
    if isinstance(n, (VarDecl, Assign)):
        label = f"{type(n).__name__} {n.name}"
    elif isinstance(n, InputDecl):
        label = f"InputDecl {n.name} [{n.trust}]" + (f" from {n.source_tag}" if n.source_tag else "")
    elif isinstance(n, Block):
        label = f"Block {n.kind.value}"
    elif isinstance(n, StringLit):
        label = f'StringLit "{_preview(n.display())}"'
    elif isinstance(n, VarRef):
        label = f"VarRef {n.name}" + (" (interpolated)" if n.interpolated else "")
    else:
        label = type(n).__name__
    return f"{label} @{n.span.line}:{n.span.col}"


def _dump_children(n: Node) -> list[Node]:
    if isinstance(n, StringLit):
        return n.holes
    return list(iter_children(n))


def dump(n: Node) -> str:
    """Render a tree view of the AST."""
    lines = [_label(n)]

    def walk(parent: Node, prefix: str):
        children = _dump_children(parent)
        for i, child in enumerate(children):
            last = i == len(children) - 1
            lines.append(f"{prefix}{'└─ ' if last else '├─ '}{_label(child)}")
            walk(child, prefix + ("   " if last else "│  "))

    walk(n, "")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

_TOKEN_NAMES = {
    "IDENT": "identifier", "STRING": "string", "$end": "end of file",
    "LBRACE": "`{`", "RBRACE": "`}`", "LPAREN": "`(`", "RPAREN": "`)`",
    "EQUALS": "`=`", "PLUS": "`+`", "SEMI": "`;`",
}
_TOKEN_ORDER = [
    "PLUS", "RPAREN", "IDENT", "STRING", "SANITIZE", "LPAREN", "EQUALS", "FROM", "INSERT", "RBRACE",
    "VAR", "INPUT", "SYSTEM", "INSTRUCTION", "SEMI", "LBRACE", "$end",
]
# Tokens accepted in a context only by error productions; never suggest them.
_STMT_ERROR_ONLY = {"INSERT", "STRING"}
_ITEM_ERROR_ONLY = {"IDENT", "SYSTEM", "INSTRUCTION", "SANITIZE"}
_STMT_KEYWORDS = {"VAR", "INPUT", "SYSTEM", "INSTRUCTION"}


def _token_name(type_: str) -> str:
    return _TOKEN_NAMES.get(type_, f"`{type_.lower()}`")


def _describe(tok: TLToken) -> str:
    if tok.type == "IDENT":
        return f"identifier `{tok.value}`"
    if tok.type == "STRING":
        return "string literal"
    return _token_name(tok.type)


@dataclass
class ParseResult:
    program: Program
    diagnostics: DiagnosticBag
    source: SourceFile
    comments: list = field(default_factory=list)  # lexer.Comment, removed during lexing

    @property
    def ok(self) -> bool:
        return not self.diagnostics.has_errors


class TrustParser:
    """LALR(1) parser for TrustLex. Build once, call parse() many times."""

    tokens = TrustLexer.tokens
    start = "program"

    def __init__(self, errorlog=None):
        self._parser = yacc.yacc(
            module=self, start=self.start, debug=False, write_tables=False,
            errorlog=errorlog if errorlog is not None else yacc.NullLogger(),
        )

    def parse(self, text: str, filename: str = "<input>", diagnostics: DiagnosticBag | None = None) -> ParseResult:
        self.diagnostics = diagnostics if diagnostics is not None else DiagnosticBag()
        self.lexer = TrustLexer(filename, self.diagnostics)
        self.lexer.input(text)
        self._statements: list[Stmt] = []
        self._last_token: TLToken | None = None
        self._recovering = False
        self._error_offset = -1
        self._eof_reported = False

        program = self._parser.parse(lexer=self.lexer, tokenfunc=self._next_token)
        if program is None:
            # PLY abandons the parse on an error at end of input, without
            # calling p_error if it is still recovering from an earlier one.
            # An unclosed block is never fallout, so report it regardless.
            if not self._eof_reported:
                self._report_unclosed_block()
            program = self._program(self._statements)
        return ParseResult(program, self.diagnostics, self.lexer.source, self.lexer.comments)

    # ---- helpers ----

    def _next_token(self):
        tok = self.lexer.token()
        if tok is not None:
            self._last_token = tok
        return tok

    @staticmethod
    def _span(p, i: int) -> SourceSpan:
        sym = p.slice[i]
        return sym.span if isinstance(sym, TLToken) else p[i].span

    def _cover(self, p, i: int, j: int) -> SourceSpan:
        return self._span(p, i).cover(self._span(p, j))

    def _program(self, statements: list[Stmt]) -> Program:
        if statements:
            span = statements[0].span.cover(statements[-1].span)
        else:
            span = self.lexer.source.span(0, 0)
        return Program(statements, span=span)

    def _completed(self, n: Node | None):
        """A statement or item parsed cleanly; recovery ends once one that
        starts after the last syntax error has been parsed."""
        if self._recovering and n is not None and n.span.offset > self._error_offset:
            self._recovering = False

    def _report(self, code, message, span, hint=None, label=None):
        """Report an error found by an error production, unless it is fallout
        from a syntax error the parser is still recovering from."""
        if not self._recovering:
            self.diagnostics.error(code, message, span, hint=hint, label=label)

    def _string(self, tok: TLToken) -> StringLit:
        value: InterpolatedString = tok.value
        parts = [
            VarRef(p.name, interpolated=True, span=p.span) if isinstance(p, HolePart) else TextSegment(p.text, span=p.span)
            for p in value.parts
        ]
        return StringLit(parts, value.triple, span=tok.span)

    # ---- program and statements ----

    def p_program(self, p):
        "program : stmt_list"
        p[0] = self._program(p[1])

    def p_stmt_list_empty(self, p):
        "stmt_list :"
        p[0] = self._statements

    def p_stmt_list(self, p):
        "stmt_list : stmt_list stmt"
        p[0] = p[1]
        if p[2] is not None:
            p[0].append(p[2])

    def p_stmt(self, p):
        """stmt : var_decl
                | input_decl
                | assign
                | block"""
        p[0] = p[1]
        self._completed(p[0])

    def p_stmt_semi(self, p):
        "stmt : SEMI"
        p[0] = None

    def p_var_decl(self, p):
        "var_decl : VAR IDENT EQUALS expr"
        p[0] = VarDecl(p[2], self._span(p, 2), p[4], span=self._cover(p, 1, 4))

    def p_input_decl(self, p):
        """input_decl : INPUT IDENT
                      | INPUT IDENT FROM IDENT"""
        name_tok = p.slice[2]
        tag = p[4] if len(p) == 5 else None
        if tag is not None and tag not in SOURCE_TAGS:
            self._report(
                "TL-P004", f"unknown input source `{tag}`", self._span(p, 4),
                hint=f"valid sources are: {', '.join(SOURCE_TAGS)}; unknown sources are treated as UNTRUSTED",
            )
        p[0] = InputDecl(p[2], name_tok.span, name_tok.provenance.trust, tag, span=self._cover(p, 1, len(p) - 1))

    def p_assign(self, p):
        "assign : IDENT EQUALS expr"
        p[0] = Assign(p[1], self._span(p, 1), p[3], span=self._cover(p, 1, 3))

    def p_block(self, p):
        """block : SYSTEM LBRACE items RBRACE
                 | INSTRUCTION LBRACE items RBRACE"""
        kind = BlockKind.SYSTEM if p.slice[1].type == "SYSTEM" else BlockKind.INSTRUCTION
        p[0] = Block(kind, p[3], self._span(p, 1), span=self._cover(p, 1, 4))

    # ---- block items ----

    def p_items_empty(self, p):
        "items :"
        p[0] = []

    def p_items(self, p):
        "items : items item"
        p[0] = p[1]
        if p[2] is not None:
            p[0].append(p[2])

    def p_item_text(self, p):
        "item : STRING"
        p[0] = TextItem(self._string(p.slice[1]), span=self._span(p, 1))
        self._completed(p[0])

    def p_item_insert(self, p):
        "item : INSERT LPAREN expr RPAREN"
        p[0] = InsertItem(p[3], span=self._cover(p, 1, 4))
        self._completed(p[0])

    def p_item_semi(self, p):
        "item : SEMI"
        p[0] = None

    # ---- expressions ----

    def p_expr_concat(self, p):
        "expr : expr PLUS term"
        p[0] = Concat(p[1], p[3], span=self._cover(p, 1, 3))

    def p_expr_term(self, p):
        "expr : term"
        p[0] = p[1]

    def p_term_string(self, p):
        "term : STRING"
        p[0] = self._string(p.slice[1])

    def p_term_ident(self, p):
        "term : IDENT"
        p[0] = VarRef(p[1], span=self._span(p, 1))

    def p_term_sanitize(self, p):
        "term : SANITIZE LPAREN expr RPAREN"
        p[0] = Sanitize(p[3], span=self._cover(p, 1, 4))

    def p_term_group(self, p):
        "term : LPAREN expr RPAREN"
        p[0] = p[2]

    # ---- error productions: common mistakes with targeted hints ----

    def p_item_bare_ident(self, p):
        "item : IDENT"
        self._report(
            "TL-P003", f"bare variable `{p[1]}` inside a block", self._span(p, 1),
            hint=f"embed variables explicitly: insert({p[1]})",
        )

    def p_item_bare_sanitize(self, p):
        "item : SANITIZE LPAREN expr RPAREN"
        self._report(
            "TL-P003", "bare sanitize(...) inside a block", self._cover(p, 1, 4),
            hint="embed the sanitized value explicitly: insert(sanitize(...))",
        )

    def p_stmt_top_level_insert(self, p):
        "stmt : INSERT LPAREN expr RPAREN"
        self._report(
            "TL-P005", "insert(...) outside a block", self._cover(p, 1, 4),
            hint="insert() is only valid inside a `system { ... }` or `instruction { ... }` block",
        )
        p[0] = None

    def p_item_nested_block(self, p):
        "item : block"
        self._report(
            "TL-P006", f"`{p[1].kind.value}` block nested inside another block", p[1].keyword_span,
            hint="blocks cannot be nested; close the enclosing block with `}` first",
        )

    def p_var_decl_missing_value(self, p):
        "var_decl : VAR IDENT"
        self._report(
            "TL-P007", f"variable `{p[2]}` declared without a value", self._cover(p, 1, 2),
            hint=f'give it a value (var {p[2]} = "...") or declare external data with `input {p[2]}`',
        )
        p[0] = None

    def p_stmt_stray_string(self, p):
        "stmt : STRING"
        self._report(
            "TL-P008", "string literal outside a block", self._span(p, 1),
            hint='place it inside a block, assign it (var s = "..."), or join it to the previous value with `+`',
        )
        p[0] = None

    def p_stmt_error(self, p):
        "stmt : error"
        p[0] = None

    def p_item_error(self, p):
        "item : error"
        p[0] = None

    def p_error(self, tok):
        self._recovering = True
        if tok is None:
            self._error_offset = len(self.lexer.source.text)
            self._report_eof()
            return
        self._error_offset = tok.span.offset

        expected = self._expected()
        hint = None
        if tok.type in _STMT_KEYWORDS and "RBRACE" in expected:
            hint = "is a `}` missing before this? declarations and blocks cannot appear inside a block"
        elif expected:
            hint = "expected " + self._format_expected(expected)
        self.diagnostics.error("TL-P001", f"unexpected {_describe(tok)}", tok.span, hint=hint)

    def _report_eof(self):
        self._eof_reported = True
        if self._report_unclosed_block():
            return
        source = self.lexer.source
        end = self._last_token.span.end_offset if self._last_token else len(source.text)
        expected = self._expected()
        hint = "expected " + self._format_expected(expected) if expected else None
        self.diagnostics.error("TL-P001", "unexpected end of file", source.span(end, end), hint=hint)

    def _report_unclosed_block(self) -> bool:
        brace = next((s for s in reversed(self._parser.symstack) if getattr(s, "type", None) == "LBRACE"), None)
        if brace is None:
            return False
        self.diagnostics.error(
            "TL-P002", "unexpected end of file: block is never closed", brace.span,
            hint="add `}` to close the block", label="block opened here",
        )
        return True

    def _accepts(self, token_type: str) -> bool:
        """Would `token_type` be shifted from the current parser stack?

        LALR state merging makes a state's action table admit lookaheads that
        are only valid in other contexts, so simulate the pending reductions
        on a copy of the stack instead of reading one row of the table.
        """
        action, goto, productions = self._parser.action, self._parser.goto, self._parser.productions
        stack = list(self._parser.statestack)
        while True:
            act = action[stack[-1]].get(token_type)
            if act is None:
                return False
            if act >= 0:  # shift, or accept on $end
                return True
            prod = productions[-act]
            if prod.len:
                del stack[-prod.len:]
            target = goto[stack[-1]].get(prod.name)
            if target is None:
                return False
            stack.append(target)

    def _expected(self) -> set[str]:
        expected = {t for t in (*self.tokens, "$end") if self._accepts(t)}
        if "VAR" in expected:
            expected -= _STMT_ERROR_ONLY
        if "RBRACE" in expected and "INSERT" in expected:
            expected -= _ITEM_ERROR_ONLY
        return expected

    @staticmethod
    def _format_expected(expected: set[str]) -> str:
        names = [_token_name(t) for t in sorted(expected, key=lambda t: (_TOKEN_ORDER.index(t) if t in _TOKEN_ORDER else 99, t))]
        return names[0] if len(names) == 1 else "one of: " + ", ".join(names)


def grammar_report() -> str:
    """Build the grammar and return PLY's warnings (conflicts, unused
    tokens, ...). Empty means the grammar is clean."""
    log = io.StringIO()
    TrustParser(errorlog=yacc.PlyLogger(log))
    return log.getvalue()


_default_parser: TrustParser | None = None


def default_parser() -> TrustParser:
    """The shared parser; its LALR tables are built on first use."""
    global _default_parser
    if _default_parser is None:
        _default_parser = TrustParser()
    return _default_parser


def parse(text: str, filename: str = "<input>", diagnostics: DiagnosticBag | None = None) -> ParseResult:
    return default_parser().parse(text, filename, diagnostics)


# --------------------------------------------------------------------------
# Debug entry point: python parser_ast.py FILE.tlx
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python parser_ast.py FILE.tlx", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        result = parse(f.read(), argv[1])
    print(dump(result.program))
    if len(result.diagnostics):
        print("\n" + result.diagnostics.render(color=sys.stdout.isatty()))
        print("\n" + result.diagnostics.summary())
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
