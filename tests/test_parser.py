"""Tests for TrustLex Module 2: grammar, AST construction, and syntax errors."""

import os
from pathlib import Path

import pytest

from lexer import TrustLevel
from parser_ast import (
    Assign, Block, BlockKind, Concat, InputDecl, InputType, InsertItem, NodeTransformer, NodeVisitor,
    Sanitize, StringLit, TextItem, TextSegment, VarDecl, VarRef, dump, grammar_report, parse,
)

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"


def ok(src):
    result = parse(src, "test.tlx")
    assert result.ok, result.diagnostics.render()
    return result.program


def codes(src):
    return [d.code for d in parse(src, "test.tlx").diagnostics]


# ---- grammar ----

def test_grammar_has_no_conflicts_or_warnings():
    assert grammar_report() == ""


def test_empty_program():
    assert ok("").statements == []
    assert ok("# only a comment\n;;").statements == []


# ---- statements ----

def test_var_decl():
    [stmt] = ok('var greeting = "hello"').statements
    assert isinstance(stmt, VarDecl) and stmt.name == "greeting"
    assert isinstance(stmt.value, StringLit)
    assert (stmt.name_span.line, stmt.name_span.col) == (1, 5)


@pytest.mark.parametrize("src, trust, tag", [
    ("input u", TrustLevel.UNTRUSTED, None),
    ("input u from user", TrustLevel.UNTRUSTED, "user"),
    ("input u from rag", TrustLevel.SEMI_TRUSTED, "rag"),
    ("input u from tool", TrustLevel.SEMI_TRUSTED, "tool"),
])
def test_input_decl(src, trust, tag):
    [stmt] = ok(src).statements
    assert isinstance(stmt, InputDecl)
    assert (stmt.name, stmt.trust, stmt.source_tag) == ("u", trust, tag)


def test_assign():
    [_, _, stmt] = ok('input u\nvar a = "x"\na = a + u').statements
    assert isinstance(stmt, Assign) and stmt.name == "a"
    assert isinstance(stmt.value, Concat)


@pytest.mark.parametrize("keyword, kind", [("system", BlockKind.SYSTEM), ("instruction", BlockKind.INSTRUCTION)])
def test_blocks(keyword, kind):
    [block] = ok(keyword + ' { "text" insert(x) ; insert(sanitize(x)) }').statements
    assert isinstance(block, Block) and block.kind is kind
    assert [type(i) for i in block.items] == [TextItem, InsertItem, InsertItem]
    assert isinstance(block.items[2].expr, Sanitize)


def test_empty_block():
    [block] = ok("system { }").statements
    assert block.items == []


# ---- expressions ----

def test_concat_is_left_associative():
    [stmt] = ok("var s = a + b + c").statements
    outer = stmt.value
    assert isinstance(outer, Concat) and isinstance(outer.left, Concat)
    assert [outer.left.left.name, outer.left.right.name, outer.right.name] == ["a", "b", "c"]


def test_parentheses_group():
    [stmt] = ok("var s = a + (b + c)").statements
    assert isinstance(stmt.value.right, Concat)


def test_sanitize_in_expressions():
    [stmt] = ok('var s = sanitize(u + "x") + v').statements
    assert isinstance(stmt.value.left, Sanitize)
    assert isinstance(stmt.value.left.expr, Concat)


def test_insert_accepts_any_expression():
    [block] = ok('system { insert(sanitize(a) + "-" + b) }').statements
    assert isinstance(block.items[0].expr, Concat)


def test_interpolation_becomes_var_refs():
    [stmt] = ok('var s = "Hi {name}, you said {msg}."').statements
    parts = stmt.value.parts
    assert [type(p) for p in parts] == [TextSegment, VarRef, TextSegment, VarRef, TextSegment]
    name = parts[1]
    assert name.interpolated and name.name == "name"
    assert (name.span.col, name.span.end_col) == (13, 19)
    assert [h.name for h in stmt.value.holes] == ["name", "msg"]


def test_semicolons_are_optional():
    with_semis = 'var a = "x"; input u; system { "t"; insert(u); };'
    without = 'var a = "x" input u system { "t" insert(u) }'
    def shape(src):  # tree without positions, which differ by the `;`s
        return [line.split(" @")[0] for line in dump(ok(src)).splitlines()]

    assert shape(with_semis) == shape(without)


# ---- spans ----

def test_node_spans():
    src = 'input u\nsystem {\n  insert(u)\n}'
    _, block = ok(src).statements
    assert (block.span.line, block.span.col, block.span.end_line, block.span.end_col) == (2, 1, 4, 2)
    insert = block.items[0]
    assert (insert.span.line, insert.span.col, insert.span.end_col) == (3, 3, 12)
    assert block.keyword_span.end_col == 7


def test_program_span_covers_all_statements():
    program = ok('var a = "x"\n\ninput b')
    assert (program.span.line, program.span.end_line) == (1, 3)


# ---- visitors ----

def test_node_visitor_collects_refs():
    class Refs(NodeVisitor):
        def __init__(self):
            self.names = []

        def visit_VarRef(self, n):
            self.names.append(n.name)

    visitor = Refs()
    visitor.visit(ok('var a = "{x}" + y\nsystem { insert(sanitize(z)) "{w}" }'))
    assert visitor.names == ["x", "y", "z", "w"]


def test_node_transformer_removes_and_replaces():
    class Strip(NodeTransformer):
        def visit_InsertItem(self, n):
            return None

        def visit_VarRef(self, n):
            return VarRef(n.name.upper(), span=n.span)

    program = Strip().visit(ok('var a = b\nsystem { "t" insert(a) }'))
    assert program.statements[0].value.name == "B"
    assert [type(i) for i in program.statements[1].items] == [TextItem]


# ---- syntax errors ----

@pytest.mark.parametrize("src, expected", [
    ("var x = )", ["TL-P001"]),
    ('input u\nsystem {\n  insert(u)\n', ["TL-P002"]),
    ("system { u }", ["TL-P003"]),
    ("system { sanitize(u) }", ["TL-P003"]),
    ("input w from web", ["TL-P004"]),
    ("insert(u)", ["TL-P005"]),
    ("system { instruction { } }", ["TL-P006"]),
    ("var k", ["TL-P007"]),
    ('"stray"', ["TL-P008"]),
])
def test_error_codes(src, expected):
    assert codes(src) == expected


def test_expected_tokens_hint():
    [diag] = parse("var x = )", "t.tlx").diagnostics
    assert diag.message == "unexpected `)`"
    assert diag.hint == "expected one of: identifier, string, `sanitize`, `(`"


def test_expected_tokens_are_context_exact():
    # LALR state merging would otherwise also suggest statement keywords here.
    [diag] = parse("input u\nsystem { insert(u }", "t.tlx").diagnostics
    assert diag.hint == "expected one of: `+`, `)`"


def test_unexpected_eof_points_after_last_token():
    [diag] = parse("var x =", "t.tlx").diagnostics
    assert (diag.code, diag.span.col) == ("TL-P001", 8)


def test_unclosed_block_points_at_brace():
    [diag] = parse("system {\n  \"a\"", "t.tlx").diagnostics
    assert (diag.code, diag.span.line, diag.span.col, diag.label) == ("TL-P002", 1, 8, "block opened here")


def test_recovery_reports_every_error():
    src = (
        'var = "x"\n'           # missing name
        "input u\n"
        "var y = ( u\n"         # missing `)`, detected at the next `var`
        'var z = "ok"\n'
        "system { insert(u }\n"  # missing `)`
    )
    result = parse(src, "t.tlx")
    assert [(d.code, d.span.line) for d in result.diagnostics] == [
        ("TL-P001", 1), ("TL-P001", 4), ("TL-P001", 5),
    ]
    # Statements between the errors survive.
    assert [type(s).__name__ for s in result.program.statements] == ["InputDecl", "VarDecl", "Block"]


def test_missing_close_brace_does_not_cascade():
    result = parse('system {\n  "a"\nvar x = "b"\n', "t.tlx")
    assert [d.code for d in result.diagnostics] == ["TL-P001", "TL-P002"]
    assert "is a `}` missing" in result.diagnostics.items[0].hint


def test_lexer_and_parser_errors_share_one_bag():
    assert codes("var a = 'x'\nvar k") == ["TL-L001", "TL-L001", "TL-P007"]


def test_parser_is_reusable_after_errors():
    parse("system {", "t.tlx")
    assert ok('var a = "x"').statements[0].name == "a"


# ---- examples ----

@pytest.mark.parametrize("name", ["safe", "injection"])
def test_example_ast_snapshots(name):
    result = parse((ROOT / "examples" / f"{name}.tlx").read_text(), f"{name}.tlx")
    assert result.ok, result.diagnostics.render()
    tree = dump(result.program) + "\n"
    snapshot = SNAPSHOTS / f"{name}.ast"
    if os.environ.get("UPDATE_SNAPSHOTS") or not snapshot.exists():
        snapshot.parent.mkdir(exist_ok=True)
        snapshot.write_text(tree)
    assert tree == snapshot.read_text()


# ---- input types (validated inputs) ----

@pytest.mark.parametrize("src, expected", [
    ('input lang : enum("en", "fr", "ta")', InputType("enum", values=("en", "fr", "ta"))),
    ('input order_id : pattern("[A-Z0-9]{8}")', InputType("pattern", pattern="[A-Z0-9]{8}")),
    ("input qty : int", InputType("int")),
    ("input qty : int(1, 100)", InputType("int", min=1, max=100)),
    ("input t : int(-5, 5)", InputType("int", min=-5, max=5)),
    ('input city from tool : pattern("[A-Za-z]{1,40}")', InputType("pattern", pattern="[A-Za-z]{1,40}")),
    ("input e : enum()", InputType("enum")),  # shape is fine; Module 3 rejects it (TL-S012)
])
def test_typed_input_forms(src, expected):
    [decl] = ok(src).statements
    assert isinstance(decl, InputDecl) and decl.type == expected
    assert decl.trust is (TrustLevel.SEMI_TRUSTED if "from tool" in src else TrustLevel.UNTRUSTED)
    assert decl.type.span.text == src.split(" : ")[1]
    assert decl.span.text == src


def test_typed_input_dump_and_round_trip():
    [decl] = ok('input lang from rag : enum("en", "fr")').statements
    assert dump(decl).startswith('InputDecl lang [SEMI_TRUSTED] from rag : enum("en", "fr") @1:1')
    assert InputType.from_dict(decl.type.to_dict()) == decl.type


@pytest.mark.parametrize("src, message", [
    ("input x : string", "unknown input type `string`"),
    ("input x : int(5, 1)", "empty range int(5, 1)"),
    ("input x : int(5)", "int takes no arguments or a range"),
    ('input x : int("1", "2")', "int takes no arguments or a range"),
    ("input x : enum", "`enum` needs arguments"),
    ("input x : pattern", "`pattern` needs arguments"),
    ("input x : enum(en, fr)", "enum arguments must be string literals, not identifier `en`"),
    ("input x : enum(1)", "enum arguments must be string literals, not number 1"),
    ('input x : enum("{y}")', "enum arguments cannot interpolate variables"),
    ('input x : pattern("a", "b")', "pattern takes exactly one regular expression"),
    ('input x :\nvar y = "a"', "expected an input type after `:`, found `var`"),
])
def test_malformed_input_types(src, message):
    result = parse(src, "test.tlx")
    [diag] = result.diagnostics.items
    assert diag.code == "TL-P009" and diag.message.startswith(message) and diag.hint


def test_parser_recovers_after_a_malformed_type():
    assert codes('input x : string\ninput y : int(3, 1)\nvar z = "ok"') == ["TL-P009", "TL-P009"]


def test_stray_number_has_a_hint():
    [diag] = parse("var x = 5", "test.tlx").diagnostics.items
    assert diag.code == "TL-P001" and "int(1, 100)" in diag.hint


@pytest.mark.parametrize("data", [
    None, [], {"kind": "enum"}, {"kind": "enum", "values": "en"}, {"kind": "enum", "values": [1]},
    {"kind": "pattern", "pattern": 5}, {"kind": "int", "min": 1}, {"kind": "int", "min": 3, "max": 1},
    {"kind": "int", "min": True, "max": 2}, {"kind": "int", "min": None, "max": 4}, {"kind": "regex", "pattern": "a"},
    {"kind": "enum", "values": ["a"], "extra": 1},
])
def test_input_type_from_dict_rejects_malformed_data(data):
    with pytest.raises(ValueError):
        InputType.from_dict(data)
