"""Tests for TrustLex Module 1: lexical analysis and trust seeding."""

from pathlib import Path

import pytest

from lexer import HolePart, Origin, TextPart, TrustLevel, TrustLexer, format_tokens

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def lex(src):
    lexer = TrustLexer("test.tlx")
    return lexer, lexer.tokenize(src)


def types(tokens):
    return [t.type for t in tokens]


def codes(lexer):
    return [d.code for d in lexer.diagnostics]


# ---- token classes ----

def test_keywords_and_identifiers():
    _, toks = lex("system instruction var input insert sanitize from systemX _x1 inputs")
    assert types(toks) == [
        "SYSTEM", "INSTRUCTION", "VAR", "INPUT", "INSERT", "SANITIZE", "FROM",
        "IDENT", "IDENT", "IDENT",
    ]


def test_punctuation():
    _, toks = lex("{ } ( ) = + ;")
    assert types(toks) == ["LBRACE", "RBRACE", "LPAREN", "RPAREN", "EQUALS", "PLUS", "SEMI"]


def test_comments_are_skipped_but_recorded():
    lexer, toks = lex('# line\nvar /* inline */ x /* multi\nline */ = "v"')
    assert types(toks) == ["VAR", "IDENT", "EQUALS", "STRING"]
    assert [c.block for c in lexer.comments] == [False, True, True]
    assert lexer.comments[2].span.end_line == 3


# ---- positions ----

def test_line_and_column_tracking():
    src = 'var a = "x"\n\tinput b # note\n/* multi\nline */ insert(b)\n'
    _, toks = lex(src)
    loc = [(t.type, t.span.line, t.span.col) for t in toks]
    assert ("INPUT", 2, 2) in loc  # a tab counts as one column
    assert ("IDENT", 2, 8) in loc
    assert loc[-4:] == [("INSERT", 4, 9), ("LPAREN", 4, 15), ("IDENT", 4, 16), ("RPAREN", 4, 17)]


def test_triple_quoted_string_spans_lines():
    _, toks = lex('var t = """a\nb\nc"""\ninput z')
    string = toks[3]
    assert string.value.triple
    assert string.value.text == "a\nb\nc"
    assert (string.span.line, string.span.end_line, string.span.end_col) == (1, 3, 5)
    assert (toks[4].type, toks[4].span.line, toks[4].span.col) == ("INPUT", 4, 1)
    assert toks[4].lineno == 4


def test_empty_strings():
    _, toks = lex('"" """"""')
    assert [t.value.text for t in toks] == ["", ""]
    assert [t.value.triple for t in toks] == [False, True]


# ---- string decoding ----

def test_escapes():
    _, toks = lex(r'"a\nb\t\"q\" \\ \{x\}"')
    value = toks[0].value
    assert value.is_plain
    assert value.text == 'a\nb\t"q" \\ {x}'


def test_line_continuation():
    _, toks = lex('"one \\\ntwo"')
    assert toks[0].value.text == "one two"


def test_interpolation_parts_and_spans():
    _, toks = lex('"Hi {name}, {{literal}} {other}!"')
    parts = toks[0].value.parts
    assert [type(p) for p in parts] == [TextPart, HolePart, TextPart, HolePart, TextPart]
    assert [p.text if isinstance(p, TextPart) else p.name for p in parts] == [
        "Hi ", "name", ", {literal} ", "other", "!",
    ]
    name = parts[1]
    assert (name.span.col, name.span.end_col) == (5, 11)
    assert [h.name for h in toks[0].value.holes] == ["name", "other"]
    assert toks[0].value.display() == "Hi {name}, {{literal}} {other}!"


def test_interpolation_inside_triple_string():
    _, toks = lex('"""\n  {rules}\n"""')
    hole = toks[0].value.holes[0]
    assert (hole.name, hole.span.line, hole.span.col) == ("rules", 2, 3)


# ---- trust seeding ----

SEED_SRC = """\
var a = "lit"
input u
input d from rag
input t from tool
input x from user
input w from web
a = u
"""


def test_trust_seeding():
    lexer, toks = lex(SEED_SRC)
    idents = [(t.value, t.provenance) for t in toks if t.type in ("IDENT", "STRING")]

    def prov(i):
        return idents[i][1]

    assert (prov(0).trust, prov(0).origin) == (None, Origin.VAR_DECL)                 # a: decided by Module 3
    assert (prov(1).trust, prov(1).origin) == (TrustLevel.TRUSTED, Origin.LITERAL)    # "lit"
    assert (prov(2).trust, prov(2).origin) == (TrustLevel.UNTRUSTED, Origin.INPUT_DECL)  # u
    assert (prov(3).trust, prov(3).source_tag) == (TrustLevel.SEMI_TRUSTED, "rag")    # d
    assert prov(4).origin is Origin.SOURCE_TAG                                        # rag
    assert (prov(5).trust, prov(5).source_tag) == (TrustLevel.SEMI_TRUSTED, "tool")   # t
    assert (prov(7).trust, prov(7).source_tag) == (TrustLevel.UNTRUSTED, "user")      # x
    assert (prov(9).trust, prov(9).source_tag) == (TrustLevel.UNTRUSTED, "web")       # w: fail closed

    a_ref, u_ref = prov(11), prov(12)
    assert (a_ref.trust, a_ref.origin) == (None, Origin.REFERENCE)
    assert (u_ref.trust, u_ref.origin) == (None, Origin.REFERENCE)

    assert list(lexer.declarations) == ["a", "u", "d", "t", "x", "w"]
    assert lexer.declarations["d"][0].trust is TrustLevel.SEMI_TRUSTED


def test_var_declared_from_an_input_is_not_seeded_trusted():
    lexer, toks = lex("input user_msg\nvar x = user_msg")
    x = next(t for t in toks if t.value == "x")
    assert x.provenance.trust is None and x.provenance.origin is Origin.VAR_DECL
    row = next(line for line in format_tokens(toks).splitlines() if line.endswith(" x"))
    assert row.split()[1:4] == ["IDENT", "-", "var-decl"]


def test_redeclarations_are_all_recorded():
    lexer, _ = lex('var a = "1"\nvar a = "2"')
    assert [p.span.line for p in lexer.declarations["a"]] == [1, 2]


def test_trust_lattice():
    T, S, U = TrustLevel.TRUSTED, TrustLevel.SEMI_TRUSTED, TrustLevel.UNTRUSTED
    assert T.join(U) is U and S.join(T) is S and U.join(S) is U
    assert T.meet(U) is T and S.meet(U) is S
    assert T.leq(S) and S.leq(U) and T.leq(U)
    assert not U.leq(S) and not S.leq(T)
    assert TrustLevel.bottom() is T and TrustLevel.top() is U


def test_lexer_is_reusable():
    lexer = TrustLexer("test.tlx")
    lexer.tokenize("input a $")
    toks = lexer.tokenize("var b")
    assert types(toks) == ["VAR", "IDENT"]
    assert list(lexer.declarations) == ["b"]


# ---- errors and recovery ----

def test_error_recovery_reports_every_error():
    src = (
        'var a = "ok" $$\n'
        'var c = "unterminated\n'
        'var d = "bad \\q escape"\n'
        "input e @\n"
        "/* never closed\n"
    )
    lexer, toks = lex(src)
    assert codes(lexer) == ["TL-L001", "TL-L002", "TL-L004", "TL-L001", "TL-L003"]
    assert [d.span.line for d in lexer.diagnostics] == [1, 2, 3, 4, 5]
    assert lexer.diagnostics.items[0].message == "illegal characters '$$'"
    # Lexing resumes after each error.
    assert types(toks)[-2:] == ["INPUT", "IDENT"]
    assert toks[-1].trust is TrustLevel.UNTRUSTED


def test_single_quote_hint():
    lexer, _ = lex("var a = 'x'")
    assert "double quotes" in lexer.diagnostics.items[0].hint


@pytest.mark.parametrize("src, expected", [
    ('"{1abc}"', ["TL-L005"]),
    ('"{}"', ["TL-L005"]),
    ('"{system}"', ["TL-L006"]),
    ('"{open"', ["TL-L005"]),
    ('"close}"', ["TL-L005"]),
    ('"{{ok}} {fine}"', []),
])
def test_interpolation_errors(src, expected):
    lexer, toks = lex(src)
    assert codes(lexer) == expected
    assert types(toks) == ["STRING"]


def test_bad_interpolation_is_kept_as_text():
    _, toks = lex('"{system}"')
    assert toks[0].value.is_plain
    assert toks[0].value.text == "{system}"


def test_render_snapshot():
    lexer, _ = lex('var c = "oops\n')
    assert lexer.diagnostics.render() == (
        "error[TL-L002]: unterminated string literal\n"
        " --> test.tlx:1:9\n"
        "  |\n"
        '1 | var c = "oops\n'
        "  |         ^~~~~ string starts here\n"
        '  = hint: close the string with a matching `"` on the same line, '
        'or use """...""" for multi-line text'
    )


def test_render_aligns_caret_after_tabs():
    lexer, _ = lex("\tinput u $")
    rendered = lexer.diagnostics.render().splitlines()
    code_line, caret_line = rendered[3], rendered[4]
    assert code_line.index("$") == caret_line.index("^")


# ---- examples ----

@pytest.mark.parametrize("name", ["safe.tlx", "injection.tlx"])
def test_examples_lex_cleanly(name):
    lexer = TrustLexer(name)
    toks = lexer.tokenize((EXAMPLES / name).read_text())
    assert not lexer.diagnostics.has_errors
    assert toks


def test_lex_errors_example():
    lexer = TrustLexer("lex_errors.tlx")
    lexer.tokenize((EXAMPLES / "lex_errors.tlx").read_text())
    assert codes(lexer) == [
        "TL-L001", "TL-L001", "TL-L004", "TL-L002", "TL-L005", "TL-L006", "TL-L001", "TL-L003",
    ]
