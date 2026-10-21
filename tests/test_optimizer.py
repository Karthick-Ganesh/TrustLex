"""Tests for TrustLex Module 5: whitespace rules, the report, and the formal
properties (slot preservation, whitespace equivalence, idempotence, ...)."""

import os
import re
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from codegen import CompiledPrompt, Message, SlotPart, TextPart, compile_source
import optimizer
from optimizer import estimate_tokens, optimize, select_token_counter, tiktoken_counter
from test_semantic import PAYLOAD, programs, sanitizer as toy_sanitizer

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
INPUTS = {"u": {"trust": "UNTRUSTED", "source": "user"}, "d": {"trust": "SEMI_TRUSTED", "source": "rag"}}
U, D = SlotPart("u", False), SlotPart("d", False)
SU = SlotPart("u", True)


def ir(*messages):
    """Build an IR from (role, parts...) tuples; strings become text parts."""
    return CompiledPrompt("t.tlx", INPUTS, [
        Message(role, "system" if role == "system" else "instruction", i + 1,
                tuple(TextPart(p) if isinstance(p, str) else p for p in parts))
        for i, (role, *parts) in enumerate(messages)
    ])


def parts_after(*parts, level=1, role="user"):
    optimized, _ = optimize(ir((role, *parts)), level)
    [message] = optimized.messages
    return message.parts


def shape(parts):
    """Whitespace-free text runs interleaved with slots (slots as atoms)."""
    out, run = [], ""
    for p in parts:
        if isinstance(p, TextPart):
            run += re.sub(r"\s+", "", p.text)
        else:
            out += [run, (p.input, p.sanitize)]
            run = ""
    return out + [run]


# ---- individual rules ----

def test_normalize_newlines():
    assert parts_after("a\r\nb\rc") == (TextPart("a\nb\nc"),)


def test_strip_trailing_whitespace_but_not_before_a_slot():
    assert parts_after("Rules:   \nQuestion:   ", U, "  \nend") == (
        TextPart("Rules:\nQuestion:   "), U, TextPart("\nend"),
    )


def test_dedent_keeps_relative_indentation():
    assert parts_after("\n    Rules:\n      - be kind\n    Done.\n    ") == (
        TextPart("Rules:\n  - be kind\nDone."),
    )


def test_dedent_ignores_lines_that_start_with_a_slot():
    assert parts_after("\n    a\n    b\n", U, "\n    c") == (TextPart("a\nb\n"), U, TextPart("\nc"))


def test_dedent_counts_indentation_before_a_slot():
    assert parts_after("    a\n    ", U) == (TextPart("a\n"), U)


def test_unindented_line_blocks_dedent_at_o1_not_o2():
    src = "Rules:\n    a\n    b"
    assert parts_after(src) == (TextPart(src),)
    assert parts_after(src, level=2) == (TextPart("Rules:\na\nb"),)


def test_blank_lines():
    assert parts_after("a\n\n\n\nb\n   \n\n c") == (TextPart("a\n\nb\n\n c"),)
    assert parts_after("a\n\n\n\nb", level=2) == (TextPart("a\nb"),)


def test_collapse_inline_spaces_at_o2_only():
    assert parts_after("a   b\t\tc") == (TextPart("a   b\t\tc"),)
    assert parts_after("a   b\t\tc", level=2) == (TextPart("a b c"),)


def test_trim_message_ends_only_where_text():
    assert parts_after("  \n hello \n ") == (TextPart("hello"),)
    assert parts_after(U, "  tail  ") == (U, TextPart("  tail"))


def test_merge_text_and_drop_empty_parts():
    optimized, report = optimize(ir(("user", "a", "", "b", U, "")))
    assert optimized.messages[0].parts == (TextPart("ab"), U)
    assert next(r for r in report.rules if r.name == "merge-text").applications == 3  # 4 text parts -> 1


def test_drop_empty_messages_but_keep_slot_only_ones():
    optimized, report = optimize(ir(("system", "   \n "), ("user", "  ", U, " ")))
    assert [m.role for m in optimized.messages] == ["user"]
    assert optimized.messages[0].parts == (U,)
    assert [m.dropped for m in report.messages] == [True, False]


def test_level_zero_changes_nothing():
    original = ir(("user", "  a  \n\n\n", U))
    optimized, report = optimize(original, 0)
    assert optimized.messages == original.messages and optimized.optimization == 0
    assert report.rules == []


def test_input_is_not_modified():
    original = ir(("user", "  a  "))
    optimize(original, 2)
    assert original.messages[0].parts == (TextPart("  a  "),) and original.optimization == 0


def test_sentinel_never_collides_with_text():
    assert parts_after("x  ", U, " y") == (TextPart("x  "), U, TextPart(" y"))


def test_invalid_level():
    with pytest.raises(ValueError):
        optimize(ir(), 3)


# ---- report ----

def test_safe_example_report():
    checked, compiled = compile_source((ROOT / "examples" / "safe.tlx").read_text(), "safe.tlx")
    optimized, report = optimize(compiled, 1, comments=checked.comments)
    assert (report.chars_before, report.chars_after) == (153, 140)
    saved = {r.name: r.chars_saved for r in report.rules}
    assert saved == {
        "merge-text": 0, "normalize-newlines": 0, "strip-trailing-ws": 4, "dedent": 8,
        "collapse-blank-lines": 0, "trim-message": 1, "drop-empty-messages": 0,
    }
    assert (report.comment_count, report.comment_chars) == (5, 300)
    assert "TOTAL" in report.format() and "-8%" in report.format()
    assert optimized.messages[0].parts[0].text.startswith("You are a billing assistant")


def test_comments_are_reported_but_not_counted_as_savings():
    checked, compiled = compile_source((ROOT / "examples" / "safe.tlx").read_text(), "safe.tlx")
    _, with_comments = optimize(compiled, 1, comments=checked.comments)
    _, without = optimize(compiled, 1)
    text = with_comments.format()
    assert "comments in source (never part of the prompt): 5 (300 chars)" in text
    assert "removed" not in text
    totals = lambda r: (r.chars_before, r.chars_after, r.tokens_before, r.tokens_after)
    assert totals(with_comments) == totals(without)
    assert [r.chars_saved for r in with_comments.rules] == [r.chars_saved for r in without.rules]


def test_estimate_tokenizer_selects_the_builtin_estimate():
    assert select_token_counter("estimate") is None
    _, compiled = compile_source('instruction { "hi there" }', "t.tlx")
    assert "regex pre-tokenizer estimate" in optimize(compiled, 1, select_token_counter("estimate"))[1].format()


def test_tokenizer_falls_back_to_the_estimate_without_tiktoken(monkeypatch):
    monkeypatch.setattr(optimizer, "tiktoken_counter", lambda: None)
    assert select_token_counter() is None
    with pytest.raises(ValueError, match="pip install tiktoken"):
        select_token_counter("tiktoken")
    with pytest.raises(ValueError, match="unknown tokenizer"):
        select_token_counter("bpe")


def test_tiktoken_counter_is_exact_and_used_automatically():
    pytest.importorskip("tiktoken")
    count = tiktoken_counter()
    if count is None:
        pytest.skip("the o200k_base encoding could not be loaded (offline?)")
    assert select_token_counter() is count and select_token_counter("tiktoken") is count
    assert count("hello world") == 2
    assert count("<|endoftext|>") > 1  # special tokens in text are counted as plain text, not rejected
    _, compiled = compile_source('instruction { "hello world" }', "t.tlx")
    _, report = optimize(compiled, 1, count)
    assert report.tokens_after == 2 and "tiktoken o200k_base (exact)" in report.format()


def test_custom_token_counter():
    def words(text):
        return len(text.split())

    _, report = optimize(ir(("user", "  one two  ")), token_counter=words)
    assert report.token_counter == "words"
    assert (report.tokens_before, report.tokens_after) == (2, 2)


def test_token_estimate():
    assert estimate_tokens("") == 0
    assert estimate_tokens("Hello, world!") == 4  # "Hello" "," " world" "!"
    assert estimate_tokens("a\n    b") >= estimate_tokens("a\nb")


def test_optimized_ir_snapshot_and_seal():
    _, compiled = compile_source((ROOT / "examples" / "safe.tlx").read_text(), "safe.tlx")
    optimized, _ = optimize(compiled, 1)
    text = optimized.to_json(indent=2) + "\n"
    snapshot = SNAPSHOTS / "safe.O1.ir.json"
    if os.environ.get("UPDATE_SNAPSHOTS") or not snapshot.exists():
        snapshot.write_text(text)
    assert text == snapshot.read_text()
    loaded = CompiledPrompt.from_json(text)
    assert loaded.optimization == 1 and loaded.digest() == optimized.digest() != compiled.digest()


# ---- formal properties on random IR ----

TEXT = st.text(alphabet="ab.: \t\n\r ", max_size=16)


@st.composite
def random_ir(draw):
    messages = []
    for _ in range(draw(st.integers(0, 4))):
        role = draw(st.sampled_from(["system", "user"]))
        parts = []
        for _ in range(draw(st.integers(0, 6))):
            if draw(st.booleans()):
                parts.append(draw(TEXT))
            else:
                name = draw(st.sampled_from(["u", "d"]))
                parts.append(SlotPart(name, role == "system" or draw(st.booleans())))
        messages.append((role, *parts))
    return ir(*messages)


@settings(max_examples=400, deadline=None)
@given(random_ir(), st.sampled_from([1, 2]))
def test_optimizer_properties(compiled, level):
    optimized, report = optimize(compiled, level)
    kept = iter(optimized.messages)
    for before, stats in zip(compiled.messages, report.messages):
        if stats.dropped:
            # Only slot-free, whitespace-only messages may disappear.
            assert not any(isinstance(p, SlotPart) for p in before.parts)
            assert not "".join(p.text for p in before.parts).strip()
            continue
        after = next(kept)
        assert (after.role, after.line) == (before.role, before.line)
        assert shape(after.parts) == shape(before.parts)  # P1 slots kept + P2 whitespace equivalence
        assert stats.chars_after <= stats.chars_before   # P4 never grows
        assert not any(isinstance(p, TextPart) and not p.text for p in after.parts)
    assert next(kept, None) is None

    again, _ = optimize(optimized, level)                # P3 idempotent
    assert again.messages == optimized.messages

    optimized.verify()                                   # P5 still secure, re-sealable
    assert CompiledPrompt.from_json(optimized.to_json()).digest() == optimized.digest()

    if level == 2:
        o1, _ = optimize(compiled, 1)
        assert sum(len(p.text) for m in optimized.messages for p in m.parts if isinstance(p, TextPart)) <= \
            sum(len(p.text) for m in o1.messages for p in m.parts if isinstance(p, TextPart))


# ---- untrusted values are untouched ----

@pytest.mark.filterwarnings("ignore::codegen.UnsafeSanitizerWarning")  # deliberate toy sanitizer
def test_values_pass_through_byte_for_byte():
    src = 'input u\nsystem { """\n    Rules.\n    """ insert(sanitize(u)) }\ninstruction { "  Q:   " insert(u) }'
    _, compiled = compile_source(src, "t.tlx", delimit_untrusted=False)
    optimized, _ = optimize(compiled, 2)
    value = "  a \n\n\n b  \t"
    rendered = optimized.render({"u": value}, lambda v, n: f"[{v}]", unsafe_sanitizer_override=True)
    # Item separators and indentation are normalized; the values are not.
    assert rendered == [("system", f"Rules.\n[{value}]"), ("user", f"Q:\n{value}")]


@pytest.mark.filterwarnings("ignore::codegen.UnsafeSanitizerWarning")  # deliberate toy sanitizer
@settings(max_examples=300, deadline=None)
@given(programs(), st.sampled_from([0, 1, 2]), st.data())
def test_optimizer_preserves_non_interference_and_content(program, level, data):
    src, inputs = program
    _, compiled = compile_source(src, "t.tlx")
    if compiled is None:
        return
    optimized, _ = optimize(compiled, level)

    sigma1 = {x: data.draw(st.text(alphabet="ab XY!\n", max_size=8)) for x in inputs}
    sigma2 = {x: v + PAYLOAD for x, v in sigma1.items()}

    def render(prompt, sigma):
        return prompt.render(sigma, lambda v, n: toy_sanitizer(v), unsafe_sanitizer_override=True)

    def system_texts(prompt, sigma):
        return [text for role, text in render(prompt, sigma) if role == "system"]

    # P7: non-interference survives optimization.
    assert system_texts(optimized, sigma1) == system_texts(optimized, sigma2), src
    # End to end, the bound prompt is whitespace-equivalent to the unoptimized one.
    def squeezed(prompt):
        return [(role, re.sub(r"\s+", "", text)) for role, text in render(prompt, sigma1)]

    assert squeezed(optimized) == squeezed(compiled)


def test_rules_run_to_a_fixpoint():
    # Found by hypothesis: trim-message removes the leading space that kept
    # dedent from applying, so one pass of the rules is not idempotent.
    once, _ = optimize(ir(("system", " ", SU, "\r\t", SU)))
    assert once.messages[0].parts == (SU, TextPart("\n"), SU)
    assert optimize(once)[0].messages == once.messages


def test_optimizer_cli_tokenizer_flag(capsys, monkeypatch):
    assert optimizer.main(["optimizer.py", str(ROOT / "examples" / "safe.tlx"), "--tokenizer", "estimate"]) == 0
    assert "tokens: ≈ regex pre-tokenizer estimate" in capsys.readouterr().out
    monkeypatch.setattr(optimizer, "tiktoken_counter", lambda: None)
    with pytest.raises(SystemExit) as exc:
        optimizer.main(["optimizer.py", str(ROOT / "examples" / "safe.tlx"), "--tokenizer", "tiktoken"])
    assert exc.value.code == 2 and "pip install tiktoken" in capsys.readouterr().err
