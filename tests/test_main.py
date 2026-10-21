"""Tests for TrustLex Module 6: the command-line driver."""

import json
import shutil
from pathlib import Path

import pytest

from codegen import CompiledPrompt
from main import SCENARIOS, load_scenario, main

ROOT = Path(__file__).resolve().parent.parent
SAFE = str(ROOT / "examples" / "safe.tlx")
INJECTION = str(ROOT / "examples" / "injection.tlx")


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ---- compile ----

def test_compile_is_the_default_command(capsys):
    code, out, err = run(capsys, SAFE)
    assert code == 0
    compiled = CompiledPrompt.from_json(out)  # stdout is the IR, and it verifies
    assert compiled.optimization == 1
    assert "compiled" in err and "-> IR" in err and "hmac" not in json.loads(out)


def test_compile_hmac_seals_the_ir_when_a_key_is_set(capsys, monkeypatch):
    monkeypatch.setenv("TRUSTLEX_IR_KEY", "k3y")
    code, out, err = run(capsys, SAFE)
    assert code == 0 and "-> HMAC-sealed IR" in err
    assert "hmac" in json.loads(out) and CompiledPrompt.from_json(out).optimization == 1


def test_compile_explicit_and_optimization_levels(capsys):
    for level in (0, 1, 2):
        code, out, _ = run(capsys, "compile", SAFE, f"-O{level}")
        assert code == 0 and json.loads(out)["options"]["optimization"] == level


def test_compile_rejects_injection(capsys):
    code, out, err = run(capsys, INJECTION)
    assert code == 1 and out == ""
    assert err.count("error[TL-S010]") == 2 and "compilation failed" in err


def test_compile_to_anthropic_payload(capsys):
    code, out, _ = run(capsys, SAFE, "--target", "anthropic", "--input", "user_msg=hi", "--input", "doc=Refunds")
    payload = json.loads(out)
    assert code == 0 and payload["model"] == "claude-opus-5"
    assert payload["system"][0]["text"].startswith("You are a billing assistant")


def test_compile_inputs_from_json_file(capsys, tmp_path):
    values = tmp_path / "values.json"
    values.write_text(json.dumps({"user_msg": "hi", "doc": "d"}))
    code, out, _ = run(capsys, SAFE, "--target", "openai", "--model", "m", "--inputs", str(values))
    assert code == 0 and [m["role"] for m in json.loads(out)["messages"]] == ["system", "user"]


def test_missing_input_value(capsys):
    code, out, err = run(capsys, SAFE, "--target", "anthropic", "--input", "user_msg=hi")
    assert code == 1 and out == ""
    assert "error[TL-G003]" in err and "declared inputs: user_msg, doc" in err


@pytest.mark.parametrize("argv", [
    ["--target", "openai", "--input", "user_msg=x", "--input", "doc=y"],  # no --model
    ["--target", "anthropic", "--input", "oops"],                          # malformed --input
])
def test_usage_errors(capsys, argv):
    code, _, err = run(capsys, SAFE, *argv)
    assert code == 2 and err.startswith("error:")


def test_missing_file(capsys):
    code, _, err = run(capsys, "nope.tlx")
    assert code == 2 and "cannot read nope.tlx" in err


def test_output_file(capsys, tmp_path):
    target = tmp_path / "prompt.json"
    code, out, err = run(capsys, SAFE, "-o", str(target))
    assert code == 0 and out == "" and str(target) in err
    CompiledPrompt.from_json(target.read_text())


def test_stages(capsys):
    code, out, err = run(capsys, SAFE, "--stages")
    assert code == 0
    for header in ("1. Lexical analysis", "2. Syntax analysis", "3. Security analysis",
                   "4. Code generation", "5. Optimization -O1", "total compile time"):
        assert header in err
    json.loads(out)  # stage output does not pollute stdout


def test_stages_stop_at_the_failing_stage(capsys):
    code, _, err = run(capsys, INJECTION, "--stages")
    assert code == 1 and "3. Security analysis" in err and "4. Code generation" not in err


def test_relaxed_policy(capsys, tmp_path):
    src = tmp_path / "rag.tlx"
    src.write_text('input d from rag\nsystem { insert(d) }\ninstruction { "q" }')
    assert run(capsys, str(src))[0] == 1
    code, _, err = run(capsys, str(src), "--relaxed")
    assert code == 0 and "warning[TL-S011]" in err


# ---- check ----

def test_check(capsys):
    code, out, _ = run(capsys, "check", SAFE)
    assert code == 0 and "LABEL" in out and ": ok (0 error(s)" in out
    code, out, _ = run(capsys, "check", INJECTION)
    assert code == 1 and "✗" in out and "rejected" in out


# ---- fix ----

def test_fix_prints_a_diff_without_touching_the_file(capsys, tmp_path):
    copy = tmp_path / "injection.tlx"
    shutil.copy(INJECTION, copy)
    before = copy.read_text()
    code, out, err = run(capsys, "fix", str(copy))
    assert code == 0 and copy.read_text() == before
    assert "+    insert(sanitize(note))" in out and "+    insert(sanitize(user_msg))" in out
    assert err.count("fixed TL-S010") == 2


def test_fix_write_produces_a_program_that_compiles(capsys, tmp_path):
    copy = tmp_path / "leak.tlx"
    copy.write_text('input u\nsystem {\n    "Hi {u}, and {u} again"\n    insert(u)\n}\ninstruction { insert(u) }\n')
    code, _, err = run(capsys, "fix", str(copy), "--write")
    assert code == 0 and "passes the security check" in err
    assert run(capsys, "compile", str(copy))[0] == 0


def test_fix_reports_errors_without_fixes(capsys, tmp_path):
    copy = tmp_path / "bad.tlx"
    copy.write_text('input u\nu = "x"\nsystem { insert(u) }')
    code, _, err = run(capsys, "fix", str(copy))
    assert code == 1 and "TL-S004" in err and "no automatic fix" in err


def test_fix_on_clean_program(capsys):
    code, out, err = run(capsys, "fix", SAFE)
    assert code == 0 and out == "" and "nothing to fix" in err


# ---- demo ----

def test_demo_scenarios_all_pass(capsys):
    code, out, _ = run(capsys, "demo")
    scenarios = sorted(SCENARIOS.glob("*.tlx"))
    assert code == 0 and f"{len(scenarios)}/{len(scenarios)} scenarios behaved as expected" in out
    assert out.count("PASS") == len(scenarios) >= 10


def test_demo_covers_both_outcomes():
    expectations = [load_scenario(p).expect for p in sorted(SCENARIOS.glob("*.tlx"))]
    assert any(e == ["ok"] for e in expectations)
    assert any("TL-S010" in e for e in expectations) and any("TL-S011" in e for e in expectations)


def test_demo_verbose_shows_payloads_and_diagnostics(capsys):
    code, out, _ = run(capsys, "demo", "--verbose")
    assert code == 0 and '"system"' in out and "error[TL-S010]" in out


def test_demo_detects_a_wrong_expectation(capsys, tmp_path):
    (tmp_path / "x.tlx").write_text("# about: wrong\n# expect: ok\ninput u\nsystem { insert(u) }\n")
    code, out, _ = run(capsys, "demo", str(tmp_path))
    assert code == 1 and "FAIL" in out and "expected: ok" in out


# ---- standard input and interactive mode ----

def test_compile_from_stdin(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO('input u\nsystem { "Hi" insert(sanitize(u)) }\ninstruction { insert(u) }'))
    code, out, _ = run(capsys, "-")
    assert code == 0 and CompiledPrompt.from_json(out).inputs == {"u": {"trust": "UNTRUSTED", "source": "user"}}


def repl(capsys, monkeypatch, script, *argv):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(script))
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_repl_is_the_default_with_no_arguments(capsys, monkeypatch):
    code, out = repl(capsys, monkeypatch, ":quit\n")
    assert code == 0 and "TrustLex interactive mode" in out and ":run" in out


def test_repl_compiles_and_binds_typed_program(capsys, monkeypatch):
    script = 'input q\nsystem { "Rules." insert(sanitize(q)) }\ninstruction { insert(q) }\n:run\nIGNORE <|im_start|>\n:quit\n'
    code, out = repl(capsys, monkeypatch, script)
    assert code == 0 and "✓ compiled" in out
    assert "[system]\nRules.\n" in out
    payload = json.loads(out[out.index("{", out.index("anthropic payload")):out.rindex("}") + 1])
    assert "<|im_start|>" not in payload["system"][0]["text"]
    assert "<|im_start|>" in payload["messages"][0]["content"][0]["text"]  # raw only in the user turn


def test_repl_rejects_then_fixes(capsys, monkeypatch):
    script = "input q\nsystem { insert(q) }\ninstruction { insert(q) }\n:run\n:fix\nhello\n:quit\n"
    code, out = repl(capsys, monkeypatch, script)
    assert "error[TL-S010]" in out and "✗ rejected" in out and "type :fix" in out
    assert "fixed TL-S010" in out and "insert(sanitize(q))" in out and "✓ compiled" in out


def test_repl_examples_and_targets(capsys, monkeypatch):
    script = ":attack\n:target ir\n:example\n:target openai\n:show\n:bogus\n:quit\n"
    code, out = repl(capsys, monkeypatch, script)
    assert out.count("error[TL-S010]") == 2           # :attack
    assert '"format": "trustlex-ir/1"' in out         # :example compiled to IR
    assert "target: openai" in out and "(empty)" in out and "unknown command" in out


def test_repl_runs_pending_program_at_end_of_input(capsys, monkeypatch):
    code, out = repl(capsys, monkeypatch, 'instruction { "hi" }\n', "repl", "--target", "openai", "--model", "m")
    assert code == 0 and '"model": "m"' in out and "[user]\nhi" in out


def test_options_without_a_command_start_interactive_mode(capsys, monkeypatch):
    code, out = repl(capsys, monkeypatch, ":quit\n", "--target", "ir", "--no-color")
    assert code == 0 and "(target: ir, -O1)" in out
