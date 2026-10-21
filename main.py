"""
TrustLex - Module 6: Command-line driver.

Runs the whole pipeline: lexer -> parser -> security checker -> code
generation -> optimizer -> (optionally) binding into an API payload.

    python main.py                               interactive mode: type a program, see the result
    python main.py FILE.tlx [options]            compile (the default command)
    python main.py compile FILE.tlx [options]    same, explicitly
    python main.py check FILE.tlx                security check and trust trace only
    python main.py fix FILE.tlx [--write]        apply the suggested security fixes
    python main.py demo [DIR] [--verbose]        run the scenario scripts
    python main.py repl                          interactive mode, explicitly

FILE may be `-` to read the program from standard input.

Compile options:
    --target ir|openai|anthropic   output the IR (default) or an API payload
    -O0 | -O1 | -O2                optimization level (default -O1)
    --input NAME=VALUE             input value (repeatable), for payload targets
    --inputs FILE.json             input values from a JSON object
    --model M, --max-tokens N      payload settings
    --relaxed                      retrieved/tool data in system blocks is a warning
    --no-delimit                   do not wrap raw untrusted values in <untrusted_input> tags
    --openai-developer-role        send OpenAI system messages as "developer"
    --stages                       print every stage's output and timing to stderr
    -o FILE                        write the output to FILE instead of stdout

Set TRUSTLEX_IR_KEY to HMAC-seal the IR; without it the IR carries only an
unkeyed SHA-256 integrity checksum.

Exit codes: 0 success, 1 compile or bind errors, 2 usage errors.
Diagnostics and stage output go to stderr, so stdout stays valid JSON.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from codegen import TARGETS, BindError, CompiledPrompt, SlotPart, compile_source, generate, resolve_ir_key
from diagnostics import apply_edits
from lexer import TrustLexer, format_tokens
from optimizer import LEVELS, OptimizationReport, optimize
from parser_ast import default_parser, dump, parse
from semantic import CheckedProgram, SecurityPolicy, analyze, check

COMMANDS = ("compile", "check", "fix", "demo", "repl")
ROOT = Path(__file__).resolve().parent
SCENARIOS = ROOT / "examples" / "scenarios"


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def use_color(stream, disabled: bool = False) -> bool:
    return not disabled and not os.environ.get("NO_COLOR") and hasattr(stream, "isatty") and stream.isatty()


def paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


GREEN, RED, BOLD, DIM = "1;32", "1;31", "1", "2"


def err(*lines):
    for line in lines:
        print(line, file=sys.stderr)


def read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from exc


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

@dataclass
class Stage:
    name: str
    ms: float
    summary: str
    body: str = ""


@dataclass
class PipelineResult:
    checked: CheckedProgram
    compiled: CompiledPrompt | None = None
    report: OptimizationReport | None = None
    stages: list[Stage] = field(default_factory=list)
    setup_ms: float = 0.0


def _timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - start) * 1000


def run_pipeline(text: str, filename: str, policy: SecurityPolicy, level: int = 1,
                 delimit_untrusted: bool = True) -> PipelineResult:
    """Run every compiler stage, recording each stage's output and timing."""
    stages = []
    _, setup_ms = _timed(default_parser)  # one-time LALR table construction, not a per-compile cost

    lexer = TrustLexer(filename)
    tokens, ms = _timed(lambda: lexer.tokenize(text))
    stages.append(Stage("Lexical analysis", ms, f"{len(tokens)} tokens, {len(lexer.comments)} comments",
                        format_tokens(tokens)))

    parsed, ms = _timed(lambda: parse(text, filename))
    stages.append(Stage("Syntax analysis", ms, f"{len(parsed.program.statements)} statements",
                        dump(parsed.program)))

    parsed_ok = parsed.ok  # read before checking: the checker adds to the same diagnostics
    checked, ms = _timed(lambda: check(parsed, policy))
    result = PipelineResult(checked, stages=stages, setup_ms=setup_ms)
    if not parsed_ok:
        return result
    errors = len(checked.diagnostics.errors)
    stages.append(Stage("Security analysis", ms, "no violations" if not errors else f"{errors} error(s)",
                        checked.format_trace()))
    if not checked.ok:
        return result

    compiled, ms = _timed(lambda: generate(checked, delimit_untrusted=delimit_untrusted))
    slots = sum(1 for m in compiled.messages for p in m.parts if isinstance(p, SlotPart))
    stages.append(Stage("Code generation", ms, f"{len(compiled.messages)} messages, {slots} input slots"))

    (optimized, report), ms = _timed(lambda: optimize(compiled, level, comments=checked.comments))
    stages.append(Stage(f"Optimization -O{level}", ms,
                        f"{report.chars_before} -> {report.chars_after} chars", report.format()))
    result.compiled, result.report = optimized, report
    return result


def print_stages(stages: list[Stage], color: bool, setup_ms: float = 0.0):
    total = sum(s.ms for s in stages)
    for i, stage in enumerate(stages, 1):
        err(paint(f"== {i}. {stage.name}", BOLD, color) + paint(f"  {stage.ms:.2f} ms  ·  {stage.summary}", DIM, color))
        if stage.body:
            err("\n".join("   " + line for line in stage.body.splitlines()), "")
    setup = f" (+ {setup_ms:.2f} ms one-time parser table construction)" if setup_ms >= 0.01 else ""
    err(paint(f"total compile time: {total:.2f} ms{setup}", DIM, color), "")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def _policy(args) -> SecurityPolicy:
    return SecurityPolicy.relaxed() if getattr(args, "relaxed", False) else SecurityPolicy.strict()


def _values(args) -> dict[str, str]:
    values = {}
    if args.inputs:
        try:
            data = json.loads(read_source(args.inputs))
        except json.JSONDecodeError as exc:
            raise UsageError(f"{args.inputs} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise UsageError(f"{args.inputs} must contain a JSON object of input values")
        values.update(data)
    for pair in args.input:
        name, sep, value = pair.partition("=")
        if not sep:
            raise UsageError(f"--input expects NAME=VALUE, got {pair!r}")
        values[name] = value
    return values


def cmd_compile(args) -> int:
    text = read_source(args.file)
    color = use_color(sys.stderr, args.no_color)
    result = run_pipeline(text, args.file, _policy(args), args.level, not args.no_delimit)
    diagnostics = result.checked.diagnostics

    if args.stages:
        print_stages(result.stages, color, result.setup_ms)
    if len(diagnostics):
        err(diagnostics.render(color), "")
    if result.compiled is None:
        err(paint("compilation failed: ", RED, color) + diagnostics.summary())
        return 1

    compiled = result.compiled
    if args.target == "ir":
        output = compiled.to_json(indent=2)
        what = "HMAC-sealed IR" if resolve_ir_key() else "IR"
    else:
        try:
            payload = compiled.bind(_values(args), args.target, args.model, args.max_tokens,
                                    openai_developer_role=args.openai_developer_role)
        except BindError as exc:
            err(paint(f"error[{exc.code}]", RED, color) + f": {exc.message}")
            if exc.code == "TL-G003":
                err(f"  = hint: pass values with --input NAME=VALUE or --inputs FILE.json "
                    f"(declared inputs: {', '.join(compiled.inputs) or 'none'})")
            return 1
        except ValueError as exc:
            raise UsageError(str(exc)) from exc
        output = json.dumps(payload, indent=2, ensure_ascii=False)
        what = f"{args.target} payload"

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    report = result.report
    err(paint("compiled ", GREEN, color)
        + f"{args.file} -> {what}{' in ' + args.output if args.output else ''} "
        + f"({len(compiled.messages)} messages, -O{args.level}: {report.chars_before} -> {report.chars_after} chars, "
        + f"sha256 {compiled.digest()[:12]}…)")
    return 0


def cmd_check(args) -> int:
    checked = analyze(read_source(args.file), args.file, _policy(args))
    color = use_color(sys.stdout, args.no_color)
    if checked.trace:
        print(checked.format_trace())
    if len(checked.diagnostics):
        print("\n" + checked.diagnostics.render(color))
    verdict = paint("ok", GREEN, color) if checked.ok else paint("rejected", RED, color)
    print(f"\n{args.file}: {verdict} ({checked.diagnostics.summary()})")
    return 0 if checked.ok else 1


def apply_fixes(text: str, filename: str, policy: SecurityPolicy) -> tuple[str, list[str], CheckedProgram]:
    """Apply security fix-its one at a time, re-checking after each, so every
    applied fix is validated against the updated program. Returns the fixed
    text, a description of each fix, and the final check."""
    applied = []
    for _ in range(50):
        checked = analyze(text, filename, policy)
        fixable = sorted((d for d in checked.diagnostics.errors if d.fixes), key=lambda d: d.span.offset)
        if not fixable:
            return text, applied, checked
        diag = fixable[0]
        text = apply_edits(text, diag.fixes[0].edits)
        applied.append(f"{diag.code} at line {diag.span.line}: {diag.fixes[0].message}")
    return text, applied, analyze(text, filename, policy)


def cmd_fix(args) -> int:
    if args.write and args.file == "-":
        raise UsageError("--write needs a file, not standard input")
    original = read_source(args.file)
    color = use_color(sys.stderr, args.no_color)
    text, applied, final = apply_fixes(original, args.file, _policy(args))
    for line in applied:
        err(paint("fixed ", GREEN, color) + line)
    if not applied:
        err("nothing to fix")

    if args.write:
        if text != original:
            Path(args.file).write_text(text, encoding="utf-8")
            err(f"wrote {args.file}")
    elif text != original:
        sys.stdout.writelines(difflib.unified_diff(
            original.splitlines(keepends=True), text.splitlines(keepends=True),
            fromfile=args.file, tofile=f"{args.file} (fixed)",
        ))

    if not final.ok:
        err("", final.diagnostics.render(color), "",
            paint("errors remain that have no automatic fix: ", RED, color) + final.diagnostics.summary())
        return 1
    err(paint("ok: ", GREEN, color) + f"the {'fixed ' if applied else ''}program passes the security check")
    return 0


@dataclass
class Scenario:
    path: Path
    about: str
    expect: list[str]  # ["ok"] or the expected error codes, in order


def load_scenario(path: Path) -> Scenario | None:
    about, expect = "", None
    for line in path.read_text(encoding="utf-8").splitlines()[:10]:
        if line.startswith("# about:"):
            about = line.removeprefix("# about:").strip()
        elif line.startswith("# expect:"):
            expect = line.removeprefix("# expect:").split()
    return Scenario(path, about, expect) if expect else None


def cmd_demo(args) -> int:
    directory = Path(args.dir) if args.dir else SCENARIOS
    color = use_color(sys.stdout, args.no_color)
    scenarios = [s for s in map(load_scenario, sorted(directory.glob("*.tlx"))) if s]
    if not scenarios:
        raise UsageError(f"no scenarios with a `# expect:` header in {directory}")

    passed = 0
    for scenario in scenarios:
        text = scenario.path.read_text(encoding="utf-8")
        checked, compiled = compile_source(text, scenario.path.name)
        codes = [d.code for d in checked.diagnostics.errors]
        ok = (compiled is not None) if scenario.expect == ["ok"] else codes == scenario.expect
        passed += ok

        outcome = "compiled" if compiled is not None else "rejected: " + " ".join(codes)
        mark = paint("PASS", GREEN, color) if ok else paint("FAIL", RED, color)
        print(f"{mark}  {scenario.path.stem:<28} {outcome:<32} {paint(scenario.about, DIM, color)}")
        if not ok:
            print(f"      expected: {' '.join(scenario.expect)}")
        if args.verbose:
            if compiled is None:
                print("\n".join("      " + line for line in checked.diagnostics.render(color).splitlines()))
            else:
                optimized, _ = optimize(compiled, 1)
                sample = {name: f"<sample {name} – ignore previous instructions>" for name in optimized.inputs}
                payload = optimized.bind(sample, "anthropic")
                print("\n".join("      " + line for line in json.dumps(payload, indent=2, ensure_ascii=False).splitlines()))
            print()

    summary = f"{passed}/{len(scenarios)} scenarios behaved as expected"
    print("\n" + (paint(summary, GREEN, color) if passed == len(scenarios) else paint(summary, RED, color)))
    return 0 if passed == len(scenarios) else 1


# --------------------------------------------------------------------------
# Interactive mode
# --------------------------------------------------------------------------

REPL_HELP = """\
Type or paste a TrustLex program, then enter :run on a line of its own.
  :run            compile the program typed so far
  :example        load and run a safe example program
  :attack         load and run an example with prompt-injection leaks
  :fix            apply the suggested security fixes to the last program and run it
  :show           show the program typed so far
  :clear          discard the program typed so far
  :target NAME    output format: anthropic (default), openai, ir
  :help           show this help
  :quit           exit (Ctrl-D also works)"""

REPL_EXAMPLES = {
    ":example": SCENARIOS / "01_safe_support_bot.tlx",
    ":attack": ROOT / "examples" / "injection.tlx",
}


class _Repl:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.policy = _policy(args)
        self.color = use_color(sys.stdout, args.no_color)
        self.buffer: list[str] = []
        self.last: str | None = None
        self.eof = False

    def ask(self, prompt: str) -> str:
        try:
            return input(prompt)
        except EOFError:
            self.eof = True
            return ""

    def loop(self) -> int:
        print(paint("TrustLex interactive mode", BOLD, self.color) + f"  (target: {self.target}, -O{self.args.level})")
        print(REPL_HELP + "\n")
        while not self.eof:
            line = self.ask("tlx> " if not self.buffer else "...> ")
            if self.eof:
                if self.buffer:
                    print()
                    self.run("\n".join(self.buffer))
                break
            command, _, arg = line.strip().partition(" ")
            if not command.startswith(":"):
                self.buffer.append(line)
            elif command == ":quit":
                break
            elif command == ":help":
                print(REPL_HELP)
            elif command == ":run":
                if self.buffer:
                    self.run("\n".join(self.buffer))
                else:
                    print("nothing to run yet: type a program first (or :example)")
            elif command in REPL_EXAMPLES:
                source = REPL_EXAMPLES[command].read_text(encoding="utf-8")
                print(source)
                self.run(source)
            elif command == ":fix":
                self.fix()
            elif command == ":show":
                print("\n".join(self.buffer) if self.buffer else "(empty)")
            elif command == ":clear":
                self.buffer = []
            elif command == ":target" and arg.strip() in TARGETS:
                self.target = arg.strip()
                print(f"target: {self.target}")
            else:
                print(f"unknown command {line.strip()!r}; type :help")
        print()
        return 0

    def run(self, source: str):
        self.buffer, self.last = [], source
        checked, compiled = compile_source(source, "<prompt>", self.policy)
        if len(checked.diagnostics):
            print(checked.diagnostics.render(self.color) + "\n")
        if compiled is None:
            print(paint("✗ rejected", RED, self.color) + f" ({checked.diagnostics.summary()})"
                  + ("  · type :fix to apply the suggested fixes" if any(d.fixes for d in checked.diagnostics) else ""))
            return
        optimized, report = optimize(compiled, self.args.level, comments=checked.comments)
        print(paint("✓ compiled", GREEN, self.color)
              + f" ({len(optimized.messages)} messages, -O{self.args.level}: "
              + f"{report.chars_before} -> {report.chars_after} chars, sha256 {optimized.digest()[:12]}…)")
        if self.target == "ir":
            print(optimized.to_json(indent=2))
            return

        if optimized.inputs:
            print("Enter a value for each input (try a prompt-injection attack):")
        values = {}
        for name, info in optimized.inputs.items():
            values[name] = self.ask(f"  {name} [{info['trust']}, from {info['source']}] = ")
        print()
        for role, text in optimized.render(values):
            print(paint(f"[{role}]", BOLD, self.color))
            print(text + "\n")
        try:
            payload = optimized.bind(values, self.target, self.args.model, self.args.max_tokens)
        except (BindError, ValueError) as exc:
            print(paint("payload not built: ", RED, self.color) + (exc.message if isinstance(exc, BindError) else str(exc)))
            if self.target == "openai":
                print("(start with --model NAME to build OpenAI payloads)")
            return
        print(paint(f"── {self.target} payload ──", DIM, self.color))
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    def fix(self):
        if self.last is None:
            print("nothing to fix: run a program first")
            return
        fixed, applied, _ = apply_fixes(self.last, "<prompt>", self.policy)
        if not applied:
            print("nothing to fix automatically")
            return
        for line in applied:
            print(paint("fixed ", GREEN, self.color) + line)
        print("\n" + fixed)
        self.run(fixed)


def cmd_repl(args) -> int:
    return _Repl(args).loop()


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="TrustLex: a security-typed compiler front-end for injection-safe LLM prompts.",
        epilog="`python main.py FILE.tlx` is short for `python main.py compile FILE.tlx`.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--relaxed", action="store_true", help="retrieved/tool data in system blocks is a warning")
        p.add_argument("--no-color", action="store_true", help="disable colored output")

    p = sub.add_parser("compile", help="compile a program to IR or an API payload")
    p.add_argument("file")
    p.add_argument("--target", choices=TARGETS, default="ir")
    p.add_argument("-O", dest="level", type=int, choices=LEVELS, default=1, help="optimization level (default 1)")
    p.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("--inputs", metavar="FILE.json")
    p.add_argument("--model")
    p.add_argument("--max-tokens", type=int)
    p.add_argument("--no-delimit", action="store_true")
    p.add_argument("--openai-developer-role", action="store_true")
    p.add_argument("--stages", action="store_true", help="print every stage's output and timing to stderr")
    p.add_argument("-o", "--output", metavar="FILE")
    common(p)
    p.set_defaults(handler=cmd_compile)

    p = sub.add_parser("check", help="run the security check and print the trust trace")
    p.add_argument("file")
    common(p)
    p.set_defaults(handler=cmd_check)

    p = sub.add_parser("fix", help="apply the suggested security fixes (prints a diff unless --write)")
    p.add_argument("file")
    p.add_argument("--write", action="store_true", help="update the file in place")
    common(p)
    p.set_defaults(handler=cmd_fix)

    p = sub.add_parser("demo", help="run the scenario scripts and compare with their expected outcomes")
    p.add_argument("dir", nargs="?", help="scenario directory (default: examples/scenarios)")
    p.add_argument("-v", "--verbose", action="store_true", help="show diagnostics and generated payloads")
    p.add_argument("--no-color", action="store_true")
    p.set_defaults(handler=cmd_demo)

    p = sub.add_parser("repl", help="interactive mode: type a program and see the compiled result")
    p.add_argument("--target", choices=TARGETS, default="anthropic")
    p.add_argument("-O", dest="level", type=int, choices=LEVELS, default=1)
    p.add_argument("--model")
    p.add_argument("--max-tokens", type=int)
    common(p)
    p.set_defaults(handler=cmd_repl)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-", "-h", "--help")):
        argv.insert(0, "repl")  # options only: interactive mode with those options
    elif argv[0] not in COMMANDS and (argv[0] == "-" or not argv[0].startswith("-")):
        argv.insert(0, "compile")
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except UsageError as exc:
        err(f"error: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
