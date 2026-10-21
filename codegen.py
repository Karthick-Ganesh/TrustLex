"""
TrustLex - Module 4: Code Generation.

Lowers a checked program to a sealed intermediate representation (IR) and,
at runtime, binds input values into provider-ready API payloads:

    CheckedProgram --generate()--> CompiledPrompt (IR) --bind(values, target)--> payload

Compile time and run time are split because input values do not exist when
the prompt is compiled. The IR keeps literal text and input slots as separate
parts, never as placeholder strings, so binding cannot be confused by values
or literals that look like placeholders, and values enter the payload as JSON
data rather than through string templating.

Security is enforced again at both stages (defence in depth):
  * generate() re-checks its own output: every slot in a system message must
    be sanitized, so a checker bug cannot silently emit a leaking prompt;
  * the IR is sealed with a SHA-256 digest of its canonical form, and
    CompiledPrompt.from_json() / bind() refuse a tampered or non-compliant IR.

What sanitize() does at runtime is pluggable. The compiler guarantees that
raw input never reaches a system message without passing through the
sanitizer; how much protection that sanitizer gives is a separate concern.
The default (trustlex-default/1) normalizes Unicode, strips control and
invisible characters, defuses chat-template role markers, caps the length and
spotlights the value inside <untrusted_input> delimiters (Hines et al., 2024).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field

from diagnostics import DiagnosticBag
from parser_ast import BlockKind
from semantic import CheckedProgram, SecurityPolicy, Slot, Text, analyze

FORMAT = "trustlex-ir/1"
TARGETS = ("ir", "openai", "anthropic")
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"
DEFAULT_ANTHROPIC_MAX_TOKENS = 16000
ITEM_SEPARATOR = "\n"


class CodegenError(Exception):
    """Raised when code cannot (or must not) be generated."""


class BindError(Exception):
    """Raised at runtime when an IR cannot be bound safely."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Runtime sanitizer
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SanitizerConfig:
    name: str = "trustlex-default/1"
    max_length: int = 4000

    def to_dict(self) -> dict:
        return {"name": self.name, "max_length": self.max_length}


_KEEP_CONTROLS = {"\n", "\t"}
_ROLE_TOKENS = re.compile(r"<\|[^|<>]{0,32}\|>|\[/?INST\]|<</?SYS>>", re.IGNORECASE)
_TRANSCRIPT_TURN = re.compile(r"(^|\n)([ \t]*)(human|assistant|system|user)([ \t]*:)", re.IGNORECASE)
_DELIMITER = re.compile(r"<(\s*/?\s*untrusted_input)", re.IGNORECASE)
_TRUNCATED = "…[truncated]"


def _strip_once(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    # Control characters (Cc) other than newline/tab, and invisible format
    # characters (Cf): zero-width spaces/joiners, bidi overrides, BOM.
    value = "".join(
        c for c in value
        if c in _KEEP_CONTROLS or unicodedata.category(c) not in ("Cc", "Cf")
    )
    return _ROLE_TOKENS.sub("", value)


def clean(value: str, max_length: int = 4000) -> str:
    """The cleaning steps of the default sanitizer.

    Deleting a role marker can splice its neighbours into a new one
    ("<|im_<|x|>start|>" -> "<|im_start|>") or into a sequence NFKC would
    still change, so the strip steps run until nothing changes. After the
    first pass, a pass can only change the value if the previous one deleted
    something, so the loop is bounded by the length; the fallback after it is
    unreachable in practice and only keeps the guarantee (no role marker in
    the output) unconditional.
    """
    value = _strip_once(value)
    for _ in range(len(value) + 1):
        stripped = _strip_once(value)
        if stripped == value:
            break
        value = stripped
    else:  # pragma: no cover - see docstring
        value = value.replace("<", "").replace("[", "")
    value = _TRANSCRIPT_TURN.sub(lambda m: f"{m[1]}{m[2]}> {m[3]}{m[4]}", value)
    if len(value) > max_length:
        value = value[: max(max_length - len(_TRUNCATED), 0)] + _TRUNCATED
    return value


def spotlight(value: str, name: str, source: str) -> str:
    """Wrap a value in delimiters it cannot close early."""
    value = _DELIMITER.sub(r"&lt;\1", value)
    return f'<untrusted_input name="{name}" source="{source}">{value}</untrusted_input>'


def default_sanitizer(config: SanitizerConfig, inputs: dict[str, dict]):
    def sanitize(value: str, name: str) -> str:
        return spotlight(clean(value, config.max_length), name, inputs[name]["source"])
    return sanitize


# --------------------------------------------------------------------------
# IR
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TextPart:
    text: str

    def to_dict(self) -> dict:
        return {"text": self.text}


@dataclass(frozen=True)
class SlotPart:
    input: str
    sanitize: bool

    def to_dict(self) -> dict:
        return {"slot": self.input, "sanitize": self.sanitize}


@dataclass(frozen=True)
class Message:
    role: str  # "system" | "user"
    block: str  # source block kind
    line: int
    parts: tuple[TextPart | SlotPart, ...]

    def to_dict(self) -> dict:
        return {"role": self.role, "block": self.block, "line": self.line,
                "parts": [p.to_dict() for p in self.parts]}


_ROLE_OF = {BlockKind.SYSTEM: "system", BlockKind.INSTRUCTION: "user"}


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class CompiledPrompt:
    source: str
    inputs: dict[str, dict]  # name -> {"trust": ..., "source": ...}
    messages: list[Message]
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    delimit_untrusted: bool = True
    optimization: int = 0  # optimizer level applied to the text parts (Module 5)
    policy: str = "strict"  # "relaxed" admits unsanitized SEMI_TRUSTED slots in system messages

    # ---- serialization ----

    def _body(self) -> dict:
        return {
            "format": FORMAT,
            "source": self.source,
            "inputs": self.inputs,
            "messages": [m.to_dict() for m in self.messages],
            "options": {"delimit_untrusted": self.delimit_untrusted, "optimization": self.optimization,
                        "policy": self.policy},
            "sanitizer": self.sanitizer.to_dict(),
        }

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self._body()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {**self._body(), "sha256": self.digest()}

    def to_json(self, indent: int | None = None) -> str:
        if indent is None:
            return _canonical(self.to_dict())
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> CompiledPrompt:
        """Load an IR, verifying its seal and the security invariant."""
        try:
            data = json.loads(text)
            if data.get("format") != FORMAT:
                raise BindError("TL-G005", f"unsupported IR format {data.get('format')!r}")
            compiled = cls(
                source=data["source"],
                inputs=data["inputs"],
                messages=[
                    Message(m["role"], m["block"], m["line"], tuple(
                        TextPart(p["text"]) if "text" in p else SlotPart(p["slot"], bool(p["sanitize"]))
                        for p in m["parts"]
                    ))
                    for m in data["messages"]
                ],
                sanitizer=SanitizerConfig(**data["sanitizer"]),
                delimit_untrusted=data["options"]["delimit_untrusted"],
                optimization=data["options"]["optimization"],
                policy=data["options"]["policy"],
            )
            expected = data["sha256"]
        except BindError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise BindError("TL-G005", f"malformed IR: {exc}") from exc
        if compiled.digest() != expected:
            raise BindError("TL-G005", "IR integrity check failed: the sha256 seal does not match its contents")
        compiled.verify()
        return compiled

    # ---- invariant ----

    def verify(self):
        """Every slot must name a declared input, and every slot in a system
        message must be sanitized. Under the relaxed policy (recorded in the
        sealed IR) a SEMI_TRUSTED slot may be unsanitized; UNTRUSTED never."""
        if self.policy not in ("strict", "relaxed"):
            raise BindError("TL-G005", f"unknown policy {self.policy!r} in IR")
        for m in self.messages:
            if m.role not in ("system", "user"):
                raise BindError("TL-G005", f"unknown role {m.role!r} in IR")
            for p in m.parts:
                if isinstance(p, SlotPart):
                    if p.input not in self.inputs:
                        raise BindError("TL-G005", f"slot `{p.input}` does not name a declared input")
                    exempt = self.policy == "relaxed" and self.inputs[p.input]["trust"] == "SEMI_TRUSTED"
                    if m.role == "system" and not p.sanitize and not exempt:
                        raise BindError(
                            "TL-G005",
                            f"IR violates the security invariant: unsanitized input `{p.input}` "
                            f"in the system message from line {m.line}",
                        )

    # ---- runtime binding ----

    def render(self, values: dict[str, str], sanitizer=None) -> list[tuple[str, str]]:
        """Fill the slots; return (role, text) pairs, skipping empty messages.
        `sanitizer(value, input_name) -> str` defaults to the IR's configured one."""
        self.verify()
        missing = [n for n in self.inputs if n not in values]
        if missing:
            raise BindError("TL-G003", "no value supplied for input(s): " + ", ".join(f"`{n}`" for n in missing))
        unknown = [n for n in values if n not in self.inputs]
        if unknown:
            raise BindError("TL-G004", "value(s) supplied for undeclared input(s): " + ", ".join(f"`{n}`" for n in unknown))
        for name, value in values.items():
            if not isinstance(value, str):
                raise BindError("TL-G003", f"the value of input `{name}` must be a string, not {type(value).__name__}")

        sanitize = sanitizer or default_sanitizer(self.sanitizer, self.inputs)
        rendered = []
        for m in self.messages:
            chunks = []
            for p in m.parts:
                if isinstance(p, TextPart):
                    chunks.append(p.text)
                elif p.sanitize:
                    chunks.append(sanitize(values[p.input], p.input))
                elif self.delimit_untrusted:
                    chunks.append(spotlight(values[p.input], p.input, self.inputs[p.input]["source"]))
                else:
                    chunks.append(values[p.input])
            text = "".join(chunks)
            if text.strip():
                rendered.append((m.role, text))
        return rendered

    def bind(self, values: dict[str, str], target: str, model: str | None = None,
             max_tokens: int | None = None, sanitizer=None, openai_developer_role: bool = False) -> dict:
        """Build an API request body for `target` ("openai" or "anthropic")."""
        rendered = self.render(values, sanitizer)
        if target == "openai":
            if not model:
                raise ValueError("the openai target requires a model name")
            system_role = "developer" if openai_developer_role else "system"
            payload = {
                "model": model,
                "messages": [
                    {"role": system_role if role == "system" else role, "content": text}
                    for role, text in rendered
                ],
            }
            if max_tokens is not None:
                payload["max_completion_tokens"] = max_tokens
            return payload
        if target == "anthropic":
            system = [{"type": "text", "text": text} for role, text in rendered if role == "system"]
            user = [{"type": "text", "text": text} for role, text in rendered if role == "user"]
            if not user:
                raise BindError("TL-G002", "the Anthropic Messages API needs at least one user message (an `instruction` block)")
            payload = {
                "model": model or DEFAULT_ANTHROPIC_MODEL,
                "max_tokens": max_tokens or DEFAULT_ANTHROPIC_MAX_TOKENS,
                "messages": [{"role": "user", "content": user}],
            }
            if system:
                payload["system"] = system
            return payload
        raise ValueError(f"unknown target {target!r}; expected one of: openai, anthropic")


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def generate(checked: CheckedProgram, sanitizer: SanitizerConfig | None = None,
             delimit_untrusted: bool = True) -> CompiledPrompt:
    """Lower a checked program to IR. Adds TL-G001/TL-G002 warnings to the
    program's diagnostics; refuses programs with errors."""
    if not checked.ok:
        raise CodegenError("cannot generate code for a program with errors")

    inputs = {
        sym.name: {"trust": sym.trust.name, "source": sym.source_tag or "user"}
        for sym in checked.symbols.values() if sym.kind == "input"
    }

    messages = []
    for cb in checked.blocks:
        parts = []
        for piece in cb.template(ITEM_SEPARATOR).pieces:
            if isinstance(piece, Text):
                parts.append(TextPart(piece.text))
            else:
                assert isinstance(piece, Slot)
                parts.append(SlotPart(piece.input, piece.sanitized))
        if parts:
            messages.append(Message(_ROLE_OF[cb.kind], cb.kind.value, cb.block.span.line, tuple(parts)))

    compiled = CompiledPrompt(checked.source.name, inputs, messages,
                              sanitizer or SanitizerConfig(), delimit_untrusted, policy=checked.policy.name)
    try:
        compiled.verify()
    except BindError as exc:  # pragma: no cover - would mean a checker bug
        raise CodegenError(f"internal error: generated IR failed verification ({exc.message})") from exc

    _warn_provider_mismatches(checked)
    return compiled


def _warn_provider_mismatches(checked: CheckedProgram):
    diagnostics: DiagnosticBag = checked.diagnostics
    seen_instruction = False
    for cb in checked.blocks:
        if cb.kind is BlockKind.INSTRUCTION:
            seen_instruction = True
        elif seen_instruction:
            diagnostics.warning(
                "TL-G001", "system block after an instruction block", cb.block.keyword_span,
                hint="Anthropic payloads send all system text first, so this block is moved ahead of the user turn",
            )
    if checked.blocks and not any(cb.kind is BlockKind.INSTRUCTION for cb in checked.blocks):
        first = checked.blocks[0].block
        diagnostics.warning(
            "TL-G002", "program has no instruction block", first.keyword_span,
            hint="the Anthropic Messages API needs a user message; binding for the anthropic target will fail",
        )


def compile_source(text: str, filename: str = "<input>", policy: SecurityPolicy | None = None,
                   sanitizer: SanitizerConfig | None = None, delimit_untrusted: bool = True):
    """Lex, parse, check and generate. Returns (checked, compiled or None)."""
    checked = analyze(text, filename, policy)
    if not checked.ok:
        return checked, None
    return checked, generate(checked, sanitizer, delimit_untrusted)


# --------------------------------------------------------------------------
# Debug entry point
# --------------------------------------------------------------------------

def _read_values(args) -> dict[str, str]:
    values = {}
    if args.inputs:
        with open(args.inputs, encoding="utf-8") as f:
            values.update(json.load(f))
    for pair in args.input:
        name, sep, value = pair.partition("=")
        if not sep:
            raise SystemExit(f"--input expects NAME=VALUE, got {pair!r}")
        values[name] = value
    return values


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="codegen.py", description="Compile a TrustLex program to IR or an API payload.")
    parser.add_argument("file")
    parser.add_argument("--target", choices=TARGETS, default="ir")
    parser.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--inputs", metavar="FILE.json")
    parser.add_argument("--model")
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--relaxed", action="store_true")
    parser.add_argument("--no-delimit", action="store_true")
    parser.add_argument("--openai-developer-role", action="store_true")
    args = parser.parse_args(argv[1:])

    with open(args.file, encoding="utf-8") as f:
        text = f.read()
    policy = SecurityPolicy.relaxed() if args.relaxed else SecurityPolicy.strict()
    checked, compiled = compile_source(text, args.file, policy, delimit_untrusted=not args.no_delimit)
    if len(checked.diagnostics):
        print(checked.diagnostics.render(color=sys.stderr.isatty()) + "\n", file=sys.stderr)
    if compiled is None:
        print(checked.diagnostics.summary(), file=sys.stderr)
        return 1

    if args.target == "ir":
        print(compiled.to_json(indent=2))
        return 0
    try:
        payload = compiled.bind(_read_values(args), args.target, args.model, args.max_tokens,
                                openai_developer_role=args.openai_developer_role)
    except BindError as exc:
        print(f"error[{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
