"""
TrustLex - Module 4: Code Generation.

Lowers a checked program to a checksummed intermediate representation (IR) and,
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
  * the IR carries a SHA-256 integrity checksum of its canonical form, which
    detects accidental corruption. With a key ($TRUSTLEX_IR_KEY or key=) it
    also carries an HMAC-SHA256 seal, which detects tampering;
  * CompiledPrompt.from_json() / bind() re-verify the security invariant
    itself, so even an IR that was edited and re-hashed cannot smuggle raw
    input into a system message.

What sanitize() does at runtime is pluggable through a registry
(register_sanitizer). The IR records the sanitizer's name and bind() runs
exactly that sanitizer; a caller-supplied callable needs an explicit
unsafe_sanitizer_override=True and warns. The compiler guarantees that
raw input never reaches a system message without passing through the
sanitizer; how much protection that sanitizer gives is a separate concern.
The default (trustlex-default/1) normalizes Unicode, strips control and
invisible characters, defuses chat-template role markers, caps the length and
spotlights the value inside <untrusted_input> delimiters (Hines et al., 2024).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import unicodedata
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field

from diagnostics import DiagnosticBag
from lexer import _IDENT_RE, SOURCE_TAGS
from parser_ast import BlockKind
from semantic import CheckedProgram, SecurityPolicy, Slot, Text, analyze

FORMAT = "trustlex-ir/1"
TARGETS = ("ir", "openai", "anthropic")
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"
DEFAULT_ANTHROPIC_MAX_TOKENS = 16000
ITEM_SEPARATOR = "\n"
MAX_SANITIZER_LENGTH = 100_000
IR_KEY_ENV = "TRUSTLEX_IR_KEY"


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
_LINE_SEPARATORS = {0x2028: "\n", 0x2029: "\n"}
_ROLE_TOKENS = re.compile(r"<\|[^|<>]{0,32}\|>|\[/?INST\]|<</?SYS>>", re.IGNORECASE)
_TRANSCRIPT_TURN = re.compile(r"(^|\n)([ \t]*)(human|assistant|system|user)([ \t]*:)", re.IGNORECASE)
_DELIMITER = re.compile(r"<(\s*/?\s*untrusted_input)", re.IGNORECASE)
_TRUNCATED = "…[truncated]"


def _strip_once(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    # LINE / PARAGRAPH SEPARATOR (Zl, Zp) survive the Cc/Cf filter, but a
    # model may still read them as line breaks; make them real newlines so
    # transcript-turn defusing sees the line start.
    value = value.translate(_LINE_SEPARATORS)
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


def _attr(text: str) -> str:
    return text.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


def _defuse_delimiters(value: str) -> str:
    """Neutralize every `<` that opens an (un)trusted_input tag, including
    lookalikes such as a fullwidth `＜／untrusted_input＞`.

    Raw user-turn slots are not passed through clean(), so they are not
    NFKC-normalized. The tag is therefore matched on a per-character NFKC
    copy, and the character that normalizes to the opening `<` is replaced
    in the original, which is otherwise left exactly as supplied."""
    if value.isascii():
        return _DELIMITER.sub(r"&lt;\1", value)
    normalized, owner = [], []
    for i, c in enumerate(value):
        n = unicodedata.normalize("NFKC", c)
        normalized.append(n)
        owner.extend([i] * len(n))
    opens = {owner[m.start()] for m in _DELIMITER.finditer("".join(normalized))}
    out = "".join("&lt;" if i in opens else c for i, c in enumerate(value))
    if _DELIMITER.search(unicodedata.normalize("NFKC", out)):  # pragma: no cover - defensive
        out = _DELIMITER.sub(r"&lt;\1", unicodedata.normalize("NFKC", value))
    return out


def spotlight(value: str, name: str, source: str) -> str:
    """Wrap a value in delimiters it cannot close early.

    verify() already restricts `name` and `source` to identifiers and known
    tags; the attributes are escaped anyway, as defence in depth."""
    value = _defuse_delimiters(value)
    return f'<untrusted_input name="{_attr(name)}" source="{_attr(source)}">{value}</untrusted_input>'


def default_sanitizer(config: SanitizerConfig, inputs: dict[str, dict]):
    def sanitize(value: str, name: str) -> str:
        return spotlight(clean(value, config.max_length), name, inputs[name]["source"])
    return sanitize


class UnsafeSanitizerWarning(UserWarning):
    """A caller replaced the IR's registered sanitizer with its own callable."""


_SANITIZERS: dict[str, Callable] = {}


def register_sanitizer(name: str, factory: Callable) -> None:
    """Register `factory(config, inputs) -> sanitize(value, input_name)`.

    The IR records the sanitizer's name, and render()/bind() look it up
    here, so the sanitizer that runs is the one the program was compiled
    against. A registered name cannot be rebound to a different factory:
    otherwise `trustlex-default/1` itself could be swapped for a no-op."""
    if not isinstance(name, str) or not name:
        raise ValueError("a sanitizer name must be a non-empty string")
    if _SANITIZERS.get(name, factory) is not factory:
        raise ValueError(f"sanitizer {name!r} is already registered")
    _SANITIZERS[name] = factory


register_sanitizer(SanitizerConfig.name, default_sanitizer)


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


def resolve_ir_key(key: str | bytes | None = None) -> bytes | None:
    """The HMAC key for sealing IR: `key` if given, else $TRUSTLEX_IR_KEY,
    else None (integrity checksum only)."""
    if key is None:
        key = os.environ.get(IR_KEY_ENV) or None
    if isinstance(key, str):
        key = key.encode("utf-8")
    if key is not None and not key:
        raise ValueError("the IR key must not be empty")
    return key


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
        """Unkeyed SHA-256 integrity checksum: detects corruption, not tampering."""
        return hashlib.sha256(_canonical(self._body()).encode("utf-8")).hexdigest()

    def mac(self, key: bytes) -> str:
        """HMAC-SHA256 seal: only a holder of `key` can produce it."""
        return hmac.new(key, _canonical(self._body()).encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self, key: str | bytes | None = None) -> dict:
        """The IR with its integrity checksum, plus an HMAC seal when a key
        is given or set in $TRUSTLEX_IR_KEY."""
        data = {**self._body(), "sha256": self.digest()}
        key = resolve_ir_key(key)
        if key is not None:
            data["hmac"] = self.mac(key)
        return data

    def to_json(self, indent: int | None = None, key: str | bytes | None = None) -> str:
        data = self.to_dict(key)
        if indent is None:
            return _canonical(data)
        return json.dumps(data, sort_keys=True, indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str, key: str | bytes | None = None) -> CompiledPrompt:
        """Load an IR, verifying its integrity checksum, its HMAC seal and the
        security invariant.

        With a key (`key=` or $TRUSTLEX_IR_KEY) the IR must carry a valid
        HMAC seal; an unsealed IR is refused, since anyone can recompute the
        checksum. An IR that carries a seal is refused when no key is
        available, rather than loaded unauthenticated."""
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise BindError("TL-G005", "malformed IR: expected a JSON object")
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
            raise BindError("TL-G005", "IR integrity check failed: the sha256 checksum does not match its contents")
        compiled._verify_seal(data, resolve_ir_key(key))
        compiled.verify()
        return compiled

    def _verify_seal(self, data: dict, key: bytes | None):
        if "hmac" not in data:
            if key is not None:
                raise BindError("TL-G005", "IR has no HMAC seal but a key is set; "
                                           "an unsealed IR could have been edited and re-hashed by anyone")
            return
        if key is None:
            raise BindError("TL-G005", f"IR carries an HMAC seal but no key is available; set {IR_KEY_ENV} or pass key=")
        tag = data["hmac"]
        if not isinstance(tag, str) or not hmac.compare_digest(tag.encode("utf-8"), self.mac(key).encode("utf-8")):
            raise BindError("TL-G005", "IR HMAC seal does not verify: wrong key, or the contents were changed")

    # ---- invariant ----

    def verify(self):
        """Every slot must name a declared input, and every slot in a system
        message must be sanitized. Under the relaxed policy (recorded in the
        IR) a SEMI_TRUSTED slot may be unsanitized; UNTRUSTED never.

        Without an HMAC key, anyone can edit the IR and recompute its checksum.
        verify() therefore never takes a stored label on faith: each input's
        trust is re-derived from its source tag, and the options are
        type-checked, so an edited `trust` cannot buy an exemption."""
        if self.policy not in ("strict", "relaxed"):
            raise BindError("TL-G005", f"unknown policy {self.policy!r} in IR")
        self._verify_options()
        self._verify_inputs()
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

    def _verify_inputs(self):
        if not isinstance(self.inputs, dict):
            raise BindError("TL-G005", "malformed IR: `inputs` must be an object")
        for name, info in self.inputs.items():
            if not isinstance(name, str) or not _IDENT_RE.match(name):
                raise BindError("TL-G005", f"invalid input name {name!r} in IR")
            if not isinstance(info, dict):
                raise BindError("TL-G005", f"malformed IR: input `{name}` must be an object")
            source, trust = info.get("source"), info.get("trust")
            if not isinstance(source, str) or source not in SOURCE_TAGS:
                raise BindError("TL-G005", f"input `{name}` has unknown source {source!r} in IR")
            expected = SOURCE_TAGS[source].name
            if trust != expected:
                raise BindError(
                    "TL-G005",
                    f"IR trust label mismatch: input `{name}` from {source} must be {expected}, "
                    f"but the IR says {trust!r}",
                )

    def _verify_options(self):
        from optimizer import LEVELS  # optimizer imports this module

        if type(self.delimit_untrusted) is not bool:
            raise BindError("TL-G005", "malformed IR: `delimit_untrusted` must be a boolean")
        if type(self.optimization) is not int or self.optimization not in LEVELS:
            raise BindError("TL-G005", f"unknown optimization level {self.optimization!r} in IR")
        if not isinstance(self.sanitizer.name, str):
            raise BindError("TL-G005", "malformed IR: the sanitizer name must be a string")
        if self.sanitizer.name not in _SANITIZERS:
            raise BindError("TL-G005", f"IR names unknown sanitizer {self.sanitizer.name!r}")
        length = self.sanitizer.max_length
        if type(length) is not int or not 1 <= length <= MAX_SANITIZER_LENGTH:
            raise BindError(
                "TL-G005", f"sanitizer max_length must be an integer in 1..{MAX_SANITIZER_LENGTH}, not {length!r}")

    # ---- runtime binding ----

    def render(self, values: dict[str, str], sanitizer=None, *,
               unsafe_sanitizer_override: bool = False) -> list[tuple[str, str]]:
        """Fill the slots; return (role, text) pairs, skipping empty messages.

        Sanitized slots go through the sanitizer registered under the IR's
        `sanitizer.name`. A caller-supplied `sanitizer(value, input_name)`
        replaces it and with it the compile-time guarantee, so it is refused
        unless `unsafe_sanitizer_override=True`, and then warns."""
        self.verify()
        if sanitizer is None:
            sanitize = _SANITIZERS[self.sanitizer.name](self.sanitizer, self.inputs)
        elif not unsafe_sanitizer_override:
            raise ValueError(
                f"a custom sanitizer would replace {self.sanitizer.name!r} and void the compile-time guarantee; "
                "register it with register_sanitizer() and compile against its name, "
                "or pass unsafe_sanitizer_override=True"
            )
        else:
            warnings.warn(
                f"using a caller-supplied sanitizer instead of {self.sanitizer.name!r}: "
                "the compile-time guarantee no longer holds",
                UnsafeSanitizerWarning, stacklevel=2,
            )
            sanitize = sanitizer
        missing = [n for n in self.inputs if n not in values]
        if missing:
            raise BindError("TL-G003", "no value supplied for input(s): " + ", ".join(f"`{n}`" for n in missing))
        unknown = [n for n in values if n not in self.inputs]
        if unknown:
            raise BindError("TL-G004", "value(s) supplied for undeclared input(s): " + ", ".join(f"`{n}`" for n in unknown))
        for name, value in values.items():
            if not isinstance(value, str):
                raise BindError("TL-G003", f"the value of input `{name}` must be a string, not {type(value).__name__}")

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
             max_tokens: int | None = None, sanitizer=None, openai_developer_role: bool = False,
             *, unsafe_sanitizer_override: bool = False) -> dict:
        """Build an API request body for `target` ("openai" or "anthropic").
        `sanitizer` / `unsafe_sanitizer_override` are as for render()."""
        rendered = self.render(values, sanitizer, unsafe_sanitizer_override=unsafe_sanitizer_override)
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
    if sanitizer is not None and sanitizer.name not in _SANITIZERS:
        raise CodegenError(f"unknown sanitizer {sanitizer.name!r}; register it with register_sanitizer() first")

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
