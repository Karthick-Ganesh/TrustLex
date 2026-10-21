"""
TrustLex - Module 3: Semantic and Security Analysis.

Checks name resolution and enforces the TrustLex security rule: no data from
an `input` may reach a `system` block unless it passed through sanitize().

Trust lattice (a chain, ordered by taint):

    TRUSTED  ⊑  SANITIZED  ⊑  SEMI_TRUSTED  ⊑  UNTRUSTED

    string literals            TRUSTED
    input x from rag | tool    SEMI_TRUSTED
    input x [from user]        UNTRUSTED
    a + b, "...{a}..."         join (⊔): the less trusted operand
    sanitize(e)                every external part of e is lowered to SANITIZED

Each block kind has a clearance; content may enter a block only if its label
is ⊑ the clearance (strict policy: system = SANITIZED, instruction = UNTRUSTED).

Flow-sensitive taint by symbolic evaluation
-------------------------------------------
TrustLex programs are straight-line: no branches, loops or calls. The checker
therefore evaluates the program exactly instead of approximating it. The value
of every variable at every program point is a Template: a sequence of literal
Text pieces and input Slots, each slot recording whether it was sanitized and
the path by which it arrived. Assignments strongly update the environment, so
`note = "clean"` really does clean `note` from that point on, and a block sees
each variable's value at the block's position. A template's label is the join
of its slots' levels (Text is TRUSTED). The checked block templates are handed
to code generation, which never re-evaluates the program.

Soundness: non-interference up to sanitization
----------------------------------------------
Let P be a program with no TL-S010/TL-S011 errors under the strict policy.
Let σ1, σ2 assign runtime strings to P's inputs, and let san be the runtime
sanitizer. If san(σ1(x)) = san(σ2(x)) for every input x, then every system
block of P renders to the same text under σ1 and σ2. Raw input can influence
privileged content only through sanitize().

Proof outline.
  (1) Exactness. By induction over the statements of P, the template Γ(v)
      bound to each variable v at each program point denotes v's runtime
      value: rendering Γ(v) under σ yields exactly the value v holds. Base
      cases are literals and inputs; Concat, interpolation and sanitize are
      homomorphic over rendering; assignment is a strong update, which is
      exact because P has no control flow.
  (2) Clean templates. If label(t) ⊑ SANITIZED then every slot of t is
      sanitized (a raw slot has level SEMI_TRUSTED or UNTRUSTED). So
      render(t, σ) depends on σ only through san ∘ σ.
  (3) The block check requires label(t) ⊑ SANITIZED for the template t of
      every system block item. By (1) that template is the item's runtime
      content, and by (2) the content is equal under σ1 and σ2.        ∎

Because the evaluation is exact, the check is also complete for this
language: a program is rejected only if some raw input slot reaches a system
block, i.e. there exist σ1, σ2 as above that render it differently. Both
directions are exercised by the property-based test in tests/test_semantic.py.
"""

from __future__ import annotations

import difflib
import functools
import sys
from dataclasses import dataclass, field, replace

from diagnostics import (
    DiagnosticBag, Edit, Fix, Related, Severity, SourceFile, SourceSpan,
)
from lexer import TrustLevel
from parser_ast import (
    Assign, Block, BlockKind, Concat, Expr, InputDecl, InsertItem, Node, ParseResult,
    Program, Sanitize, StringLit, TextItem, TextSegment, VarDecl, VarRef, parse,
)


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityPolicy:
    """Clearance of each block kind, and how leaks of retrieved/tool data
    (SEMI_TRUSTED) into a block are reported."""

    clearances: dict = field(default_factory=lambda: {
        BlockKind.SYSTEM: TrustLevel.SANITIZED,
        BlockKind.INSTRUCTION: TrustLevel.UNTRUSTED,
    })
    semi_trusted_severity: Severity = Severity.ERROR

    @classmethod
    def strict(cls) -> SecurityPolicy:
        return cls()

    @classmethod
    def relaxed(cls) -> SecurityPolicy:
        """Retrieved and tool data in a system block is only a warning.
        The soundness lemma then covers UNTRUSTED inputs only."""
        return cls(semi_trusted_severity=Severity.WARNING)

    def clearance(self, kind: BlockKind) -> TrustLevel:
        return self.clearances[kind]

    @property
    def name(self) -> str:
        return "relaxed" if self.semi_trusted_severity is Severity.WARNING else "strict"


# --------------------------------------------------------------------------
# Templates: exact symbolic values
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FlowStep:
    """One step of a taint path, shown as a secondary diagnostic location."""

    description: str
    span: SourceSpan


@dataclass(frozen=True)
class Text:
    text: str


@dataclass(frozen=True)
class Slot:
    """A placeholder for the runtime value of an input."""

    input: str
    source_level: TrustLevel
    sanitized: bool = False
    path: tuple[FlowStep, ...] = ()

    @property
    def level(self) -> TrustLevel:
        return self.source_level.meet(TrustLevel.SANITIZED) if self.sanitized else self.source_level


@dataclass(frozen=True)
class Template:
    pieces: tuple[Text | Slot, ...] = ()

    @classmethod
    def of_text(cls, text: str) -> Template:
        return cls((Text(text),)) if text else cls()

    def __add__(self, other: Template) -> Template:
        if not self.pieces:
            return other
        if not other.pieces:
            return self
        a, b = self.pieces[-1], other.pieces[0]
        if isinstance(a, Text) and isinstance(b, Text):
            return Template(self.pieces[:-1] + (Text(a.text + b.text),) + other.pieces[1:])
        return Template(self.pieces + other.pieces)

    @property
    def slots(self) -> list[Slot]:
        return [p for p in self.pieces if isinstance(p, Slot)]

    @property
    def label(self) -> TrustLevel:
        return functools.reduce(TrustLevel.join, (s.level for s in self.slots), TrustLevel.TRUSTED)

    def _map_slots(self, f) -> Template:
        return Template(tuple(f(p) if isinstance(p, Slot) else p for p in self.pieces))

    def sanitized(self) -> Template:
        return self._map_slots(lambda s: replace(s, sanitized=True))

    def with_step(self, step: FlowStep) -> Template:
        return self._map_slots(lambda s: replace(s, path=s.path + (step,)))

    def sources(self) -> list[str]:
        """Contributing inputs, in order, e.g. ['user_msg', 'doc (sanitized)']."""
        seen = []
        for s in self.slots:
            name = s.input + (" (sanitized)" if s.sanitized else "")
            if name not in seen:
                seen.append(name)
        return seen

    def render(self, values: dict[str, str], sanitizer) -> str:
        """Reference semantics: the text this template denotes at runtime."""
        return "".join(
            p.text if isinstance(p, Text) else (sanitizer(values[p.input]) if p.sanitized else values[p.input])
            for p in self.pieces
        )

    @staticmethod
    def join(templates, separator: str = "") -> Template:
        result = Template()
        for i, t in enumerate(templates):
            if i:
                result = result + Template.of_text(separator)
            result = result + t
        return result


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@dataclass
class Symbol:
    name: str
    kind: str  # "input" | "var"
    span: SourceSpan
    trust: TrustLevel | None = None  # inputs only
    source_tag: str | None = None
    used: bool = False
    implicit: bool = False  # created by an assignment to an undeclared name


@dataclass
class CheckedItem:
    item: Node
    template: Template


@dataclass
class CheckedBlock:
    block: Block
    items: list[CheckedItem]

    @property
    def kind(self) -> BlockKind:
        return self.block.kind

    def template(self, separator: str = "\n") -> Template:
        return Template.join((i.template for i in self.items), separator)

    def render(self, values: dict[str, str], sanitizer, separator: str = "\n") -> str:
        return self.template(separator).render(values, sanitizer)


@dataclass
class TraceEntry:
    span: SourceSpan
    event: str
    label: TrustLevel
    sources: list[str]
    allowed: bool | None = None  # block items only


@dataclass
class CheckedProgram:
    program: Program
    source: SourceFile
    diagnostics: DiagnosticBag
    policy: SecurityPolicy
    symbols: dict[str, Symbol] = field(default_factory=dict)
    blocks: list[CheckedBlock] = field(default_factory=list)
    labels: dict[Node, TrustLevel] = field(default_factory=dict)
    trace: list[TraceEntry] = field(default_factory=list)
    comments: list = field(default_factory=list)  # lexer.Comment, for the optimizer report

    @property
    def ok(self) -> bool:
        return not self.diagnostics.has_errors

    def format_trace(self) -> str:
        rows = [("LOC", "EVENT", "LABEL", "SOURCES")]
        for e in self.trace:
            mark = "" if e.allowed is None else (" ✓" if e.allowed else " ✗")
            rows.append((f"{e.span.line}:{e.span.col}", e.event, f"{e.label}{mark}", ", ".join(e.sources) or "-"))
        widths = [max(len(r[i]) for r in rows) for i in range(3)]
        return "\n".join(
            f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}".rstrip() for r in rows
        )


# --------------------------------------------------------------------------
# Checker
# --------------------------------------------------------------------------

_LEAK_HINT = {
    TrustLevel.UNTRUSTED: "untrusted text in a privileged block can override your instructions (direct prompt injection)",
    TrustLevel.SEMI_TRUSTED: "retrieved or tool-produced text can carry instructions planted by a third party (indirect prompt injection)",
}
_MAX_PATH = 4


def _short(text: str, limit: int = 32) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class SecurityChecker:
    def __init__(self, source: SourceFile, diagnostics: DiagnosticBag, policy: SecurityPolicy):
        self.source = source
        self.diagnostics = diagnostics
        self.policy = policy
        self.symbols: dict[str, Symbol] = {}
        self.env: dict[str, Template] = {}
        self.templates: dict[Node, Template] = {}
        self.labels: dict[Node, TrustLevel] = {}
        self.trace: list[TraceEntry] = []
        self._target: str | None = None
        self._declared_later: dict[str, SourceSpan] = {}
        self._all_names: set[str] = set()

    def check(self, program: Program) -> CheckedProgram:
        for stmt in program.statements:
            if isinstance(stmt, (InputDecl, VarDecl)):
                self._declared_later.setdefault(stmt.name, stmt.name_span)
                self._all_names.add(stmt.name)

        blocks = []
        for stmt in program.statements:
            if isinstance(stmt, InputDecl):
                self._input(stmt)
            elif isinstance(stmt, VarDecl):
                self._var(stmt)
            elif isinstance(stmt, Assign):
                self._assign(stmt)
            elif isinstance(stmt, Block):
                blocks.append(self._block(stmt))

        for sym in self.symbols.values():
            if not sym.used and not sym.implicit:
                what = "input" if sym.kind == "input" else "variable"
                self.diagnostics.warning("TL-W001", f"{what} `{sym.name}` is never used", sym.span)

        return CheckedProgram(
            program, self.source, self.diagnostics, self.policy,
            self.symbols, blocks, self.labels, self.trace,
        )

    # ---- statements ----

    def _input(self, stmt: InputDecl):
        if self._redeclared(stmt.name, stmt.name_span):
            return
        self.symbols[stmt.name] = Symbol(stmt.name, "input", stmt.name_span, stmt.trust, stmt.source_tag)
        origin = f"`{stmt.name}` is {stmt.trust} input" + (f" (from {stmt.source_tag})" if stmt.source_tag else "")
        template = Template((Slot(stmt.name, stmt.trust, path=(FlowStep(origin, stmt.name_span),)),))
        self.env[stmt.name] = template
        self._record(stmt, template, f"input {stmt.name}")

    def _var(self, stmt: VarDecl):
        template = self._eval_into(stmt.name, stmt.value)
        existing = self.symbols.get(stmt.name)
        if existing is not None and existing.implicit:
            existing.implicit = False
        elif not self._redeclared(stmt.name, stmt.name_span):
            self.symbols[stmt.name] = Symbol(stmt.name, "var", stmt.name_span)
        if self.symbols[stmt.name].kind == "var":
            self.env[stmt.name] = template
        self._record(stmt, template, f"var {stmt.name}")

    def _assign(self, stmt: Assign):
        template = self._eval_into(stmt.name, stmt.value)
        sym = self.symbols.get(stmt.name)
        if sym is None:
            self.diagnostics.error(
                "TL-S003", f"assignment to undeclared variable `{stmt.name}`", stmt.name_span,
                hint=f"declare it first: var {stmt.name} = ...",
            )
            self.symbols[stmt.name] = Symbol(stmt.name, "var", stmt.name_span, implicit=True)
        elif sym.kind == "input":
            self.diagnostics.error(
                "TL-S004", f"cannot assign to input `{stmt.name}`", stmt.name_span,
                related=[Related(sym.span, "declared as an input here")],
                hint="inputs are read-only external values; declare a new variable instead: var name = ...",
            )
            return  # keep the input's own taint
        self.env[stmt.name] = template
        self._record(stmt, template, f"{stmt.name} = {_short(stmt.value.span.text, 24)}")

    def _redeclared(self, name: str, span: SourceSpan) -> bool:
        previous = self.symbols.get(name)
        if previous is None:
            return False
        self.diagnostics.error(
            "TL-S002", f"`{name}` is already declared", span,
            related=[Related(previous.span, "first declared here")],
            hint=f"to change a variable's value, assign without `var`: {name} = ...; otherwise rename one of them",
        )
        return True

    # ---- expressions ----

    def _eval_into(self, target: str, expr: Expr) -> Template:
        self._target = target
        try:
            return self._eval(expr)
        finally:
            self._target = None

    def _eval(self, expr: Expr) -> Template:
        if isinstance(expr, StringLit):
            template = Template()
            for part in expr.parts:
                template = template + (Template.of_text(part.text) if isinstance(part, TextSegment) else self._eval(part))
        elif isinstance(expr, VarRef):
            template = self._read(expr)
        elif isinstance(expr, Concat):
            template = self._eval(expr.left) + self._eval(expr.right)
        elif isinstance(expr, Sanitize):
            inner = self._eval(expr.expr)
            if inner.label.leq(TrustLevel.SANITIZED):
                what = "trusted data" if inner.label is TrustLevel.TRUSTED else "data that is already sanitized"
                self.diagnostics.warning(
                    "TL-W002", f"sanitize() applied to {what} has no effect", expr.span,
                    hint=f"remove the call: {_short(expr.expr.span.text, 40)}",
                )
            template = inner.sanitized()
        else:
            raise TypeError(f"unexpected expression {type(expr).__name__}")
        self.templates[expr] = template
        self.labels[expr] = template.label
        return template

    def _read(self, ref: VarRef) -> Template:
        sym = self.symbols.get(ref.name)
        if sym is None:
            self._undeclared(ref)
            return Template()
        sym.used = True
        template = self.env.get(ref.name, Template())
        target = self._target
        if target is not None and template.slots:
            if ref.name == target:
                text = f"`{target}` is reassigned from its previous value"
            elif ref.interpolated:
                text = f"`{ref.name}` is interpolated into `{target}`"
            else:
                text = f"`{ref.name}` flows into `{target}`"
            template = template.with_step(FlowStep(text, ref.span))
        return template

    def _undeclared(self, ref: VarRef):
        later = self._declared_later.get(ref.name)
        if later is not None and later.offset < ref.span.offset:
            hint = "a variable cannot be used in its own declaration"
        elif later is not None:
            hint = f"`{ref.name}` is declared later, on line {later.line}; move the declaration above this use"
        else:
            close = difflib.get_close_matches(ref.name, list(self.symbols), n=1)
            hint = (
                f"did you mean `{close[0]}`?" if close
                else f'declare it: `input {ref.name}` for external data, or var {ref.name} = "..."'
            )
        self.diagnostics.error("TL-S001", f"undeclared variable `{ref.name}`", ref.span, hint=hint)

    # ---- blocks ----

    def _block(self, block: Block) -> CheckedBlock:
        clearance = self.policy.clearance(block.kind)
        items = []
        for item in block.items:
            if isinstance(item, TextItem):
                template = Template()
                for part in item.text.parts:
                    if isinstance(part, TextSegment):
                        template = template + Template.of_text(part.text)
                    else:
                        hole = self._eval(part)
                        self._enforce(block, clearance, hole, part)
                        template = template + hole
                self.templates[item.text] = template
            else:
                template = self._eval(item.expr)
                self._enforce(block, clearance, template, item)
            items.append(CheckedItem(item, template))
            self.labels[item] = template.label
            event = f"{block.kind.value} ← {_short(item.span.text)}"
            self.trace.append(TraceEntry(item.span, event, template.label, template.sources(), template.label.leq(clearance)))

        if block.kind is BlockKind.SYSTEM and not block.items:
            self.diagnostics.warning("TL-W003", "empty system block", block.keyword_span)
        return CheckedBlock(block, items)

    def _enforce(self, block: Block, clearance: TrustLevel, template: Template, site: Node):
        """Report every input whose raw data in `template` exceeds the
        block's clearance. `site` is an InsertItem or an interpolated VarRef."""
        leaks: dict[str, Slot] = {}
        for slot in template.slots:
            if not slot.level.leq(clearance):
                leaks.setdefault(slot.input, slot)

        for name, slot in leaks.items():
            level = slot.source_level
            code, severity = ("TL-S010", Severity.ERROR) if level is TrustLevel.UNTRUSTED else ("TL-S011", self.policy.semi_trusted_severity)
            kind = block.kind.value

            if isinstance(site, VarRef):
                span = site.span
                label = f"`{{{site.name}}}` interpolates {level} data"
                fix = self._hole_fix(block, site)
            else:
                span = site.expr.span
                expr = site.expr
                if isinstance(expr, VarRef):
                    label = "raw input inserted here" if expr.name == name else f"`{expr.name}` carries {level} data"
                else:
                    label = f"this expression carries {level} data"
                fix = self._insert_fix(site, name, clearance)

            path = list(slot.path)
            notes = []
            if len(path) > _MAX_PATH:
                notes.append(f"{len(path) - _MAX_PATH} intermediate step(s) of the taint path omitted")
                path = path[:1] + path[-(_MAX_PATH - 1):]

            self.diagnostics.report(
                severity, code, f"{level} data from input `{name}` reaches a `{kind}` block", span,
                label=label,
                related=[Related(step.span, step.description) for step in path],
                notes=notes,
                fixes=[fix] if fix else [],
                hint=f"`{kind}` blocks accept data up to {clearance}; {_LEAK_HINT[level]}",
            )

    # ---- fix-its ----

    def _offenders(self, expr: Expr, name: str, clearance: TrustLevel) -> list[Expr]:
        """Smallest sub-expressions that carry raw `name` data and can be
        wrapped in sanitize()."""
        if isinstance(expr, Concat):
            return self._offenders(expr.left, name, clearance) + self._offenders(expr.right, name, clearance)
        if isinstance(expr, Sanitize):
            return []
        template = self.templates.get(expr, Template())
        leaking = any(s.input == name and not s.level.leq(clearance) for s in template.slots)
        return [expr] if leaking else []

    def _insert_fix(self, item: InsertItem, name: str, clearance: TrustLevel) -> Fix | None:
        offenders = self._offenders(item.expr, name, clearance)
        if not offenders:
            return None
        edits = tuple(Edit(e.span, f"sanitize({e.span.text})") for e in offenders)
        # Preview the whole insert(...) item with the edits applied.
        base = item.span.offset
        preview = item.span.text
        for edit in sorted(edits, key=lambda e: e.span.offset, reverse=True):
            start, end = edit.span.offset - base, edit.span.end_offset - base
            preview = preview[:start] + edit.text + preview[end:]
        return Fix(f"sanitize the value before it enters the block: `{preview}`", edits)

    def _hole_fix(self, block: Block, hole: VarRef) -> Fix:
        clean = f"{hole.name}_clean"
        n = 2
        while clean in self._all_names:
            clean = f"{hole.name}_clean{n}"
            n += 1
        indent = " " * (block.span.col - 1)
        decl = f"var {clean} = sanitize({hole.name})"
        at_block = self.source.span(block.span.offset, block.span.offset)
        return Fix(
            f"interpolation cannot be sanitized in place; declare `{decl}` before the block and write `{{{clean}}}`",
            (Edit(at_block, decl + "\n" + indent), Edit(hole.span, "{" + clean + "}")),
        )

    # ---- trace ----

    def _record(self, stmt: Node, template: Template, event: str):
        self.labels[stmt] = template.label
        self.trace.append(TraceEntry(stmt.span, event, template.label, template.sources()))


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------

def check(parsed: ParseResult, policy: SecurityPolicy | None = None) -> CheckedProgram:
    """Run the security analysis on a parse result. Programs with lexical or
    syntax errors are not analysed."""
    policy = policy or SecurityPolicy.strict()
    if not parsed.ok:
        return CheckedProgram(parsed.program, parsed.source, parsed.diagnostics, policy, comments=parsed.comments)
    checked = SecurityChecker(parsed.source, parsed.diagnostics, policy).check(parsed.program)
    checked.comments = parsed.comments
    return checked


def analyze(text: str, filename: str = "<input>", policy: SecurityPolicy | None = None) -> CheckedProgram:
    """Lex, parse and check `text`."""
    return check(parse(text, filename), policy)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print("usage: python semantic.py [--relaxed] FILE.tlx", file=sys.stderr)
        return 2
    policy = SecurityPolicy.relaxed() if "--relaxed" in argv else SecurityPolicy.strict()
    with open(args[0], encoding="utf-8") as f:
        checked = analyze(f.read(), args[0], policy)
    if checked.trace:
        print(checked.format_trace())
    if len(checked.diagnostics):
        print("\n" + checked.diagnostics.render(color=sys.stdout.isatty()))
    print("\n" + checked.diagnostics.summary())
    return 0 if checked.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
