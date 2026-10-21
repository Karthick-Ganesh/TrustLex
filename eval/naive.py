"""
Naive renderer: the vulnerable baseline.

Evaluates a TrustLex program the way an application that builds prompts by
string concatenation would: every value is inserted raw, sanitize(x) is the
identity, nothing is spotlighted, and no trust rule is checked. Blocks map to
the same roles, and items are joined the same way, as in codegen.

    naive_render(source, values) -> [(role, text), ...]

Only the parser is reused; the security checker and code generator are not
involved, so the compiler's semantics are untouched.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from codegen import _ROLE_OF, ITEM_SEPARATOR  # noqa: E402
from parser_ast import (  # noqa: E402
    Assign, Block, Concat, InputDecl, Sanitize, StringLit, TextItem, TextSegment, VarDecl, VarRef, parse,
)


def _eval(expr, env: dict[str, str]) -> str:
    if isinstance(expr, StringLit):
        return "".join(p.text if isinstance(p, TextSegment) else env.get(p.name, "") for p in expr.parts)
    if isinstance(expr, VarRef):
        return env.get(expr.name, "")
    if isinstance(expr, Concat):
        return _eval(expr.left, env) + _eval(expr.right, env)
    if isinstance(expr, Sanitize):
        return _eval(expr.expr, env)  # the naive app has no sanitizer
    raise TypeError(f"unexpected expression {type(expr).__name__}")


def naive_render(source: str, values: dict[str, str]) -> list[tuple[str, str]]:
    """Render `source` with `values` and no trust checks. Raises ValueError
    if the program has lexical or syntax errors."""
    result = parse(source, "<naive>")
    if not result.ok:
        raise ValueError("cannot render a program with syntax errors:\n" + result.diagnostics.render())
    env: dict[str, str] = {}
    rendered = []
    for stmt in result.program.statements:
        if isinstance(stmt, InputDecl):
            env[stmt.name] = values.get(stmt.name, "")
        elif isinstance(stmt, (VarDecl, Assign)):
            env[stmt.name] = _eval(stmt.value, env)
        elif isinstance(stmt, Block):
            items = [_eval(i.text, env) if isinstance(i, TextItem) else _eval(i.expr, env) for i in stmt.items]
            text = ITEM_SEPARATOR.join(items)
            if text.strip():
                rendered.append((_ROLE_OF[stmt.kind], text))
    return rendered


def system_text(rendered: list[tuple[str, str]]) -> str:
    """All system-role text of a rendering, joined."""
    return "\n".join(text for role, text in rendered if role == "system")
