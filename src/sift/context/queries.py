"""Compiled tree-sitter queries for Python, and the plain extraction over them.

Everything here returns plain dataclasses, not `ContextBundle` types. Query
results are a parsing concern; deciding what they mean for a finding —
completeness, redaction, reachability — is `builder.py`'s job. Keeping the
line means a fixture test here can assert exact spans without dragging in the
rest of the bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache, lru_cache
from importlib import resources
from pathlib import Path

import tree_sitter_python as tsp
from tree_sitter import Language, Node, Parser, Query, QueryCursor

#: Names that mean "the real callee cannot be determined from the AST alone."
#: A call to one of these on the path to a flagged sink is decision D6's
#: DYNAMIC_DISPATCH trigger.
DYNAMIC_CALL_NAMES = frozenset({"getattr", "setattr", "eval", "exec", "__import__"})

#: Not a Python package — a plain resource subdirectory under sift.context, so
#: adding a new .scm file needs no __init__.py.
_QUERY_DIR = ("tree_sitter_queries", "python")


@lru_cache(maxsize=1)
def python_language() -> Language:
    return Language(tsp.language())


@lru_cache(maxsize=1)
def python_parser() -> Parser:
    return Parser(python_language())


@cache
def _compiled(name: str) -> Query:
    base = resources.files("sift.context")
    for segment in _QUERY_DIR:
        base = base / segment
    text = (base / f"{name}.scm").read_text(encoding="utf-8")
    return Query(python_language(), text)


def parse(source: bytes) -> Node:
    """Parse Python source. Returns the root node of the syntax tree."""
    return python_parser().parse(source).root_node


def _one(captures: dict[str, list[Node]], key: str) -> Node | None:
    """The first node captured under `key`, or None. Typed so a missing key
    and an empty list both narrow the same way instead of confusing mypy."""
    nodes = captures.get(key)
    return nodes[0] if nodes else None


@dataclass(frozen=True)
class FunctionDef:
    """One `def`, decorated or not."""

    name: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    body_start_byte: int
    decorators: tuple[str, ...] = ()

    @property
    def is_decorated(self) -> bool:
        return bool(self.decorators)


@dataclass(frozen=True)
class CallExpr:
    """One call expression, named where the AST makes that possible."""

    name: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int


@dataclass(frozen=True)
class ImportStmt:
    """One import statement. `module` and `names` are best-effort, from text."""

    text: str
    start_line: int
    module: str | None
    names: tuple[str, ...] = field(default_factory=tuple)


def _line(node: Node) -> tuple[int, int]:
    """1-indexed [start_line, end_line], matching FileLineRef/CodeSpan convention."""
    return node.start_point[0] + 1, node.end_point[0] + 1


def iter_functions(root: Node, source: bytes) -> list[FunctionDef]:
    """Every function definition, decorators attached where present.

    Deduplicates the decorated/undecorated double-match noted in
    function_bounds.scm by node byte range: a decorated function's inner
    `function_definition` matches both patterns, and the decorated match wins.
    """
    cursor = QueryCursor(_compiled("function_bounds"))
    by_span: dict[tuple[int, int], FunctionDef] = {}

    for pattern_index, captures in cursor.matches(root):
        def_node = _one(captures, "def")
        if def_node is None:
            continue
        span = (def_node.start_byte, def_node.end_byte)
        if pattern_index == 0 and span in by_span and by_span[span].is_decorated:
            continue  # already recorded via an earlier decorated match
        name_node = _one(captures, "name")
        body_node = _one(captures, "body")
        if name_node is None or body_node is None:
            continue
        decorators = tuple(
            source[d.start_byte : d.end_byte].decode("utf-8", errors="replace")
            for d in captures.get("deco", [])
        )
        existing = by_span.get(span)
        if existing is not None and existing.is_decorated and not decorators:
            continue  # keep the decorated version already stored

        # A decorator can carry security-relevant meaning (auth requirements,
        # a route pattern), so it belongs inside the span of "the function" an
        # agent is shown, not left outside it. wrapper_node's start includes the
        # decorator lines; def_node's end already covers the body.
        wrapper_node = _one(captures, "decorated") if decorators else None
        start_node = wrapper_node or def_node
        start_line, end_line = start_node.start_point[0] + 1, def_node.end_point[0] + 1

        by_span[span] = FunctionDef(
            name=source[name_node.start_byte : name_node.end_byte].decode(
                "utf-8", errors="replace"
            ),
            start_line=start_line,
            end_line=end_line,
            start_byte=start_node.start_byte,
            end_byte=def_node.end_byte,
            body_start_byte=body_node.start_byte,
            decorators=decorators,
        )
    return sorted(by_span.values(), key=lambda f: f.start_byte)


def iter_calls(node: Node, source: bytes) -> list[CallExpr]:
    """Every call expression within `node`, named where the AST allows it.

    `node` can be a whole file's root or a single function's body — the query
    is the same either way, so callee extraction (within a function) and
    caller search (across a file) share one implementation.
    """
    cursor = QueryCursor(_compiled("calls"))
    calls = []
    for _, captures in cursor.matches(node):
        call_node = _one(captures, "call")
        name_node = _one(captures, "name")
        if call_node is None or name_node is None:
            continue
        start_line, end_line = _line(call_node)
        calls.append(
            CallExpr(
                name=source[name_node.start_byte : name_node.end_byte].decode(
                    "utf-8", errors="replace"
                ),
                start_line=start_line,
                end_line=end_line,
                start_byte=call_node.start_byte,
                end_byte=call_node.end_byte,
            )
        )
    return calls


def _parse_import_text(text: str) -> tuple[str | None, tuple[str, ...]]:
    """Best-effort module + imported names from an import statement's own text.

    Text-based rather than a query capture per D2-style token extraction,
    because `import a.b.c as d` and `from a.b import c, d as e` need different
    shapes and forcing one capture name to cover both would blur which form
    produced it (see the comment in imports.scm).
    """
    stripped = text.strip()
    if stripped.startswith("from "):
        rest = stripped[len("from ") :]
        module, _, names_part = rest.partition(" import ")
        names = tuple(
            n.strip().split(" as ")[0].strip() for n in names_part.split(",") if n.strip()
        )
        return module.strip() or None, names
    if stripped.startswith("import "):
        rest = stripped[len("import ") :]
        first = rest.split(",")[0].strip()
        module = first.split(" as ")[0].strip()
        return module or None, ()
    return None, ()


def iter_imports(root: Node, source: bytes) -> list[ImportStmt]:
    cursor = QueryCursor(_compiled("imports"))
    imports = []
    for _, captures in cursor.matches(root):
        stmt_node = _one(captures, "import")
        if stmt_node is None:
            continue
        text = source[stmt_node.start_byte : stmt_node.end_byte].decode("utf-8", errors="replace")
        module, names = _parse_import_text(text)
        start_line, _ = _line(stmt_node)
        imports.append(ImportStmt(text=text, start_line=start_line, module=module, names=names))
    return sorted(imports, key=lambda i: i.start_line)


def enclosing_function(root: Node, source: bytes, line: int) -> FunctionDef | None:
    """The innermost function definition whose span contains `line`.

    "Innermost" rather than "first match" is what makes nested functions
    resolve to the nested one, not the module-level wrapper around it.
    """
    candidates = [f for f in iter_functions(root, source) if f.start_line <= line <= f.end_line]
    if not candidates:
        return None
    return min(candidates, key=lambda f: f.end_line - f.start_line)


def query_source_path(query_name: str) -> Path:
    """Where a compiled query's .scm file lives, for a fixture test to load it."""
    base = resources.files("sift.context")
    for segment in _QUERY_DIR:
        base = base / segment
    return Path(str(base / f"{query_name}.scm"))
