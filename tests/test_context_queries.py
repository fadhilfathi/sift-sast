"""Fixture tests, one per tree-sitter query. Exact spans, not "it parsed"."""

from __future__ import annotations

from pathlib import Path

from sift.context.queries import (
    DYNAMIC_CALL_NAMES,
    enclosing_function,
    iter_calls,
    iter_functions,
    iter_imports,
    parse,
    query_source_path,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "python"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# --------------------------------------------------------------- function_bounds


def test_every_query_file_exists_on_disk() -> None:
    """A packaging regression would otherwise fail as an obscure Query error."""
    for name in ("function_bounds", "calls", "imports"):
        assert query_source_path(name).is_file(), name


def test_function_bounds_exact_spans() -> None:
    source = load("function_bounds.py")
    functions = {f.name: f for f in iter_functions(parse(source), source)}

    assert set(functions) == {
        "plain",
        "decorated_single",
        "decorated_stacked",
        "method",
        "outer",
        "inner",
    }

    assert functions["plain"].start_line == 6
    assert functions["plain"].end_line == 7
    assert functions["plain"].decorators == ()

    assert functions["decorated_single"].start_line == 10
    assert functions["decorated_single"].end_line == 12
    assert functions["decorated_single"].decorators == ("@functools.wraps(plain)",)

    assert functions["decorated_stacked"].start_line == 15
    assert functions["decorated_stacked"].end_line == 18
    assert functions["decorated_stacked"].decorators == (
        "@functools.wraps(plain)",
        "@functools.lru_cache",
    )


def test_function_bounds_finds_a_method_inside_a_class() -> None:
    source = load("function_bounds.py")
    functions = {f.name: f for f in iter_functions(parse(source), source)}
    assert functions["method"].start_line == 22
    assert functions["method"].end_line == 23


def test_function_bounds_finds_nested_functions_separately() -> None:
    source = load("function_bounds.py")
    functions = {f.name: f for f in iter_functions(parse(source), source)}
    assert functions["outer"].start_line == 26
    assert functions["inner"].start_line == 27
    assert functions["inner"].end_line == 28
    # inner is inside outer's span, not equal to it
    assert functions["outer"].start_byte < functions["inner"].start_byte
    assert functions["inner"].end_byte <= functions["outer"].end_byte


def test_enclosing_function_picks_the_innermost() -> None:
    """The whole point of enclosing_function over a flat span search."""
    source = load("function_bounds.py")
    root = parse(source)
    inner_line_ref = enclosing_function(root, source, 28)  # `return m * 2` inside inner
    assert inner_line_ref is not None
    assert inner_line_ref.name == "inner"


def test_enclosing_function_none_outside_any_function() -> None:
    source = load("function_bounds.py")
    assert enclosing_function(parse(source), source, 1) is None  # the module docstring


# ---------------------------------------------------------------------- calls


def test_calls_are_named_where_the_ast_allows_it() -> None:
    source = load("calls_and_dispatch.py")
    root = parse(source)
    names = [c.name for c in iter_calls(root, source)]
    assert "check_output" in names
    assert "len" in names
    assert "getattr" in names


def test_calls_do_not_invent_a_name_for_an_uncapturable_target() -> None:
    """factory(x)() has no statically nameable callee for the outer call.

    Only `factory(x)` — named `factory` — should appear; there must be no
    second call captured for the anonymous outer invocation.
    """
    source = load("calls_and_dispatch.py")
    root = parse(source)
    fn = next(f for f in iter_functions(root, source) if f.name == "uncapturable_target")
    body = root.descendant_for_byte_range(fn.body_start_byte, fn.end_byte)
    assert body is not None
    names = [c.name for c in iter_calls(body, source)]
    assert names == ["factory"]


def test_dynamic_call_names_covers_the_fixtures_dispatch_case() -> None:
    source = load("calls_and_dispatch.py")
    root = parse(source)
    fn = next(f for f in iter_functions(root, source) if f.name == "dynamic_dispatch")
    body = root.descendant_for_byte_range(fn.body_start_byte, fn.end_byte)
    assert body is not None
    names = {c.name for c in iter_calls(body, source)}
    assert names & DYNAMIC_CALL_NAMES == {"getattr"}


def test_static_calls_trigger_no_dynamic_dispatch() -> None:
    source = load("calls_and_dispatch.py")
    root = parse(source)
    fn = next(f for f in iter_functions(root, source) if f.name == "static_calls")
    body = root.descendant_for_byte_range(fn.body_start_byte, fn.end_byte)
    assert body is not None
    names = {c.name for c in iter_calls(body, source)}
    assert not (names & DYNAMIC_CALL_NAMES)


# -------------------------------------------------------------------- imports


def test_imports_both_statement_forms() -> None:
    source = load("imports_mixed.py")
    imports = iter_imports(parse(source), source)
    by_text = {i.text: i for i in imports}

    assert by_text["import os"].module == "os"
    assert by_text["import subprocess as sp"].module == "subprocess"
    assert by_text["from flask import Flask, request"].module == "flask"
    assert by_text["from flask import Flask, request"].names == ("Flask", "request")


def test_relative_imports_are_captured_even_when_module_is_ambiguous() -> None:
    """`from . import helpers` and a dotted relative import both parse.

    Best-effort module extraction may not fully resolve a relative import to a
    real package, and that is fine here: it is still present in the list for
    a human reviewing `sift context dump`, which is what matters at this layer.
    """
    source = load("imports_mixed.py")
    imports = iter_imports(parse(source), source)
    texts = {i.text for i in imports}
    assert "from . import helpers" in texts
    assert "from ..pkg.module import thing as aliased" in texts


def test_imports_are_ordered_by_line() -> None:
    source = load("imports_mixed.py")
    imports = iter_imports(parse(source), source)
    assert [i.start_line for i in imports] == sorted(i.start_line for i in imports)
