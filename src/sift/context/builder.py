"""Assembles one `ContextBundle` per finding. tree-sitter and file reads only.

Every read goes through `sift.paths` for traversal safety. Every retrieved
span is redacted before it is attached to the bundle. Nothing here calls a
model, and `tests/test_no_llm.py` enforces that at the module level, not just
by convention.

Scope, stated rather than hidden: this is a best-effort Python builder, not a
whole-program analysis. Caller and callee resolution search the files under
the repo root by name, which can both miss a dynamically-constructed call and
occasionally match an unrelated same-named function elsewhere in the project.
That imprecision is exactly why D6's completeness signal exists — a bundle
built this way must say what it is unsure of, not present a guess as fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sift.context import queries
from sift.context.queries import CallExpr, FunctionDef
from sift.context.redact import redact_span
from sift.ingest.fingerprint import FindingRef
from sift.models.context import (
    CallerSearch,
    CallSite,
    CodeSpan,
    CompletenessReason,
    ContextBundle,
    EntrypointKind,
    Reachability,
    RedactedSecret,
    SanitizerCall,
    TruncatedCaller,
    completeness_from,
)
from sift.models.verdict import FileLineRef
from sift.paths import UnsafePathError, read_text_full, resolve
from sift.prefilter.classify import classify

#: See decision D7 in docs/ARCHITECTURE.md. Direct caller, and one hop beyond
#: it — deeper reachability reasoning is Reachability's targeted entrypoint
#: search, not a wider breadth-first walk of this list.
HOP_LIMIT = 2

#: Total CodeSpans materialized across the whole caller-graph walk, shared
#: across both hops rather than a per-hop cap that would multiply out.
SPAN_BUDGET = 20

#: Above this many direct callers, the search is refused rather than
#: partially sampled — see D7 for why partial enumeration would be worse than
#: an honest refusal here.
DIRECT_CALLER_REFUSE_THRESHOLD = 50

#: Decorator text fragments recognized as marking an entrypoint. Matched as a
#: substring of the decorator's own source text — a best-effort heuristic,
#: not a framework-aware parser. A decorator this misses simply leaves
#: entrypoint_kind at UNKNOWN and externally_reachable at None; it is never
#: read as "not an entrypoint".
_ENTRYPOINT_DECORATORS: tuple[tuple[str, EntrypointKind], ...] = (
    (".route(", EntrypointKind.HTTP_HANDLER),
    (".get(", EntrypointKind.HTTP_HANDLER),
    (".post(", EntrypointKind.HTTP_HANDLER),
    (".put(", EntrypointKind.HTTP_HANDLER),
    (".delete(", EntrypointKind.HTTP_HANDLER),
    (".patch(", EntrypointKind.HTTP_HANDLER),
    ("@app.", EntrypointKind.HTTP_HANDLER),
    ("click.command", EntrypointKind.CLI_ARGUMENT),
    ("app.cli.command", EntrypointKind.CLI_ARGUMENT),
    (".task(", EntrypointKind.QUEUE_CONSUMER),
    ("celery", EntrypointKind.QUEUE_CONSUMER),
)

#: Known-safe functions, matched by bare call name. `confirmed=True` is only
#: ever set for one of these OR a project-defined function whose own body was
#: actually read (see `_check_sanitizers`) — never for an unresolved name that
#: merely looks like a sanitizer.
_TRUSTED_SANITIZER_NAMES = frozenset({"quote", "escape", "quote_plus", "shlex_quote"})

#: How many files the project scan will look at. Bounded so a caller search
#: against an enormous checkout cannot become the slow stage; exceeding it is
#: not itself a correctness problem since caller search is best-effort already.
MAX_PROJECT_FILES = 500


@dataclass
class _Ctx:
    """Mutable state threaded through one bundle build. Not exported."""

    repo_root: Path
    reasons: set[CompletenessReason]
    redactions: list[RedactedSecret]
    spans_used: int = 0


def _project_python_files(repo_root: Path) -> list[Path]:
    """Every .py file under the repo root, vendored/generated dirs skipped.

    Skipping them is a relevance and performance improvement, not a
    correctness requirement — classify() is already trusted for this in
    Stage 1, so this reuses it rather than re-deriving the same rule.
    """
    files = []
    for path in sorted(repo_root.rglob("*.py")):
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError:  # pragma: no cover - rglob always yields children
            continue
        found = classify(relative)
        if found.file_class.value in ("VENDORED", "GENERATED"):
            continue
        files.append(path)
        if len(files) >= MAX_PROJECT_FILES:
            break
    return files


def _make_span(ctx: _Ctx, path: str, source: bytes, fn: FunctionDef) -> CodeSpan:
    """A redacted CodeSpan for one function definition."""
    span = CodeSpan(
        path=path,
        start_line=fn.start_line,
        end_line=fn.end_line,
        source=source[fn.start_byte : fn.end_byte].decode("utf-8", errors="replace"),
        symbol=fn.name,
        language="python",
    )
    redacted, secrets = redact_span(span)
    ctx.redactions.extend(secrets)
    ctx.spans_used += 1
    return redacted


def _entrypoint_kind(decorators: tuple[str, ...]) -> EntrypointKind | None:
    for decorator in decorators:
        for needle, kind in _ENTRYPOINT_DECORATORS:
            if needle in decorator:
                return kind
    return None


@dataclass(frozen=True)
class _CallerHit:
    path: str
    source: bytes
    fn: FunctionDef
    call_line: int


def _find_callers(name: str, files: list[Path], repo_root: Path) -> list[_CallerHit]:
    """Every distinct function, across `files`, containing a call to `name`.

    Deterministic file and byte order, never a random sample — see D7 on why
    that matters for reproducibility across identical runs.
    """
    hits: dict[tuple[str, int, int], _CallerHit] = {}
    for file_path in files:
        text = read_text_full(file_path)
        if text is None:
            continue
        source = text.encode("utf-8")
        root = queries.parse(source)
        relative = file_path.relative_to(repo_root).as_posix()
        calls = [c for c in queries.iter_calls(root, source) if c.name == name]
        for call in calls:
            enclosing = queries.enclosing_function(root, source, call.start_line)
            if enclosing is None or enclosing.name == name:
                continue  # a call to itself (recursion) is not a distinct caller
            key = (relative, enclosing.start_byte, enclosing.end_byte)
            if key not in hits:
                hits[key] = _CallerHit(
                    path=relative, source=source, fn=enclosing, call_line=call.start_line
                )
    return sorted(hits.values(), key=lambda h: (h.path, h.fn.start_byte))


def _walk_callers(
    ctx: _Ctx, target_name: str, files: list[Path], exclude_key: tuple[str, int, int]
) -> tuple[list[CallSite], CallerSearch, EntrypointKind | None, CodeSpan | None]:
    """The full D7 traversal: hop 1, refuse/truncate accounting, then hop 2.

    The span budget is scoped to this walk alone, not the whole bundle: it is
    reset to zero on entry so spans already spent on the enclosing function,
    callee definitions, or sanitizer resolution do not eat into "20 CodeSpans
    across the caller graph" before the caller graph has looked at anything.
    """
    ctx.spans_used = 0
    search = CallerSearch(hop_limit=HOP_LIMIT, span_budget=SPAN_BUDGET)
    call_sites: list[CallSite] = []
    entrypoint_kind: EntrypointKind | None = None
    entrypoint_span: CodeSpan | None = None

    hop1 = [
        h
        for h in _find_callers(target_name, files, ctx.repo_root)
        if (h.path, h.fn.start_byte, h.fn.end_byte) != exclude_key
    ]
    if len(hop1) > DIRECT_CALLER_REFUSE_THRESHOLD:
        search.refused = True
        search.direct_caller_count = len(hop1)
        ctx.reasons.add(CompletenessReason.CALLER_SEARCH_REFUSED)
        search.spans_used = ctx.spans_used
        return call_sites, search, entrypoint_kind, entrypoint_span

    frontier: list[tuple[_CallerHit, int]] = [(h, 1) for h in hop1]
    visited_keys = {exclude_key}
    index = 0
    while index < len(frontier):
        hit, hop = frontier[index]
        index += 1
        key = (hit.path, hit.fn.start_byte, hit.fn.end_byte)
        if key in visited_keys:
            continue
        visited_keys.add(key)

        if ctx.spans_used >= search.span_budget:
            search.truncated = True
            ctx.reasons.add(CompletenessReason.CALLER_SEARCH_TRUNCATED)
            remaining = [f for f, h in frontier[index - 1 :]]
            search.truncated_at.append(
                TruncatedCaller(
                    symbol=target_name,
                    path=hit.path,
                    callers_found=len(remaining) + 1,
                    callers_kept=0,
                )
            )
            break

        span = _make_span(ctx, hit.path, hit.source, hit.fn)
        call_sites.append(CallSite(caller=span, call_line=hit.call_line, hops_from_finding=hop))

        found_kind = _entrypoint_kind(hit.fn.decorators)
        if found_kind is not None and entrypoint_kind is None:
            entrypoint_kind = found_kind
            entrypoint_span = span

        if hop < HOP_LIMIT and ctx.spans_used < search.span_budget:
            deeper = [
                h
                for h in _find_callers(hit.fn.name, files, ctx.repo_root)
                if (h.path, h.fn.start_byte, h.fn.end_byte) not in visited_keys
            ]
            frontier.extend((h, hop + 1) for h in deeper)

    search.spans_used = ctx.spans_used
    return call_sites, search, entrypoint_kind, entrypoint_span


def _check_sanitizers(
    ctx: _Ctx, callees: list[CallExpr], files: list[Path], path: str
) -> list[SanitizerCall]:
    """Best-effort: a call named like a sanitizer, confirmed only if resolved.

    `confirmed=True` only for a fixed, small set of well-known trusted
    functions matched by bare name, or a project-defined function whose body
    was actually read. A name that merely looks like a sanitizer — matched by
    neither path — stays `confirmed=False`: visible, not trusted.
    """
    sanitizers = []
    for call in callees:
        location = FileLineRef(path=path, line=call.start_line)
        if call.name in _TRUSTED_SANITIZER_NAMES:
            sanitizers.append(SanitizerCall(name=call.name, location=location, confirmed=True))
            continue
        resolved = _resolve_definition(ctx, call.name, files)
        if resolved is not None:
            sanitizers.append(
                SanitizerCall(
                    name=call.name, location=location, definition=resolved, confirmed=True
                )
            )
    return sanitizers


def _resolve_definition(ctx: _Ctx, name: str, files: list[Path]) -> CodeSpan | None:
    """The first project-defined function named `name`, if any file defines one."""
    for file_path in files:
        text = read_text_full(file_path)
        if text is None:
            continue
        source = text.encode("utf-8")
        root = queries.parse(source)
        for fn in queries.iter_functions(root, source):
            if fn.name == name:
                relative = file_path.relative_to(ctx.repo_root).as_posix()
                return _make_span(ctx, relative, source, fn)
    return None


def build_context_bundle(finding: FindingRef, repo_root: Path) -> ContextBundle:
    """Assemble a `ContextBundle` for one finding. Never raises on bad input.

    A finding whose file cannot be safely resolved or read still produces a
    bundle — `INSUFFICIENT`, with the reason recorded — because a missing
    bundle is indistinguishable from one nobody built yet, and this must be
    distinguishable from that.
    """
    ctx = _Ctx(repo_root=repo_root, reasons=set(), redactions=[])
    flagged = FileLineRef(path=finding.uri or "", line=finding.start_line or 1)

    base_kwargs: dict[str, object] = {
        "correlation_id": finding.correlation_id,
        "rule_id": finding.rule_id or "",
        "message": "",
        "flagged": flagged,
        "caller_search": CallerSearch(hop_limit=HOP_LIMIT, span_budget=SPAN_BUDGET),
    }

    if not finding.uri:
        ctx.reasons.add(CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED)
        return ContextBundle(
            **base_kwargs,
            completeness=completeness_from(ctx.reasons, externally_reachable=None),
            completeness_reasons=sorted(ctx.reasons),
        )

    try:
        real_path = resolve(repo_root, finding.uri)
    except UnsafePathError:
        ctx.reasons.add(CompletenessReason.PATH_TRAVERSAL_REFUSED)
        ctx.reasons.add(CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED)
        return ContextBundle(
            **base_kwargs,
            completeness=completeness_from(ctx.reasons, externally_reachable=None),
            completeness_reasons=sorted(ctx.reasons),
        )

    file_class = classify(finding.uri, repo_root).file_class
    text = read_text_full(real_path)
    if text is None:
        ctx.reasons.add(CompletenessReason.FILE_UNREADABLE)
        ctx.reasons.add(CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED)
        return ContextBundle(
            **base_kwargs,
            file_class=file_class,
            completeness=completeness_from(ctx.reasons, externally_reachable=None),
            completeness_reasons=sorted(ctx.reasons),
        )

    source = text.encode("utf-8")
    root = queries.parse(source)
    relative_path = finding.uri
    imports = [i.text for i in queries.iter_imports(root, source)]

    enclosing_fn = queries.enclosing_function(root, source, flagged.line)
    if enclosing_fn is None:
        ctx.reasons.add(CompletenessReason.ENCLOSING_FUNCTION_UNRESOLVED)
        return ContextBundle(
            **base_kwargs,
            file_class=file_class,
            imports=imports,
            completeness=completeness_from(ctx.reasons, externally_reachable=None),
            completeness_reasons=sorted(ctx.reasons),
        )

    enclosing_span = _make_span(ctx, relative_path, source, enclosing_fn)

    body_node = root.descendant_for_byte_range(enclosing_fn.body_start_byte, enclosing_fn.end_byte)
    callees = queries.iter_calls(body_node, source) if body_node is not None else []
    if any(c.name in queries.DYNAMIC_CALL_NAMES for c in callees):
        ctx.reasons.add(CompletenessReason.DYNAMIC_DISPATCH)

    files = _project_python_files(repo_root)

    called_definitions: list[CodeSpan] = []
    for callee_name in dict.fromkeys(c.name for c in callees):  # de-duplicated, order preserved
        defn = _resolve_definition(ctx, callee_name, files)
        if defn is not None:
            called_definitions.append(defn)

    sanitizers = _check_sanitizers(ctx, callees, files, relative_path)

    exclude_key = (relative_path, enclosing_fn.start_byte, enclosing_fn.end_byte)
    call_sites, caller_search, entry_kind, entry_span = _walk_callers(
        ctx, enclosing_fn.name, files, exclude_key
    )

    if entry_kind is None:
        entry_kind = _entrypoint_kind(enclosing_fn.decorators)
        if entry_kind is not None:
            entry_span = enclosing_span

    # True when a decorator-recognized entrypoint was found on the path;
    # otherwise None, never False. A function with zero callers found in the
    # scanned project might still be imported and called from outside that
    # scan entirely, so absence of a caller cannot be turned into proof of
    # unreachability - only a positive entrypoint match can be a positive
    # answer here.
    externally_reachable = True if entry_kind is not None else None

    reachability = Reachability(
        entrypoint_kind=entry_kind or EntrypointKind.UNKNOWN,
        entrypoint=entry_span,
        path_from_entrypoint=list(reversed(call_sites)) if entry_kind is not None else [],
        externally_reachable=externally_reachable,
        notes=(
            ["reached the direct-caller refuse threshold; entrypoint search did not run further"]
            if caller_search.refused
            else []
        ),
    )

    reasons = set(ctx.reasons)
    completeness = completeness_from(reasons, externally_reachable=externally_reachable)

    return ContextBundle(
        correlation_id=finding.correlation_id,
        rule_id=finding.rule_id or "",
        message="",
        flagged=flagged,
        enclosing_function=enclosing_span,
        callers=call_sites,
        caller_search=caller_search,
        called_definitions=called_definitions,
        file_class=file_class,
        imports=imports,
        sanitizers=sanitizers,
        reachability=reachability,
        redactions=ctx.redactions,
        completeness=completeness,
        completeness_reasons=sorted(reasons),
    )
