"""Stage 2 makes zero LLM calls. Enforced, not assumed.

Two independent checks: a static sweep for any network-capable or
provider-SDK import in the context-builder modules, and a dynamic run of the
whole builder with socket creation disabled, so a call hidden behind a
dynamic import or a string-built module name would still be caught.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

from sift.context.builder import build_context_bundle
from sift.ingest.fingerprint import FindingRef, IdentitySource

CONTEXT_SRC = Path(__file__).resolve().parents[1] / "src" / "sift" / "context"
PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"

#: Any of these appearing as an import anywhere under src/sift/context/ means
#: a provider SDK or raw network client snuck into a stage that must stay
#: deterministic. Not a prompt-content check - an import-graph check.
FORBIDDEN_MODULES = frozenset(
    {
        "anthropic",
        "openai",
        "httpx",
        "requests",
        "aiohttp",
        "urllib.request",
        "http.client",
        "socket",
    }
)


def _imported_modules(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_context_module_imports_a_network_or_provider_library() -> None:
    offenders = []
    for path in CONTEXT_SRC.rglob("*.py"):
        imported = _imported_modules(path.read_text(encoding="utf-8"))
        hit = imported & FORBIDDEN_MODULES
        if hit:
            offenders.append(f"{path.relative_to(CONTEXT_SRC.parents[2])}: {sorted(hit)}")
    assert offenders == [], "network/provider import found in src/sift/context/:\n" + "\n".join(
        offenders
    )


def test_build_context_bundle_never_opens_a_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the real builder over the real fixture project with sockets disabled.

    If anything in the call graph — tree-sitter, redaction, path resolution —
    ever tried to reach the network, this raises before the attempt completes.
    """

    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("socket.socket() was called during context building")

    monkeypatch.setattr(socket, "socket", _forbidden)

    finding = FindingRef(
        correlation_id="x",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="r",
        uri="src/app.py",
        start_line=27,
    )
    bundle = build_context_bundle(finding, PROJECT)
    assert bundle.enclosing_function is not None  # the run actually did something
