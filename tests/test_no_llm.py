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
#: The P4 dataset builder must stay deterministic for the same reason as the
#: context builder: a provider SDK or network client here could spend money
#: or leak finding data during labeling. Same import-graph check.
DATASET_BUILD = Path(__file__).resolve().parents[1] / "evals" / "dataset" / "build.py"

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


def test_dataset_build_script_imports_no_network_or_provider_library() -> None:
    """Same import-graph check as the context builder, extended to the P4
    dataset builder. The 'zero LLM calls' claim is enforced here, not assumed."""
    imported = _imported_modules(DATASET_BUILD.read_text(encoding="utf-8"))
    hit = imported & FORBIDDEN_MODULES
    assert hit == set(), f"network/provider import found in {DATASET_BUILD}: {sorted(hit)}"


def test_dataset_build_runs_with_sockets_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run the real dataset build into a scratch dir with sockets disabled.

    Fails if labeling ever reaches the network (provider SDK, download, phone
    home) even when hidden behind a dynamic import. Also asserts the written
    snapshot files carry no ground-truth markers: no "# finding: TP/FP"
    comment and no tp_/fp_ function name may survive into model-visible code.
    """

    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("socket.socket() was called during dataset construction")

    monkeypatch.setattr(socket, "socket", _forbidden)

    from evals.dataset import build as dataset_build

    snap_dir = tmp_path / "snap"
    assert dataset_build.main(out_dir=tmp_path, snap_dir=snap_dir) == 0

    from sift.eval.dataset import load_dataset

    entries = load_dataset(tmp_path / "dataset.jsonl")
    assert len(entries) >= 100  # the build actually labeled something

    leaks = []
    for path in snap_dir.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "# finding:" in text:
            leaks.append(f"{path.name}: ground-truth marker comment survived")
        for marker in ("def tp_", "def fp_"):
            if marker in text:
                leaks.append(f"{path.name}: label-leaking {marker} function name survived")
    assert leaks == []

    # Twins of a synth pair must share one rule_id (a scanner rule fires on the
    # sink, not the outcome), and the alpha_/beta_ name must not encode the
    # label: both assignments occur across files.
    from collections import defaultdict

    by_file: dict[str, list[str]] = defaultdict(list)
    alpha_is_tp: set[bool] = set()
    for e in entries:
        if not e.id.startswith("synth-"):
            continue
        by_file[e.path].append(e.rule_id)
        src_lines = (snap_dir / Path(e.path).name).read_text(encoding="utf-8").splitlines()
        enclosing = next(ln for ln in src_lines[: e.line][::-1] if ln.startswith("def "))
        if e.ground_truth.value == "TRUE_POSITIVE":
            alpha_is_tp.add(enclosing.startswith("def alpha_"))
    assert all(len(set(rules)) == 1 for rules in by_file.values()), (
        "synth twins with different rule_ids: "
        + str({k: v for k, v in by_file.items() if len(set(v)) != 1})
    )
    assert alpha_is_tp == {True, False}, "alpha_ name correlates with the label"
