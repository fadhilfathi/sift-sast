"""D1's cache key: sensitive to the whole bundle, not just the flagged line.

See docs/ARCHITECTURE.md's stability matrix - this is the code that has to
actually produce those rows.
"""

from __future__ import annotations

from pathlib import Path

from sift.context.builder import build_context_bundle
from sift.ingest.fingerprint import FindingRef, IdentitySource
from sift.models.context import ContextBundle
from sift.orchestrator.cache_key import compute_cache_key

PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"


def _bundle(start_line: int = 27) -> ContextBundle:
    finding = FindingRef(
        correlation_id="cache-key-test",
        identity_source=IdentitySource.CONTENT,
        run_index=0,
        result_index=0,
        rule_id="sift-test/command-injection",
        uri="src/app.py",
        start_line=start_line,
    )
    return build_context_bundle(finding, PROJECT)


def _key(**overrides: object) -> str:
    base: dict[str, object] = {
        "correlation_id": "c1",
        "bundle": _bundle(),
        "model_ids": ("a", "b", "c", "d"),
        "temperature": 0.0,
        "prompt_hashes": {"reachability.txt": "abc"},
        "sift_version": "0.0.0",
    }
    return compute_cache_key(**(base | overrides))  # type: ignore[arg-type]


def test_same_inputs_produce_the_same_key() -> None:
    assert _key() == _key()


def test_different_correlation_id_changes_the_key() -> None:
    assert _key(correlation_id="c1") != _key(correlation_id="c2")


def test_different_model_ids_change_the_key() -> None:
    assert _key(model_ids=("a", "b", "c", "d")) != _key(model_ids=("x", "b", "c", "d"))


def test_different_temperature_changes_the_key() -> None:
    assert _key(temperature=0.0) != _key(temperature=0.5)


def test_different_prompt_hash_changes_the_key() -> None:
    assert _key(prompt_hashes={"a": "1"}) != _key(prompt_hashes={"a": "2"})


def test_different_sift_version_changes_the_key() -> None:
    assert _key(sift_version="0.0.0") != _key(sift_version="0.0.1")


def test_key_is_a_hex_sha256() -> None:
    key = _key()
    assert len(key) == 64
    assert all(c in "0123456789abcdef" for c in key)
