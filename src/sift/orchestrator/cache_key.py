"""D1's cache key: specified in P1, implementable now that ContextBundle is
populated (P3) and the prompts exist (P5).

See docs/ARCHITECTURE.md, "3. Cache key - can I reuse a verdict?":

    sha256(correlation_id, canonical(ContextBundle), model_ids,
           temperature, prompt_version_hashes, sift_version)

Deliberately more sensitive than the correlation ID. A function-body edit
that never touches the flagged line must still change this key, because it
can change the correct verdict - reusing a stale dismissal costs a breach,
re-adjudicating costs cents. When in doubt, change the key.
"""

from __future__ import annotations

import hashlib
import json

from sift.models.context import ContextBundle


def canonical_bundle(bundle: ContextBundle) -> str:
    """Deterministic JSON of the whole bundle, key order normalized.

    The whole bundle, not just the flagged line - see the module docstring.
    """
    return json.dumps(bundle.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


def compute_cache_key(
    *,
    correlation_id: str,
    bundle: ContextBundle,
    model_ids: tuple[str, ...],
    temperature: float,
    prompt_hashes: dict[str, str],
    sift_version: str,
) -> str:
    """The whole D1 cache key in one call, so no caller assembles the payload
    shape by hand and risks getting a field order or a missing input wrong."""
    payload = json.dumps(
        {
            "correlation_id": correlation_id,
            "bundle": canonical_bundle(bundle),
            "model_ids": list(model_ids),
            "temperature": temperature,
            "prompt_hashes": prompt_hashes,
            "sift_version": sift_version,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
