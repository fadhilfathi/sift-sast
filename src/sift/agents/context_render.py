"""Shared placeholder rendering for the P5 analyst prompts.

One function so the four analyst templates (reachability, exploitability,
adversary, adjudicator) cannot drift apart on how a `ContextBundle` field is
formatted. Reads spans only through `as_untrusted_block()` (D9), never
`.source` directly.
"""

from __future__ import annotations

from sift.models.context import ContextBundle


def common_bundle_fields(bundle: ContextBundle) -> dict[str, object]:
    """Every placeholder shared by the P5 analyst prompt templates."""
    sanitizers = [s.name for s in bundle.sanitizers] or ["none-confirmed"]
    context_block = "\n\n".join(s.as_untrusted_block() for s in bundle.all_spans()) or (
        "(no spans retrieved)"
    )
    data_flow = (
        "\n".join(
            f"{st.order}: {st.location.path}:{st.location.line} {st.source_line}"
            for st in bundle.data_flow
        )
        or "(none provided)"
    )
    return {
        "rule_id": bundle.rule_id,
        "message": bundle.message or bundle.rule_id,
        "file_class": bundle.file_class.value,
        "completeness": bundle.completeness.value,
        "completeness_reasons": ",".join(r.value for r in bundle.completeness_reasons) or "none",
        "externally_reachable": bundle.reachability.externally_reachable,
        "entrypoint_kind": bundle.reachability.entrypoint_kind.value,
        "caller_search_refused": bundle.caller_search.refused,
        "caller_search_truncated": bundle.caller_search.truncated,
        "direct_caller_count": bundle.caller_search.direct_caller_count,
        "sanitizers": ",".join(sanitizers),
        "imports": ",".join(bundle.imports) or "none",
        "context_block": context_block,
        "data_flow": data_flow,
    }
