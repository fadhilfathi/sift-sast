"""The naive single-prompt baseline's prompt assembly (P4 step 5, Run A).

One function, shared by the pilot runner and the render test, so the tested
path and the run path cannot drift apart. Reads spans only through
`as_untrusted_block()` (D9), never `.source` directly.
"""

from __future__ import annotations

from sift.models.context import ContextBundle


def render_baseline_prompt(template: str, bundle: ContextBundle) -> str:
    """Fill every `{placeholder}` in the baseline template from the bundle."""
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
    return template.format(
        rule_id=bundle.rule_id,
        message=bundle.message or bundle.rule_id,
        file_class=bundle.file_class.value,
        completeness=bundle.completeness.value,
        completeness_reasons=",".join(r.value for r in bundle.completeness_reasons) or "none",
        externally_reachable=bundle.reachability.externally_reachable,
        entrypoint_kind=bundle.reachability.entrypoint_kind.value,
        sanitizers=",".join(sanitizers),
        imports=",".join(bundle.imports) or "none",
        context_block=context_block,
        data_flow=data_flow,
    )
