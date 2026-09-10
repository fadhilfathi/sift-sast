"""The Adjudicator's prompt assembly (P5).

Renders the three analyst arguments with `role` stripped — the Adjudicator
sees ARGUMENT A/B/C in caller-supplied order, never which analyst produced
which. Order is the orchestrator's concern, not this module's.
"""

from __future__ import annotations

from sift.agents.context_render import common_bundle_fields
from sift.models.context import ContextBundle
from sift.models.verdict import AdversaryOutput, AnalystOutput

#: What the Adjudicator ever sees: the raw parsed model output, which never
#: carried a `role` field to begin with. Nothing is "stripped" at this point
#: because nothing identifying was ever attached — see AnalystOutput /
#: AdversaryOutput in sift.models.verdict.
AgentOutput = AnalystOutput | AdversaryOutput


def render_argument(output: AgentOutput) -> str:
    """One agent's raw output as prompt text. No role, no identity."""
    evidence = (
        "\n".join(f"  - {ref.path}:{ref.line}" for ref in output.evidence_lines) or "  (none cited)"
    )
    if isinstance(output, AdversaryOutput):
        objections = (
            "\n".join(
                f"  - claim: {o.claim}\n"
                f"    evidence: "
                f"{', '.join(f'{r.path}:{r.line}' for r in o.evidence) or '(none cited)'}"
                for o in output.objections
            )
            or "  (none filed)"
        )
    else:
        objections = "  (not applicable - only the Adversary files objections)"
    unresolved = "\n".join(f"  - {q}" for q in output.unresolved_questions) or "  (none)"
    return (
        f"position: {output.position.value}\n"
        f"confidence: {output.confidence:.2f}\n"
        f"reasoning: {output.reasoning}\n"
        f"evidence_lines:\n{evidence}\n"
        f"objections:\n{objections}\n"
        f"unresolved_questions:\n{unresolved}"
    )


def render_adjudicator_prompt(
    template: str, bundle: ContextBundle, arguments: list[AgentOutput]
) -> str:
    """Fill every `{placeholder}` in the adjudicator template.

    `arguments` must be exactly 3, in the order the caller wants labeled
    A/B/C — this function does not shuffle or otherwise choose that order.
    """
    if len(arguments) != 3:
        raise ValueError(f"adjudicator needs exactly 3 arguments, got {len(arguments)}")
    fields = common_bundle_fields(bundle)
    fields["argument_a"] = render_argument(arguments[0])
    fields["argument_b"] = render_argument(arguments[1])
    fields["argument_c"] = render_argument(arguments[2])
    return template.format(**fields)
