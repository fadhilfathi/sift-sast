"""End-to-end `sift triage` real-run wiring, against a fake `complete_fn`.

Zero live model calls - see tests/conftest.py. This proves the CLI actually
drives Stage 1 through Stage 4 for real (not just --dry-run's estimate),
using a small hand-built SARIF result against the real python_project
fixture the orchestrator tests already use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sift.cli as cli_module
from sift.cli import app
from sift.llm.provider import ChatMessage, ProviderConfig, ProviderResponse

PROJECT = Path(__file__).resolve().parent / "fixtures" / "python_project"

_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "sift-test", "rules": []}},
            "results": [
                {
                    "ruleId": "sift-test/command-injection",
                    "message": {"text": "shell=True with untrusted input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 27},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

_ANALYST = {
    "position": "TRUE_POSITIVE",
    "confidence": 0.9,
    "reasoning": "reaches the sink",
    "evidence_lines": [{"path": "src/app.py", "line": 26}],
    "unresolved_questions": [],
}
_ADVERSARY = {
    "position": "TRUE_POSITIVE",
    "confidence": 0.8,
    "reasoning": "unconfirmed sanitizer",
    "evidence_lines": [{"path": "src/app.py", "line": 26}],
    "objections": [
        {"claim": "no sanitizer confirmed", "evidence": [{"path": "src/app.py", "line": 26}]}
    ],
    "unresolved_questions": [],
}
_ADJUDICATOR = {
    "verdict": "TRUE_POSITIVE",
    "confidence": 0.9,
    "justification": "reaches shell=True with no mitigation",
    "evidence_lines": [{"path": "src/app.py", "line": 26}],
    "unresolved_questions": [],
    "open_objections": [],
}


def _fake_complete(
    config: ProviderConfig, messages: list[ChatMessage], *, model: object = None
) -> ProviderResponse:
    instructions = messages[-1].content
    if instructions.startswith("You are the REACHABILITY") or instructions.startswith(
        "You are the EXPLOITABILITY"
    ):
        payload = _ANALYST
    elif instructions.startswith("You are the ADVERSARY"):
        payload = _ADVERSARY
    else:
        payload = _ADJUDICATOR
    return ProviderResponse(
        content=json.dumps(payload),
        model="x/y",
        prompt_tokens=100,
        completion_tokens=50,
        cost_usd=0.001,
    )


def test_real_triage_run_produces_a_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIFT_API_KEY", "fake-key-for-this-test")
    monkeypatch.setattr(cli_module, "complete", _fake_complete)

    sarif_path = tmp_path / "in.sarif"
    sarif_path.write_text(json.dumps(_SARIF), encoding="utf-8")
    out = tmp_path / "out.sarif"
    report = tmp_path / "report.json"
    comment = tmp_path / "comment.md"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "triage",
            str(sarif_path),
            "--repo",
            str(PROJECT),
            "--out",
            str(out),
            "--report-out",
            str(report),
            "--comment-out",
            str(comment),
        ],
    )
    assert result.exit_code == 0, result.output

    annotated = json.loads(out.read_text(encoding="utf-8"))
    sift_props = annotated["runs"][0]["results"][0]["properties"]["sift/v1"]
    assert sift_props["verdict"] == "TRUE_POSITIVE"
    assert sift_props["adversary_objection_count"] == 1

    report_data = json.loads(report.read_text(encoding="utf-8"))
    assert report_data["adjudicated"] == 1
    assert report_data["verdict_counts"]["TRUE_POSITIVE"] == 1

    comment_text = comment.read_text(encoding="utf-8")
    assert "Adjudicated TRUE_POSITIVE (1)" in comment_text
    comment_text.encode("ascii")
