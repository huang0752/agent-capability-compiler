from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from acc_core.cli.main import EXIT_INPUT, EXIT_SUCCESS, main

FIXTURE = Path("tests/fixtures/domains/content")


def _project(tmp_path: Path) -> Path:
    target = tmp_path / "content"
    shutil.copytree(FIXTURE, target)
    return target


def _intent_plan() -> dict[str, object]:
    proven = {
        "status": "proven",
        "rationale": "The source contract proves this safety boundary.",
        "evidence_refs": ["content-source-contract"],
    }
    return {
        "schema_version": "2",
        "intents": [
            {
                "id": "content.transition",
                "domain_id": "content_publication",
                "resource": "content",
                "user_goal": "Transition content to a permitted publication state.",
                "route_ids": [
                    "GET /content/{entity_id}",
                    "PATCH /content/{entity_id}/transition",
                ],
                "interaction_ids": [],
                "candidate_ids": ["content.transition"],
                "capability_ids": ["content.transition"],
                "kind": "action",
                "effect": "transition",
                "rationale": {
                    "summary": "One bounded goal owns preview and mutation.",
                    "compose": "The read establishes state for the transition.",
                },
                "evidence": [
                    {
                        "evidence_ref": "content-source-contract",
                        "supports": "Route dependency and Action lifecycle.",
                    }
                ],
                "confidence": "high",
                "gaps": [],
                "recommendation": "compose",
                "action_safety": {
                    "authorization": proven,
                    "idempotency": proven,
                    "concurrency": proven,
                    "approval": proven,
                    "outcome_resolution": proven,
                },
            }
        ],
        "relationships": [],
    }


def test_intents_brief_exposes_full_denominator_without_a_quantity_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _project(tmp_path)

    assert main(["intents", "brief", str(project), "--json"]) == EXIT_SUCCESS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["ok"] is True
    result = payload["result"]
    assert result["denominator"]["total_route_count"] == 2
    assert len(result["routes"]) == 2
    assert result["planning_contract"]["fixed_tool_quota"] == "forbidden"
    assert result["planning_contract"]["route_per_tool_default"] == "forbidden"
    assert "tool_count" not in result["planning_contract"]


def test_intents_audit_reports_actual_projection_after_ai_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _project(tmp_path)
    (project / "intent-plan.yaml").write_text(
        yaml.safe_dump(_intent_plan(), sort_keys=False), encoding="utf-8"
    )

    assert main(["intents", "audit", str(project), "--json"]) == EXIT_SUCCESS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["result"]["accepted"] is True
    assert payload["result"]["intent_count"] == 1
    assert payload["result"]["recommendation_counts"] == {"compose": 1}
    assert payload["result"]["route_accounting"]["discovered"] == 2
    assert payload["result"]["route_accounting"]["unassigned"] == []
    assert payload["result"]["portfolio"]["projected_mcp_tool_count"] == 4
    assert payload["result"]["portfolio"]["quantity_target"] is None


def test_intents_audit_fails_closed_without_ai_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _project(tmp_path)

    assert main(["intents", "audit", str(project), "--json"]) == EXIT_INPUT
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["ok"] is False
    assert {item["code"] for item in payload["diagnostics"]} == {"ACC_INTENT_PLAN_REQUIRED"}


def test_intents_brief_remains_available_to_repair_an_invalid_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = _project(tmp_path)
    (project / "intent-plan.yaml").write_text(
        "schema_version: '2'\nintents: []\nrelationships: []\n", encoding="utf-8"
    )

    assert main(["intents", "brief", str(project), "--json"]) == EXIT_SUCCESS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["result"]["existing_intent_plan"] is True
    assert payload["result"]["existing_intent_plan_valid"] is False
    assert payload["result"]["existing_intent_plan_diagnostics"][0]["code"] == (
        "ACC_SCHEMA_INVALID"
    )
