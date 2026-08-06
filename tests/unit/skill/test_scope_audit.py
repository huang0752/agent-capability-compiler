from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "scope_audit.py"


def _route(
    route_id: str,
    *,
    disposition: str = "planned",
    method: str = "GET",
    evidence_sources: list[str] | None = None,
    reason: str | None = None,
    operation_id: str | None = "customer.search",
) -> dict[str, object]:
    return {
        "id": route_id,
        "domain": "customer",
        "method": method,
        "path": f"/api/{route_id.replace('.', '/')}",
        "evidence_sources": (
            ["customer-routes"] if evidence_sources is None else evidence_sources
        ),
        "eligibility": "eligible",
        "disposition": disposition,
        "operation_id": operation_id,
        "capability_ids": ["search_customers"],
        "reason": reason,
    }


def _summary(routes: list[object]) -> dict[str, int]:
    result = {
        "discovered_routes": len(routes),
        "eligible_read_routes": 0,
        "planned": 0,
        "composed": 0,
        "excluded": 0,
        "blocked_on_evidence": 0,
        "out_of_scope": 0,
        "unresolved": 0,
    }
    for route in routes:
        if not isinstance(route, dict):
            result["unresolved"] += 1
            continue
        if route.get("eligibility") == "eligible":
            result["eligible_read_routes"] += 1
        disposition = route.get("disposition")
        if isinstance(disposition, str) and disposition in result:
            result[disposition] += 1
        else:
            result["unresolved"] += 1
    return result


def _write_project(
    tmp_path: Path,
    *,
    mode: str | None = "system_readonly_complete",
    user_confirmation: str | None = None,
    selected_domains: list[str] | None = None,
    routes: list[object] | None = None,
    summary_overrides: dict[str, int] | None = None,
) -> Path:
    project = tmp_path / "acc-project"
    project.mkdir()
    actual_routes: list[object] = (
        routes if routes is not None else [_route("customer.search")]
    )
    scope: dict[str, object] = {
        "user_confirmation": user_confirmation,
        "selected_domains": selected_domains or [],
    }
    if mode is not None:
        scope["mode"] = mode
    summary = _summary(actual_routes)
    summary.update(summary_overrides or {})
    inventory = {
        "schema_version": "1",
        "scope": scope,
        "routes": actual_routes,
        "summary": summary,
    }
    (project / "scope-inventory.yaml").write_text(
        yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8"
    )
    (project / "system-map.yaml").write_text(
        yaml.safe_dump({"candidate_operations": []}), encoding="utf-8"
    )
    (project / "capability-plan.yaml").write_text(
        yaml.safe_dump({"capabilities": []}), encoding="utf-8"
    )
    (project / "coverage-baseline.json").write_text(
        json.dumps({"source_scope": {}}), encoding="utf-8"
    )
    return project


def _run(project: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--project", str(project)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads(completed.stdout) if completed.stdout else {}
    return completed, payload


def test_system_complete_accepts_a_fully_disposed_inventory(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="system_readonly_complete")

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "system_readonly_complete"


def test_pilot_requires_explicit_user_confirmation(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="pilot", user_confirmation=None)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_CONFIRMATION_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/user_confirmation"


def test_system_complete_rejects_out_of_scope_and_evidence_blockers(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", disposition="out_of_scope", reason="not selected"),
            _route(
                "report.get",
                disposition="blocked_on_evidence",
                reason="scope unknown",
            ),
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
        "ACC_SCOPE_EVIDENCE_BLOCKED",
    }


def test_missing_mode_is_rejected(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode=None)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_MODE_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/scope/mode"


def test_confirmed_pilot_is_valid(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="User explicitly approved a bounded pilot.",
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "pilot"


def test_domain_complete_requires_a_selected_domain(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="domain_complete")

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/selected_domains"


def test_route_contract_violations_have_stable_codes(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[
            _route("customer.search"),
            _route(
                "customer.search",
                disposition="excluded",
                method="POST",
                evidence_sources=[],
                reason=None,
            ),
            _route("report.get", operation_id=None),
        ],
        summary_overrides={"planned": 99},
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_ROUTE_DUPLICATE",
        "ACC_SCOPE_METHOD_INVALID",
        "ACC_SCOPE_EVIDENCE_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
        "ACC_SCOPE_OPERATION_REQUIRED",
        "ACC_SCOPE_SUMMARY_MISMATCH",
    }
    assert all(item["path"] == "scope-inventory.yaml" for item in payload["diagnostics"])
    assert all(item["pointer"].startswith("/") for item in payload["diagnostics"])


def test_diagnostics_never_echo_input_secrets(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    project = _write_project(tmp_path, mode=secret)

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_MODE_INVALID"
    assert secret not in completed.stdout
