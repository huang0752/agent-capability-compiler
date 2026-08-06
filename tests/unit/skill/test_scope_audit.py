from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "scope_audit.py"


def _route(
    route_id: str,
    *,
    domain: str = "customer",
    disposition: str = "planned",
    method: str = "GET",
    evidence_sources: list[str] | None = None,
    reason: str | None = None,
    operation_id: str | None = "customer.search",
) -> dict[str, object]:
    return {
        "id": route_id,
        "domain": domain,
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


def _source_scope(routes: list[object]) -> dict[str, int]:
    summary = _summary(routes)
    return {
        "eligible_read_routes": summary["eligible_read_routes"],
        "planned_or_composed": summary["planned"] + summary["composed"],
        "excluded": summary["excluded"],
        "blocked_on_evidence": summary["blocked_on_evidence"],
        "unresolved": summary["unresolved"],
    }


def _write_project(
    tmp_path: Path,
    *,
    mode: str | None = "system_readonly_complete",
    user_confirmation: str | None = None,
    selected_domains: list[str] | None = None,
    declared_domains: list[str] | None = None,
    routes: list[object] | None = None,
    summary_overrides: dict[str, int] | None = None,
    system_operations: list[str] | None = None,
    plan_dependencies: list[str] | None = None,
    baseline_source_scope: dict[str, int] | None = None,
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
        "domains": [
            {"id": domain}
            for domain in (
                declared_domains
                if declared_domains is not None
                else sorted(
                    {
                        str(route["domain"])
                        for route in actual_routes
                        if isinstance(route, dict)
                        and isinstance(route.get("domain"), str)
                        and route["domain"]
                    }
                )
            )
        ],
        "routes": actual_routes,
        "summary": summary,
    }
    (project / "scope-inventory.yaml").write_text(
        yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8"
    )
    operation_ids = sorted(
        {
            str(route["operation_id"])
            for route in actual_routes
            if isinstance(route, dict)
            and route.get("disposition") in {"planned", "composed"}
            and isinstance(route.get("operation_id"), str)
            and route["operation_id"]
        }
    )
    actual_system_operations = (
        operation_ids if system_operations is None else system_operations
    )
    (project / "system-map.yaml").write_text(
        yaml.safe_dump(
            {
                "candidate_operations": [
                    {"id": operation_id}
                    for operation_id in actual_system_operations
                ]
            }
        ),
        encoding="utf-8",
    )
    actual_plan_dependencies = (
        operation_ids if plan_dependencies is None else plan_dependencies
    )
    (project / "capability-plan.yaml").write_text(
        yaml.safe_dump(
            {
                "capabilities": [
                    {"id": "scope-capability", "operation_dependencies": actual_plan_dependencies}
                ]
            }
        ),
        encoding="utf-8",
    )
    (project / "coverage-baseline.json").write_text(
        json.dumps(
            {
                "source_scope": (
                    _source_scope(actual_routes)
                    if baseline_source_scope is None
                    else baseline_source_scope
                )
            }
        ),
        encoding="utf-8",
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


def test_schema_version_must_be_one_without_echoing_input(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    project = _write_project(tmp_path)
    inventory_path = project / "scope-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    inventory["schema_version"] = secret
    inventory_path.write_text(
        yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8"
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_SCHEMA_VERSION_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/schema_version"
    assert secret not in completed.stdout


def test_route_domain_must_be_a_non_empty_string(tmp_path: Path) -> None:
    route = _route("customer.search")
    route["domain"] = ""
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/domain"


@pytest.mark.parametrize(
    "invalid_path",
    [
        "api/customers",
        "//api/customers",
        "/api//customers",
        "/api/customers?limit=1",
        "/api/customers#details",
        "/api\\customers",
        "/api/../customers",
    ],
)
def test_route_path_must_be_a_safe_origin_relative_path(
    tmp_path: Path, invalid_path: str
) -> None:
    route = _route("customer.search")
    route["path"] = invalid_path
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_PATH_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/path"


def test_route_eligibility_must_be_declared_without_echoing_input(tmp_path: Path) -> None:
    secret = "production-secret-never-output"
    route = _route("customer.search")
    route["eligibility"] = secret
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_ELIGIBILITY_INVALID"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/eligibility"
    assert secret not in completed.stdout


@pytest.mark.parametrize("disposition", ["planned", "composed"])
def test_ineligible_routes_cannot_be_planned_or_composed(
    tmp_path: Path, disposition: str
) -> None:
    route = _route("customer.search", disposition=disposition)
    route["eligibility"] = "ineligible"
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_INELIGIBLE_DISPOSITION"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/disposition"


def test_ineligible_routes_are_not_counted_as_eligible(tmp_path: Path) -> None:
    route = _route(
        "customer.search",
        disposition="excluded",
        reason="write-only route",
        operation_id=None,
    )
    route["eligibility"] = "ineligible"
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["result"]["source_scope"]["eligible_read_routes"] == 0


def test_planned_and_composed_routes_must_exist_in_system_map_and_plan(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", operation_id="customer.search"),
            _route(
                "customer.context",
                disposition="composed",
                operation_id="customer.context",
            ),
        ],
        system_operations=[],
        plan_dependencies=[],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert [item["code"] for item in payload["diagnostics"]].count(
        "ACC_SCOPE_SYSTEM_MAP_MISSING_OPERATION"
    ) == 2
    assert [item["code"] for item in payload["diagnostics"]].count(
        "ACC_SCOPE_PLAN_MISSING_OPERATION"
    ) == 2


def test_coverage_baseline_source_scope_must_match_inventory_denominator(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        baseline_source_scope={
            "eligible_read_routes": 99,
            "planned_or_composed": 1,
            "excluded": 0,
            "blocked_on_evidence": 0,
            "unresolved": 0,
        },
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_COVERAGE_MISMATCH"
    assert payload["diagnostics"][0]["path"] == "coverage-baseline.json"
    assert payload["diagnostics"][0]["pointer"] == "/source_scope"


def test_domain_complete_rejects_an_undeclared_selected_domain(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        declared_domains=["report"],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_UNDECLARED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/selected_domains/0"


def test_domain_complete_requires_selected_domain_routes_to_be_complete(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        routes=[
            _route(
                "customer.search",
                disposition="blocked_on_evidence",
                operation_id=None,
                reason="missing permission evidence",
            )
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_INCOMPLETE"
    assert payload["diagnostics"][0]["pointer"] == "/routes/0/disposition"


def test_domain_complete_requires_outside_routes_to_be_explicitly_out_of_scope(
    tmp_path: Path,
) -> None:
    project = _write_project(
        tmp_path,
        mode="domain_complete",
        selected_domains=["customer"],
        routes=[
            _route("customer.search"),
            _route("report.get", domain="report", operation_id="report.get"),
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_DOMAIN_BOUNDARY_AMBIGUOUS"
    assert payload["diagnostics"][0]["pointer"] == "/routes/1/disposition"


@pytest.mark.parametrize(
    ("mode", "confirmation", "selected_domains", "routes"),
    [
        ("pilot", "Approved bounded pilot.", [], [_route("customer.search")]),
        (
            "domain_complete",
            None,
            ["customer"],
            [
                _route("customer.search"),
                _route(
                    "report.get",
                    domain="report",
                    disposition="out_of_scope",
                    operation_id=None,
                    reason="outside selected domain",
                ),
            ],
        ),
        ("system_readonly_complete", None, [], [_route("customer.search")]),
    ],
)
def test_all_three_scope_modes_accept_consistent_artifacts(
    tmp_path: Path,
    mode: str,
    confirmation: str | None,
    selected_domains: list[str],
    routes: list[object],
) -> None:
    project = _write_project(
        tmp_path,
        mode=mode,
        user_confirmation=confirmation,
        selected_domains=selected_domains,
        routes=routes,
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == mode
