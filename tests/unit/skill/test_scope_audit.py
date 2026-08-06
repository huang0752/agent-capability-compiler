from __future__ import annotations

import json
import runpy
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
    eligibility: str = "eligible",
    usage_evidence_sources: list[str] | None = None,
    exclusion_rule_id: str | None = None,
    exclusion_decision: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": route_id,
        "domain": domain,
        "method": method,
        "path": f"/api/{route_id.replace('.', '/')}",
        "evidence_sources": (["customer-routes"] if evidence_sources is None else evidence_sources),
        "eligibility": eligibility,
        "disposition": disposition,
        "operation_id": operation_id,
        "capability_ids": ["search_customers"],
        "reason": reason,
        **(
            {"usage_evidence_sources": usage_evidence_sources}
            if usage_evidence_sources is not None
            else {}
        ),
        **({"exclusion_rule_id": exclusion_rule_id} if exclusion_rule_id is not None else {}),
        **({"exclusion_decision": exclusion_decision} if exclusion_decision is not None else {}),
    }


def _decision(
    rationale: str,
    *,
    evidence_sources: list[str] | None = None,
    capability_ids: list[str] | None = None,
    replacement_route_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "rationale": rationale,
        "evidence_sources": ["route-decision"] if evidence_sources is None else evidence_sources,
        "capability_ids": [] if capability_ids is None else capability_ids,
        "replacement_route_ids": ([] if replacement_route_ids is None else replacement_route_ids),
    }


def _rule(
    rule_id: str,
    route_ids: list[str],
    *,
    category: str = "binary_or_download",
    rationale: str = "Shared technical exclusion",
    evidence_sources: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": rule_id,
        "category": category,
        "route_ids": route_ids,
        "rationale": rationale,
        "evidence_sources": ["rule-evidence"] if evidence_sources is None else evidence_sources,
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
    summary = _summary(
        [
            route
            for route in routes
            if isinstance(route, dict) and route.get("eligibility") == "eligible"
        ]
    )
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
    exclusion_rules: list[dict[str, object]] | None = None,
    approved_route_ids: list[str] | None = None,
    approval_text: str | None = None,
    system_operation_records: list[dict[str, object]] | None = None,
    plan_capabilities: list[dict[str, object]] | None = None,
) -> Path:
    project = tmp_path / "acc-project"
    project.mkdir()
    actual_routes: list[object] = routes if routes is not None else [_route("customer.search")]
    scope: dict[str, object] = {
        "user_confirmation": user_confirmation,
        "selected_domains": selected_domains or [],
    }
    if mode is not None:
        scope["mode"] = mode
    if approved_route_ids is not None or approval_text is not None:
        scope["exclusion_approval"] = {
            "approved_route_ids": approved_route_ids or [],
            "approval_text": approval_text,
        }
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
        "exclusion_rules": exclusion_rules or [],
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
    actual_system_operations = operation_ids if system_operations is None else system_operations
    route_ids_by_operation: dict[str, list[str]] = {}
    for route in actual_routes:
        if not isinstance(route, dict):
            continue
        operation_id = route.get("operation_id")
        route_id = route.get("id")
        if (
            route.get("disposition") in {"planned", "composed"}
            and isinstance(operation_id, str)
            and isinstance(route_id, str)
        ):
            route_ids_by_operation.setdefault(operation_id, []).append(route_id)
    actual_operation_records = (
        system_operation_records
        if system_operation_records is not None
        else [
            {"id": operation_id, "scope_route_ids": route_ids_by_operation.get(operation_id, [])}
            for operation_id in actual_system_operations
        ]
    )
    (project / "system-map.yaml").write_text(
        yaml.safe_dump({"candidate_operations": actual_operation_records}),
        encoding="utf-8",
    )
    actual_plan_dependencies = operation_ids if plan_dependencies is None else plan_dependencies
    actual_capabilities = (
        plan_capabilities
        if plan_capabilities is not None
        else [{"id": "scope-capability", "operation_dependencies": actual_plan_dependencies}]
    )
    (project / "capability-plan.yaml").write_text(
        yaml.safe_dump({"capabilities": actual_capabilities}),
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
    inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")

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
def test_route_path_must_be_a_safe_origin_relative_path(tmp_path: Path, invalid_path: str) -> None:
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
def test_ineligible_routes_cannot_be_planned_or_composed(tmp_path: Path, disposition: str) -> None:
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


def test_source_scope_counts_only_eligible_route_dispositions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    routes: list[object] = [
        _route("customer.search"),
        {
            **_route(
                "internal.write",
                disposition="excluded",
                operation_id=None,
                reason="write-only route",
            ),
            "eligibility": "ineligible",
        },
    ]
    project = _write_project(tmp_path, routes=routes)
    inventory = yaml.safe_load((project / "scope-inventory.yaml").read_text(encoding="utf-8"))
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    script = runpy.run_path(str(SCRIPT))

    result, diagnostics = script["audit_inventory"](inventory, path="scope-inventory.yaml")

    assert diagnostics == []
    assert inventory["summary"]["excluded"] == 1
    assert result["source_scope"]["eligible_read_routes"] == 1
    assert result["source_scope"]["planned"] == 1
    assert result["source_scope"]["composed"] == 0
    assert result["source_scope"]["excluded"] == 0
    assert result["source_scope"]["blocked_on_evidence"] == 0
    assert result["source_scope"]["unresolved"] == 0
    assert script["coverage_source_scope"](result["source_scope"]) == {
        "eligible_read_routes": 1,
        "planned_or_composed": 1,
        "excluded": 0,
        "blocked_on_evidence": 0,
        "unresolved": 0,
    }


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


def _excluded_route(
    route_id: str,
    *,
    rule_id: str = "binary-rule",
    domain: str = "customer",
    rationale: str | None = None,
    category: str = "binary_or_download",
    usage: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    decision_rationale = rationale or f"Exclude {route_id} based on route-specific evidence"
    route = _route(
        route_id,
        domain=domain,
        disposition="excluded",
        operation_id=None,
        reason="legacy-compatible exclusion reason",
        usage_evidence_sources=["frontend-client"] if usage else None,
        exclusion_rule_id=rule_id,
        exclusion_decision=_decision(decision_rationale),
    )
    rule = _rule(
        rule_id,
        [route_id],
        category=category,
        rationale=f"Shared rationale for {rule_id}",
    )
    return route, rule


def test_warning_diagnostic_is_non_blocking_and_preserves_result(tmp_path: Path) -> None:
    routes: list[object] = []
    rules: list[dict[str, object]] = []
    for index in range(7):
        route, rule = _excluded_route(f"customer.excluded{index}", rule_id=f"rule-{index}")
        routes.append(route)
        rules.append(rule)
    routes.extend(
        _route(f"customer.planned{index}", operation_id=f"customer.planned{index}")
        for index in range(3)
    )
    project = _write_project(tmp_path, routes=routes, exclusion_rules=rules)

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "system_readonly_complete"
    assert payload["diagnostics"] == [
        {
            "code": "ACC_SCOPE_HIGH_EXCLUSION_RATIO",
            "message": "eligible route exclusion ratio is unusually high",
            "path": "scope-inventory.yaml",
            "pointer": "/summary/excluded",
            "severity": "warning",
        }
    ]


@pytest.mark.parametrize(
    ("eligible_count", "excluded_count", "expects_warning"),
    [(9, 9, False), (10, 6, False), (10, 7, True), (20, 14, True)],
)
def test_high_exclusion_ratio_uses_locked_eligible_route_thresholds(
    tmp_path: Path,
    eligible_count: int,
    excluded_count: int,
    expects_warning: bool,
) -> None:
    routes: list[object] = [
        _route(
            f"customer.route{index}",
            disposition="excluded" if index < excluded_count else "planned",
            operation_id=None if index < excluded_count else f"customer.route{index}",
            reason="pilot omission" if index < excluded_count else None,
        )
        for index in range(eligible_count)
    ]
    routes.append(
        _route(
            "internal.write",
            disposition="excluded",
            operation_id=None,
            eligibility="ineligible",
            reason="write route",
        )
    )
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=routes,
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    codes = [item["code"] for item in payload["diagnostics"]]
    assert ("ACC_SCOPE_HIGH_EXCLUSION_RATIO" in codes) is expects_warning


def test_error_still_fails_while_preserving_warning_diagnostics(tmp_path: Path) -> None:
    routes: list[object] = []
    rules: list[dict[str, object]] = []
    for index in range(7):
        route, rule = _excluded_route(f"customer.excluded{index}", rule_id=f"rule-{index}")
        routes.append(route)
        rules.append(rule)
    routes.extend(
        _route(f"customer.planned{index}", operation_id=f"customer.planned{index}")
        for index in range(3)
    )
    project = _write_project(
        tmp_path,
        routes=routes,
        exclusion_rules=rules,
        summary_overrides={"planned": 99},
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["ok"] is False
    assert {item["severity"] for item in payload["diagnostics"]} == {"error", "warning"}
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_SUMMARY_MISMATCH",
        "ACC_SCOPE_HIGH_EXCLUSION_RATIO",
    }


def test_system_complete_requires_structured_exclusion_rule_and_decision(
    tmp_path: Path,
) -> None:
    route = _route(
        "customer.download",
        disposition="excluded",
        operation_id=None,
        reason="legacy reason is insufficient",
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_EXCLUSION_RULE_REQUIRED",
        "ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED",
        "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY",
    }


def test_exclusion_rule_must_exist_match_route_and_have_evidence(tmp_path: Path) -> None:
    route, _ = _excluded_route("customer.download", rule_id="missing")
    project = _write_project(
        tmp_path,
        routes=[route],
        exclusion_rules=[_rule("other", ["unknown.route"], evidence_sources=[])],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_EXCLUSION_RULE_UNKNOWN",
        "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
        "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
    }


def test_exclusion_rule_cannot_assign_the_same_route_twice(tmp_path: Path) -> None:
    route, first = _excluded_route("customer.download", rule_id="first")
    second = _rule("second", ["customer.download"])
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[first, second])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize(
    "mutator",
    [
        lambda route, rule: rule.update(route_ids=[]),
        lambda route, rule: rule.update(route_ids=["customer.download", "customer.download"]),
        lambda route, rule: rule.update(category="not-a-category"),
        lambda route, rule: rule.update(rationale="   "),
        lambda route, rule: rule.update(route_ids=["customer.other"]),
        lambda route, rule: route.update(disposition="planned", operation_id="customer.download"),
    ],
)
def test_exclusion_rule_fields_and_bidirectional_relation_are_strict(
    tmp_path: Path, mutator: Any
) -> None:
    route, rule = _excluded_route("customer.download")
    mutator(route, rule)
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[rule])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_exclusion_rule_ids_must_be_unique(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.download")
    project = _write_project(
        tmp_path,
        routes=[route],
        exclusion_rules=[rule, {**rule, "route_ids": ["customer.download"]}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_route_exclusion_decision_requires_unique_rationale_and_evidence(
    tmp_path: Path,
) -> None:
    first, first_rule = _excluded_route(
        "customer.download", rule_id="first", rationale=" Reused   Decision "
    )
    second, second_rule = _excluded_route(
        "report.download", rule_id="second", rationale="reused decision"
    )
    assert isinstance(second["exclusion_decision"], dict)
    second["exclusion_decision"]["evidence_sources"] = []
    project = _write_project(
        tmp_path,
        routes=[first, second, _route("customer.search")],
        exclusion_rules=[first_rule, second_rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_EXCLUSION_DECISION_REUSED",
        "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
    }


def test_ineligible_still_requires_reason_and_route_evidence(tmp_path: Path) -> None:
    route = _route(
        "internal.write",
        disposition="excluded",
        operation_id=None,
        eligibility="ineligible",
        evidence_sources=[],
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_EVIDENCE_REQUIRED",
        "ACC_SCOPE_REASON_REQUIRED",
    }


def test_system_complete_still_rejects_blocked_on_evidence(tmp_path: Path) -> None:
    route = _route(
        "customer.blocked",
        disposition="blocked_on_evidence",
        operation_id=None,
        reason="permission evidence missing",
    )
    project = _write_project(tmp_path, routes=[route])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EVIDENCE_BLOCKED" in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize(
    ("operation_record", "expected_code"),
    [
        ({"id": "customer.search"}, "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED"),
        (
            {"id": "customer.search", "scope_route_ids": ["unknown.route"]},
            "ACC_SCOPE_OPERATION_ROUTE_TRACE_ROUTE_UNKNOWN",
        ),
    ],
)
def test_operation_route_trace_is_required_and_must_exist(
    tmp_path: Path,
    operation_record: dict[str, object],
    expected_code: str,
) -> None:
    project = _write_project(tmp_path, system_operation_records=[operation_record])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert expected_code in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize("trace", [[], "customer.search", [""]])
def test_operation_route_trace_rejects_empty_non_list_or_empty_ids(
    tmp_path: Path, trace: object
) -> None:
    project = _write_project(
        tmp_path,
        system_operation_records=[{"id": "customer.search", "scope_route_ids": trace}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize("disposition", ["excluded", "blocked_on_evidence"])
def test_operation_trace_rejects_non_planned_routes(tmp_path: Path, disposition: str) -> None:
    traced = _route(
        "customer.traced",
        disposition=disposition,
        operation_id=None,
        reason="not available as an operation",
    )
    if disposition == "excluded":
        traced["eligibility"] = "ineligible"
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[traced, _route("customer.search")],
        system_operation_records=[
            {"id": "customer.search", "scope_route_ids": ["customer.traced"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_INVALID" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_operation_trace_requires_matching_route_operation_id(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        system_operation_records=[
            {"id": "different.operation", "scope_route_ids": ["customer.search"]}
        ],
        plan_capabilities=[
            {"id": "scope-capability", "operation_dependencies": ["different.operation"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_OPERATION_MISMATCH" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_capability_dependency_must_exist_in_system_map(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        plan_capabilities=[
            {
                "id": "scope-capability",
                "operation_dependencies": ["customer.search", "unknown.operation"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_duplicate_or_subsumed_requires_capability_and_replacement_closure(
    tmp_path: Path,
) -> None:
    excluded, rule = _excluded_route(
        "customer.duplicate", rule_id="duplicate", category="duplicate_or_subsumed"
    )
    excluded["exclusion_decision"] = _decision(
        "Customer duplicate is represented by the search capability"
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} >= {
        "ACC_SCOPE_SUBSUMED_CAPABILITY_REQUIRED",
        "ACC_SCOPE_SUBSUMED_REPLACEMENT_REQUIRED",
    }


def test_duplicate_or_subsumed_accepts_a_complete_replacement_closure(tmp_path: Path) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is represented by customer search",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_capabilities=[
            {
                "id": "search_customers",
                "operation_dependencies": ["customer.search"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["ok"] is True


def test_duplicate_or_subsumed_rejects_invalid_replacement_closure(tmp_path: Path) -> None:
    excluded, rule = _excluded_route(
        "customer.duplicate", rule_id="duplicate", category="duplicate_or_subsumed"
    )
    excluded["exclusion_decision"] = _decision(
        "Duplicate route is replaced",
        capability_ids=["missing-capability"],
        replacement_route_ids=["customer.duplicate"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


@pytest.mark.parametrize("replacement_disposition", ["excluded", "blocked_on_evidence"])
def test_subsumed_replacement_must_be_planned_or_composed(
    tmp_path: Path, replacement_disposition: str
) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is replaced",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    replacement = _route(
        "customer.search",
        disposition=replacement_disposition,
        operation_id=None,
        reason="not an operation",
    )
    if replacement_disposition == "excluded":
        replacement["eligibility"] = "ineligible"
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[excluded, replacement],
        exclusion_rules=[rule],
        plan_capabilities=[{"id": "search_customers", "operation_dependencies": []}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


def test_subsumed_capability_dependency_must_cover_replacement_operation(
    tmp_path: Path,
) -> None:
    excluded, rule = _excluded_route(
        "legacy.lookup", rule_id="duplicate", category="duplicate_or_subsumed", domain="legacy"
    )
    excluded["exclusion_decision"] = _decision(
        "Legacy lookup is replaced",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        plan_capabilities=[{"id": "search_customers", "operation_dependencies": []}],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID" in {item["code"] for item in payload["diagnostics"]}


def test_excluded_route_cannot_appear_in_an_ordinary_operation_trace(tmp_path: Path) -> None:
    excluded, rule = _excluded_route("customer.duplicate")
    project = _write_project(
        tmp_path,
        routes=[excluded, _route("customer.search")],
        exclusion_rules=[rule],
        system_operation_records=[
            {
                "id": "customer.search",
                "scope_route_ids": ["customer.search", "customer.duplicate"],
            }
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_OPERATION_ROUTE_TRACE_INVALID" in {
        item["code"] for item in payload["diagnostics"]
    }


@pytest.mark.parametrize("category", ["operational_polling", "low_business_value"])
def test_subjective_exclusion_requires_exact_non_empty_approval(
    tmp_path: Path, category: str
) -> None:
    route, rule = _excluded_route("platform.health", rule_id="subjective", category=category)
    project = _write_project(
        tmp_path,
        routes=[route, _route("platform.status")],
        exclusion_rules=[rule],
        approved_route_ids=["different.route"],
        approval_text="",
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_EXCLUSION_APPROVAL_REQUIRED" in {
        item["code"] for item in payload["diagnostics"]
    }


def test_frontend_used_exclusion_requires_approval_in_system_complete(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.visible", usage=True)
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    frontend_diagnostics = [
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    ]
    assert {item["severity"] for item in frontend_diagnostics} == {"error", "warning"}


def test_approved_frontend_used_exclusion_remains_a_warning(tmp_path: Path) -> None:
    route, rule = _excluded_route("customer.visible", usage=True)
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
        approved_route_ids=["customer.visible"],
        approval_text="User approved excluding this exact frontend-used route.",
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    frontend_diagnostics = [
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    ]
    assert [item["severity"] for item in frontend_diagnostics] == ["warning"]


def test_frontend_used_exclusion_is_warning_in_pilot(tmp_path: Path) -> None:
    route = _route(
        "customer.visible",
        disposition="excluded",
        operation_id=None,
        reason="approved pilot omission",
        usage_evidence_sources=["frontend-client"],
    )
    project = _write_project(
        tmp_path,
        mode="pilot",
        user_confirmation="Approved pilot.",
        routes=[route, _route("customer.search")],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED"
    assert payload["diagnostics"][0]["severity"] == "warning"


def test_domain_with_eligible_routes_requires_a_capability(tmp_path: Path) -> None:
    route, rule = _excluded_route("report.download", domain="report")
    project = _write_project(
        tmp_path,
        routes=[route, _route("customer.search")],
        exclusion_rules=[rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY" in {item["code"] for item in payload["diagnostics"]}


def test_zero_capability_exception_requires_every_route_to_be_validly_subsumed(
    tmp_path: Path,
) -> None:
    valid, valid_rule = _excluded_route(
        "legacy.lookup", rule_id="valid", category="duplicate_or_subsumed", domain="legacy"
    )
    valid["exclusion_decision"] = _decision(
        "Legacy lookup is replaced cross-domain",
        capability_ids=["search_customers"],
        replacement_route_ids=["customer.search"],
    )
    invalid, invalid_rule = _excluded_route("legacy.export", rule_id="invalid", domain="legacy")
    project = _write_project(
        tmp_path,
        routes=[valid, invalid, _route("customer.search")],
        exclusion_rules=[valid_rule, invalid_rule],
        plan_capabilities=[
            {"id": "search_customers", "operation_dependencies": ["customer.search"]}
        ],
    )

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY" in {item["code"] for item in payload["diagnostics"]}


def test_scope_diagnostics_do_not_echo_malicious_structured_values(tmp_path: Path) -> None:
    secret = "structured-secret-never-output"
    route, rule = _excluded_route(secret, rule_id=secret)
    rule.update(
        category=secret,
        rationale=secret,
        evidence_sources=[secret],
        route_ids=[secret],
    )
    assert isinstance(route["exclusion_decision"], dict)
    route["exclusion_decision"].update(
        rationale=secret,
        evidence_sources=[secret],
        capability_ids=[secret],
        replacement_route_ids=[secret],
    )
    project = _write_project(tmp_path, routes=[route], exclusion_rules=[rule])

    completed, payload = _run(project)

    assert completed.returncode == 3
    assert payload["diagnostics"]
    assert secret not in completed.stdout


def test_cross_domain_rule_rationale_reuse_is_a_warning(tmp_path: Path) -> None:
    first, first_rule = _excluded_route("customer.download", rule_id="customer-rule")
    second, second_rule = _excluded_route("report.download", rule_id="report-rule", domain="report")
    second_rule["rationale"] = first_rule["rationale"]
    project = _write_project(
        tmp_path,
        routes=[
            first,
            second,
            _route("customer.search"),
            _route("report.list", domain="report", operation_id="report.list"),
        ],
        exclusion_rules=[first_rule, second_rule],
    )

    completed, payload = _run(project)

    assert completed.returncode == 0
    warning = next(
        item
        for item in payload["diagnostics"]
        if item["code"] == "ACC_SCOPE_EXCLUSION_TEMPLATE_REUSED"
    )
    assert warning["severity"] == "warning"
