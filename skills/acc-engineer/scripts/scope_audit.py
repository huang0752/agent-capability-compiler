#!/usr/bin/env python3
"""Audit ACC source-scope modes and route dispositions deterministically."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml
from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    diagnostic,
    emit,
    read_file_bytes,
    safe_existing_path,
)

SCOPE_MODES = {"pilot", "domain_complete", "system_readonly_complete"}
DISPOSITIONS = {
    "planned",
    "composed",
    "excluded",
    "blocked_on_evidence",
    "out_of_scope",
}
TERMINAL_COMPLETE = {"planned", "composed", "excluded"}
ELIGIBILITIES = {"eligible", "ineligible"}
SUMMARY_FIELDS = (
    "discovered_routes",
    "eligible_read_routes",
    "planned",
    "composed",
    "excluded",
    "blocked_on_evidence",
    "out_of_scope",
    "unresolved",
)


def add_issue(
    diagnostics: list[dict[str, object]],
    code: str,
    message: str,
    *,
    path: str,
    pointer: str,
) -> None:
    """Append a stable, location-aware diagnostic without echoing input values."""

    diagnostics.append(diagnostic(code, message, path=path, pointer=pointer))


def mapping_at(document: Mapping[str, object], key: str) -> Mapping[str, object] | None:
    value = document.get(key)
    if isinstance(value, Mapping) and all(isinstance(item, str) for item in value):
        return cast(Mapping[str, object], value)
    return None


def string_at(document: Mapping[str, object], key: str) -> str | None:
    value = document.get(key)
    return value if isinstance(value, str) else None


def string_list_at(document: Mapping[str, object], key: str) -> list[str] | None:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return cast(list[str], value)


def declared_domain_ids(document: Mapping[str, object]) -> set[str]:
    """Return non-empty domain identifiers declared by the inventory."""

    domains = document.get("domains")
    if not isinstance(domains, list):
        return set()
    return {
        domain_id
        for item in domains
        if isinstance(item, Mapping)
        and (domain_id := string_at(item, "id")) is not None
        and bool(domain_id.strip())
    }


def system_operation_ids(document: Mapping[str, object]) -> set[str]:
    """Index operation identifiers declared in the System Map."""

    operations = document.get("candidate_operations")
    if not isinstance(operations, list):
        return set()
    return {
        operation_id
        for item in operations
        if isinstance(item, Mapping)
        and (operation_id := string_at(item, "id")) is not None
        and bool(operation_id)
    }


def plan_operation_ids(document: Mapping[str, object]) -> set[str]:
    """Index all operation dependencies declared by planned capabilities."""

    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list):
        return set()
    result: set[str] = set()
    for capability in capabilities:
        if not isinstance(capability, Mapping):
            continue
        dependencies = capability.get("operation_dependencies")
        if isinstance(dependencies, list):
            result.update(item for item in dependencies if isinstance(item, str) and item)
    return result


def coverage_source_scope(source_scope: Mapping[str, object]) -> dict[str, object]:
    """Project inventory counters onto the coverage baseline denominator."""

    planned = source_scope.get("planned")
    composed = source_scope.get("composed")
    planned_or_composed: object = None
    if isinstance(planned, int) and isinstance(composed, int):
        planned_or_composed = planned + composed
    return {
        "eligible_read_routes": source_scope.get("eligible_read_routes"),
        "planned_or_composed": planned_or_composed,
        "excluded": source_scope.get("excluded"),
        "blocked_on_evidence": source_scope.get("blocked_on_evidence"),
        "unresolved": source_scope.get("unresolved"),
    }


def is_origin_relative_path(value: str | None) -> bool:
    """Return whether a route path is an unambiguous origin-relative path."""

    return (
        value is not None
        and value.startswith("/")
        and "//" not in value
        and "?" not in value
        and "#" not in value
        and "\\" not in value
        and ".." not in value
    )


def load_document(path: Path) -> dict[str, object]:
    """Safely load a bounded UTF-8 YAML/JSON mapping."""

    metadata = path.stat()
    raw = read_file_bytes(path, metadata, DEFAULT_MAX_FILE_BYTES, path.name)
    try:
        value = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SafePathError(
            "ACC_SCOPE_DOCUMENT_INVALID",
            "document must be valid UTF-8 YAML or JSON",
            path=path.name,
        ) from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SafePathError(
            "ACC_SCOPE_DOCUMENT_INVALID",
            "document must be an object",
            path=path.name,
        )
    return cast(dict[str, object], value)


def audit_inventory(
    document: Mapping[str, object], *, path: str
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Validate scope mode, route dispositions, and recomputed summary counts."""

    diagnostics: list[dict[str, object]] = []
    if string_at(document, "schema_version") != "1":
        add_issue(
            diagnostics,
            "ACC_SCOPE_SCHEMA_VERSION_INVALID",
            'schema_version must be "1"',
            path=path,
            pointer="/schema_version",
        )
    scope = mapping_at(document, "scope")
    routes = document.get("routes")
    summary = mapping_at(document, "summary")
    if scope is None:
        add_issue(
            diagnostics,
            "ACC_SCOPE_DOCUMENT_INVALID",
            "scope must be an object",
            path=path,
            pointer="/scope",
        )
        return {}, diagnostics
    if not isinstance(routes, list) or summary is None:
        pointer = "/routes" if not isinstance(routes, list) else "/summary"
        add_issue(
            diagnostics,
            "ACC_SCOPE_DOCUMENT_INVALID",
            "routes and summary are required",
            path=path,
            pointer=pointer,
        )
        return {}, diagnostics

    mode = string_at(scope, "mode")
    confirmation = string_at(scope, "user_confirmation")
    selected_domains = string_list_at(scope, "selected_domains")
    selected_domain_ids = set(selected_domains or [])
    if mode not in SCOPE_MODES:
        add_issue(
            diagnostics,
            "ACC_SCOPE_MODE_INVALID",
            "scope mode is invalid",
            path=path,
            pointer="/scope/mode",
        )
    if mode == "pilot" and (confirmation is None or not confirmation.strip()):
        add_issue(
            diagnostics,
            "ACC_SCOPE_CONFIRMATION_REQUIRED",
            "pilot requires explicit user confirmation",
            path=path,
            pointer="/scope/user_confirmation",
        )
    if mode == "domain_complete" and not selected_domains:
        add_issue(
            diagnostics,
            "ACC_SCOPE_DOMAIN_REQUIRED",
            "domain_complete requires selected domains",
            path=path,
            pointer="/scope/selected_domains",
        )
    if mode == "domain_complete" and selected_domains:
        declared_domains = declared_domain_ids(document)
        for index, domain_id in enumerate(selected_domains):
            if domain_id not in declared_domains:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_DOMAIN_UNDECLARED",
                    "selected domain must be declared in the inventory",
                    path=path,
                    pointer=f"/scope/selected_domains/{index}",
                )

    seen: set[str] = set()
    operation_ids: set[str] = set()
    counters = {name: 0 for name in SUMMARY_FIELDS}
    source_counters = {name: 0 for name in SUMMARY_FIELDS}
    for index, raw_route in enumerate(routes):
        counters["discovered_routes"] += 1
        pointer = f"/routes/{index}"
        if not isinstance(raw_route, Mapping) or not all(isinstance(key, str) for key in raw_route):
            counters["unresolved"] += 1
            add_issue(
                diagnostics,
                "ACC_SCOPE_ROUTE_INVALID",
                "route must be an object",
                path=path,
                pointer=pointer,
            )
            continue
        route = cast(Mapping[str, object], raw_route)
        eligible_route = string_at(route, "eligibility") == "eligible"
        if eligible_route:
            source_counters["discovered_routes"] += 1
            source_counters["eligible_read_routes"] += 1
        route_id = string_at(route, "id")
        if route_id is None or not route_id:
            counters["unresolved"] += 1
            if eligible_route:
                source_counters["unresolved"] += 1
            add_issue(
                diagnostics,
                "ACC_SCOPE_ROUTE_INVALID",
                "route id is required",
                path=path,
                pointer=f"{pointer}/id",
            )
        elif route_id in seen:
            add_issue(
                diagnostics,
                "ACC_SCOPE_ROUTE_DUPLICATE",
                "route id must be unique",
                path=path,
                pointer=f"{pointer}/id",
            )
        else:
            seen.add(route_id)

        domain = string_at(route, "domain")
        if domain is None or not domain.strip():
            add_issue(
                diagnostics,
                "ACC_SCOPE_DOMAIN_INVALID",
                "route domain must be a non-empty string",
                path=path,
                pointer=f"{pointer}/domain",
            )
        route_path = string_at(route, "path")
        if not is_origin_relative_path(route_path):
            add_issue(
                diagnostics,
                "ACC_SCOPE_PATH_INVALID",
                "route path must be a safe origin-relative path",
                path=path,
                pointer=f"{pointer}/path",
            )

        if string_at(route, "method") not in {"GET", "HEAD"}:
            add_issue(
                diagnostics,
                "ACC_SCOPE_METHOD_INVALID",
                "scope inventory permits GET or HEAD",
                path=path,
                pointer=f"{pointer}/method",
            )
        evidence = string_list_at(route, "evidence_sources")
        if evidence is None or not evidence or any(not item for item in evidence):
            add_issue(
                diagnostics,
                "ACC_SCOPE_EVIDENCE_REQUIRED",
                "route evidence is required",
                path=path,
                pointer=f"{pointer}/evidence_sources",
            )

        eligibility = string_at(route, "eligibility")
        if eligibility not in ELIGIBILITIES:
            add_issue(
                diagnostics,
                "ACC_SCOPE_ELIGIBILITY_INVALID",
                "route eligibility must be eligible or ineligible",
                path=path,
                pointer=f"{pointer}/eligibility",
            )
        if eligibility == "eligible":
            counters["eligible_read_routes"] += 1
        disposition = string_at(route, "disposition")
        if disposition not in DISPOSITIONS:
            counters["unresolved"] += 1
            if eligible_route:
                source_counters["unresolved"] += 1
            add_issue(
                diagnostics,
                "ACC_SCOPE_DISPOSITION_INVALID",
                "route disposition is invalid",
                path=path,
                pointer=f"{pointer}/disposition",
            )
            continue
        counters[disposition] += 1
        if eligible_route:
            source_counters[disposition] += 1

        if mode == "domain_complete" and selected_domain_ids:
            if (
                domain in selected_domain_ids
                and eligibility == "eligible"
                and disposition not in TERMINAL_COMPLETE
            ):
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_DOMAIN_INCOMPLETE",
                    "eligible selected-domain route must have a complete disposition",
                    path=path,
                    pointer=f"{pointer}/disposition",
                )
            if domain not in selected_domain_ids and disposition != "out_of_scope":
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_DOMAIN_BOUNDARY_AMBIGUOUS",
                    "route outside selected domains must be explicitly out of scope",
                    path=path,
                    pointer=f"{pointer}/disposition",
                )

        if eligibility == "ineligible" and disposition in {"planned", "composed"}:
            add_issue(
                diagnostics,
                "ACC_SCOPE_INELIGIBLE_DISPOSITION",
                "ineligible routes cannot be planned or composed",
                path=path,
                pointer=f"{pointer}/disposition",
            )

        reason = string_at(route, "reason")
        if disposition in {"excluded", "blocked_on_evidence", "out_of_scope"} and (
            reason is None or not reason.strip()
        ):
            add_issue(
                diagnostics,
                "ACC_SCOPE_REASON_REQUIRED",
                "route disposition requires a reason",
                path=path,
                pointer=f"{pointer}/reason",
            )
        operation_id = string_at(route, "operation_id")
        if disposition in {"planned", "composed"}:
            if operation_id is None or not operation_id:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_OPERATION_REQUIRED",
                    "planned route requires an operation",
                    path=path,
                    pointer=f"{pointer}/operation_id",
                )
            else:
                operation_ids.add(operation_id)
        if mode == "system_readonly_complete" and disposition == "out_of_scope":
            add_issue(
                diagnostics,
                "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
                "system scope cannot omit an eligible route",
                path=path,
                pointer=f"{pointer}/disposition",
            )
        if mode == "system_readonly_complete" and disposition == "blocked_on_evidence":
            add_issue(
                diagnostics,
                "ACC_SCOPE_EVIDENCE_BLOCKED",
                "system scope has unresolved evidence",
                path=path,
                pointer=f"{pointer}/disposition",
            )

    for name, actual in counters.items():
        if summary.get(name) != actual:
            add_issue(
                diagnostics,
                "ACC_SCOPE_SUMMARY_MISMATCH",
                "declared scope summary does not match routes",
                path=path,
                pointer=f"/summary/{name}",
            )

    result: dict[str, object] = {
        "scope_mode": mode,
        "selected_domains": sorted(selected_domains or []),
        "operation_ids": sorted(operation_ids),
        "source_scope": source_counters,
    }
    return result, diagnostics


def audit_cross_artifacts(
    result: Mapping[str, object],
    *,
    system_map: Mapping[str, object],
    capability_plan: Mapping[str, object],
    coverage_baseline: Mapping[str, object],
) -> list[dict[str, object]]:
    """Validate operation references and the source-scope denominator."""

    diagnostics: list[dict[str, object]] = []
    operation_ids = result.get("operation_ids")
    required_operations = (
        sorted(item for item in operation_ids if isinstance(item, str))
        if isinstance(operation_ids, list)
        else []
    )
    mapped_operations = system_operation_ids(system_map)
    planned_operations = plan_operation_ids(capability_plan)
    for operation_id in required_operations:
        if operation_id not in mapped_operations:
            add_issue(
                diagnostics,
                "ACC_SCOPE_SYSTEM_MAP_MISSING_OPERATION",
                "planned or composed operation must exist in the System Map",
                path="system-map.yaml",
                pointer="/candidate_operations",
            )
        if operation_id not in planned_operations:
            add_issue(
                diagnostics,
                "ACC_SCOPE_PLAN_MISSING_OPERATION",
                "planned or composed operation must exist in the capability plan",
                path="capability-plan.yaml",
                pointer="/capabilities",
            )

    inventory_source_scope = result.get("source_scope")
    baseline_source_scope = mapping_at(coverage_baseline, "source_scope")
    expected_source_scope = (
        coverage_source_scope(inventory_source_scope)
        if isinstance(inventory_source_scope, Mapping)
        else None
    )
    if baseline_source_scope != expected_source_scope:
        add_issue(
            diagnostics,
            "ACC_SCOPE_COVERAGE_MISMATCH",
            "coverage source scope must match the inventory denominator",
            path="coverage-baseline.json",
            pointer="/source_scope",
        )
    return diagnostics


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="scope-audit")
    value.add_argument("--project", required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    command = "scope-audit"
    arguments = parser().parse_args(argv)
    try:
        project = safe_existing_path(arguments.project, kind="directory")
        inventory_path = safe_existing_path(str(project / "scope-inventory.yaml"), kind="file")
        system_map_path = safe_existing_path(str(project / "system-map.yaml"), kind="file")
        capability_plan_path = safe_existing_path(
            str(project / "capability-plan.yaml"), kind="file"
        )
        coverage_baseline_path = safe_existing_path(
            str(project / "coverage-baseline.json"), kind="file"
        )
        result, diagnostics = audit_inventory(
            load_document(inventory_path), path="scope-inventory.yaml"
        )
        diagnostics.extend(
            audit_cross_artifacts(
                result,
                system_map=load_document(system_map_path),
                capability_plan=load_document(capability_plan_path),
                coverage_baseline=load_document(coverage_baseline_path),
            )
        )
        emit(
            command,
            ok=not diagnostics,
            result=result if not diagnostics else None,
            diagnostics=diagnostics,
        )
        return 0 if not diagnostics else 3
    except SafePathError as exc:
        emit(
            command,
            ok=False,
            result=None,
            diagnostics=[diagnostic(exc.code, str(exc), path=exc.path)],
        )
        return 2 if exc.code == "ACC_SKILL_PATH_INVALID" else 3


if __name__ == "__main__":
    raise SystemExit(main())
