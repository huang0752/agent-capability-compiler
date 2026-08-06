#!/usr/bin/env python3
"""Audit ACC source-scope modes and route dispositions deterministically."""

from __future__ import annotations

import re
from collections import defaultdict
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
EXCLUSION_CATEGORIES = {
    "binary_or_download",
    "sensitive_configuration",
    "alternate_identity_boundary",
    "unsafe_dynamic_authorization",
    "unavailable_or_disabled",
    "operational_polling",
    "duplicate_or_subsumed",
    "low_business_value",
}
SUBJECTIVE_EXCLUSION_CATEGORIES = {"operational_polling", "low_business_value"}
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
    severity: str = "error",
) -> None:
    """Append a stable, location-aware diagnostic without echoing input values."""

    diagnostics.append(diagnostic(code, message, path=path, pointer=pointer, severity=severity))


def has_error(diagnostics: list[dict[str, object]]) -> bool:
    """Return whether diagnostics contain a release-blocking error."""

    return any(item.get("severity") == "error" for item in diagnostics)


def normalize_rationale(value: str) -> str:
    """Normalize a rationale for deterministic exact reuse detection."""

    return re.sub(r"\s+", " ", value.strip()).lower()


def non_empty_string_list(value: object) -> list[str] | None:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and bool(item.strip()) for item in value)
    ):
        return None
    values = cast(list[str], value)
    return values if len(values) == len(set(values)) else None


def index_routes(document: Mapping[str, object]) -> dict[str, tuple[int, Mapping[str, object]]]:
    """Index the first well-formed route by its stable identifier."""

    routes = document.get("routes")
    if not isinstance(routes, list):
        return {}
    result: dict[str, tuple[int, Mapping[str, object]]] = {}
    for index, route in enumerate(routes):
        if not isinstance(route, Mapping):
            continue
        route_id = string_at(route, "id")
        if route_id and route_id not in result:
            result[route_id] = (index, cast(Mapping[str, object], route))
    return result


def approved_exclusion_route_ids(document: Mapping[str, object]) -> set[str]:
    scope = mapping_at(document, "scope")
    approval = mapping_at(scope, "exclusion_approval") if scope is not None else None
    if approval is None:
        return set()
    text = string_at(approval, "approval_text")
    route_ids = non_empty_string_list(approval.get("approved_route_ids"))
    if text is None or not text.strip() or route_ids is None:
        return set()
    return set(route_ids)


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


def audit_exclusion_rules(
    document: Mapping[str, object], *, path: str
) -> tuple[dict[str, Mapping[str, object]], list[dict[str, object]]]:
    """Validate structured exclusion rules and their bidirectional route relation."""

    diagnostics: list[dict[str, object]] = []
    routes = index_routes(document)
    raw_rules = document.get("exclusion_rules", [])
    if not isinstance(raw_rules, list):
        add_issue(
            diagnostics,
            "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
            "exclusion_rules must be a list",
            path=path,
            pointer="/exclusion_rules",
        )
        return {}, diagnostics

    rules: dict[str, Mapping[str, object]] = {}
    assigned_routes: dict[str, str] = {}
    for index, raw_rule in enumerate(raw_rules):
        pointer = f"/exclusion_rules/{index}"
        if not isinstance(raw_rule, Mapping):
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                "exclusion rule must be an object",
                path=path,
                pointer=pointer,
            )
            continue
        rule = cast(Mapping[str, object], raw_rule)
        rule_id = string_at(rule, "id")
        if rule_id is None or not rule_id.strip() or rule_id in rules:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                "exclusion rule id must be non-empty and unique",
                path=path,
                pointer=f"{pointer}/id",
            )
            continue
        rules[rule_id] = rule
        category = string_at(rule, "category")
        if category not in EXCLUSION_CATEGORIES:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                "exclusion rule category is invalid",
                path=path,
                pointer=f"{pointer}/category",
            )
        rationale = string_at(rule, "rationale")
        if rationale is None or not rationale.strip():
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                "exclusion rule rationale is required",
                path=path,
                pointer=f"{pointer}/rationale",
            )
        evidence = non_empty_string_list(rule.get("evidence_sources"))
        if evidence is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
                "exclusion rule evidence is required and unique",
                path=path,
                pointer=f"{pointer}/evidence_sources",
            )
        route_ids = non_empty_string_list(rule.get("route_ids"))
        if route_ids is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                "exclusion rule route ids are required and unique",
                path=path,
                pointer=f"{pointer}/route_ids",
            )
            continue
        for route_offset, route_id in enumerate(route_ids):
            route_entry = routes.get(route_id)
            if route_entry is None:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                    "exclusion rule route must exist",
                    path=path,
                    pointer=f"{pointer}/route_ids/{route_offset}",
                )
                continue
            _, route = route_entry
            if (
                string_at(route, "eligibility") != "eligible"
                or string_at(route, "disposition") != "excluded"
                or string_at(route, "exclusion_rule_id") != rule_id
                or route_id in assigned_routes
            ):
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                    "exclusion rule and route relation must be unique and bidirectional",
                    path=path,
                    pointer=f"{pointer}/route_ids/{route_offset}",
                )
            assigned_routes[route_id] = rule_id

    mode = string_at(mapping_at(document, "scope") or {}, "mode")
    if mode == "system_readonly_complete":
        for route_id, (index, route) in routes.items():
            if (
                string_at(route, "eligibility") != "eligible"
                or string_at(route, "disposition") != "excluded"
            ):
                continue
            rule_id = string_at(route, "exclusion_rule_id")
            if rule_id is None or not rule_id.strip():
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_RULE_REQUIRED",
                    "eligible excluded route requires an exclusion rule",
                    path=path,
                    pointer=f"/routes/{index}/exclusion_rule_id",
                )
            elif rule_id not in rules:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_RULE_UNKNOWN",
                    "eligible excluded route references an unknown exclusion rule",
                    path=path,
                    pointer=f"/routes/{index}/exclusion_rule_id",
                )
            elif assigned_routes.get(route_id) != rule_id:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_RULE_ROUTE_MISMATCH",
                    "exclusion rule must list its referencing route exactly once",
                    path=path,
                    pointer=f"/routes/{index}/exclusion_rule_id",
                )
    return rules, diagnostics


def audit_route_exclusion_decision(
    document: Mapping[str, object], *, path: str
) -> list[dict[str, object]]:
    """Require distinct route-level exclusion decisions in system-complete mode."""

    diagnostics: list[dict[str, object]] = []
    scope = mapping_at(document, "scope") or {}
    if string_at(scope, "mode") != "system_readonly_complete":
        return diagnostics
    seen: dict[str, int] = {}
    for _route_id, (index, route) in index_routes(document).items():
        if (
            string_at(route, "eligibility") != "eligible"
            or string_at(route, "disposition") != "excluded"
        ):
            continue
        decision = mapping_at(route, "exclusion_decision")
        if decision is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED",
                "eligible excluded route requires a route-level decision",
                path=path,
                pointer=f"/routes/{index}/exclusion_decision",
            )
            continue
        rationale = string_at(decision, "rationale")
        if rationale is None or not rationale.strip():
            add_issue(
                diagnostics,
                "ACC_SCOPE_ROUTE_EXCLUSION_DECISION_REQUIRED",
                "route-level exclusion rationale is required",
                path=path,
                pointer=f"/routes/{index}/exclusion_decision/rationale",
            )
        else:
            normalized = normalize_rationale(rationale)
            if normalized in seen:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_DECISION_REUSED",
                    "route-level exclusion rationale must not be reused",
                    path=path,
                    pointer=f"/routes/{index}/exclusion_decision/rationale",
                )
            else:
                seen[normalized] = index
        if non_empty_string_list(decision.get("evidence_sources")) is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
                "route-level exclusion evidence is required and unique",
                path=path,
                pointer=f"/routes/{index}/exclusion_decision/evidence_sources",
            )
    return diagnostics


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
    _, rule_diagnostics = audit_exclusion_rules(document, path=path)
    diagnostics.extend(rule_diagnostics)
    diagnostics.extend(audit_route_exclusion_decision(document, path=path))
    return result, diagnostics


def system_operations(
    document: Mapping[str, object],
) -> dict[str, tuple[int, Mapping[str, object]]]:
    operations = document.get("candidate_operations")
    if not isinstance(operations, list):
        return {}
    result: dict[str, tuple[int, Mapping[str, object]]] = {}
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            continue
        operation_id = string_at(operation, "id")
        if operation_id and operation_id not in result:
            result[operation_id] = (index, cast(Mapping[str, object], operation))
    return result


def plan_capabilities(
    document: Mapping[str, object],
) -> dict[str, tuple[int, Mapping[str, object]]]:
    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list):
        return {}
    result: dict[str, tuple[int, Mapping[str, object]]] = {}
    for index, capability in enumerate(capabilities):
        if not isinstance(capability, Mapping):
            continue
        capability_id = string_at(capability, "id")
        if capability_id and capability_id not in result:
            result[capability_id] = (index, cast(Mapping[str, object], capability))
    return result


def audit_operation_route_traces(
    inventory: Mapping[str, object],
    *,
    system_map: Mapping[str, object],
    capability_plan: Mapping[str, object],
) -> list[dict[str, object]]:
    diagnostics: list[dict[str, object]] = []
    routes = index_routes(inventory)
    operations = system_operations(system_map)
    for operation_id, (index, operation) in operations.items():
        route_ids = non_empty_string_list(operation.get("scope_route_ids"))
        if route_ids is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED",
                "candidate operation requires unique scope route ids",
                path="system-map.yaml",
                pointer=f"/candidate_operations/{index}/scope_route_ids",
            )
            continue
        for offset, route_id in enumerate(route_ids):
            entry = routes.get(route_id)
            pointer = f"/candidate_operations/{index}/scope_route_ids/{offset}"
            if entry is None:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_OPERATION_ROUTE_TRACE_ROUTE_UNKNOWN",
                    "operation route trace must reference an inventory route",
                    path="system-map.yaml",
                    pointer=pointer,
                )
                continue
            _, route = entry
            if string_at(route, "eligibility") != "eligible" or string_at(
                route, "disposition"
            ) not in {"planned", "composed"}:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_OPERATION_ROUTE_TRACE_INVALID",
                    "operation route trace must reference an eligible planned or composed route",
                    path="system-map.yaml",
                    pointer=pointer,
                )
            if string_at(route, "operation_id") != operation_id:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_OPERATION_ROUTE_TRACE_OPERATION_MISMATCH",
                    "operation route trace must match the route operation id",
                    path="system-map.yaml",
                    pointer=pointer,
                )

    mapped_ids = set(operations)
    for _, (index, capability) in plan_capabilities(capability_plan).items():
        dependencies = capability.get("operation_dependencies")
        if not isinstance(dependencies, list):
            continue
        for offset, dependency in enumerate(dependencies):
            if not isinstance(dependency, str) or not dependency or dependency not in mapped_ids:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN",
                    "capability dependency must exist in the System Map",
                    path="capability-plan.yaml",
                    pointer=f"/capabilities/{index}/operation_dependencies/{offset}",
                )
    return diagnostics


def audit_subsumed_replacement_closure(
    inventory: Mapping[str, object],
    *,
    system_map: Mapping[str, object],
    capability_plan: Mapping[str, object],
) -> tuple[set[str], list[dict[str, object]]]:
    diagnostics: list[dict[str, object]] = []
    valid_routes: set[str] = set()
    routes = index_routes(inventory)
    rules, _ = audit_exclusion_rules(inventory, path="scope-inventory.yaml")
    operations = system_operations(system_map)
    capabilities = plan_capabilities(capability_plan)
    operation_traces: dict[str, set[str]] = {}
    for operation_id, (_, operation) in operations.items():
        traces = string_list_at(operation, "scope_route_ids")
        operation_traces[operation_id] = set(traces or [])

    for route_id, (index, route) in routes.items():
        rule_id = string_at(route, "exclusion_rule_id")
        rule = rules.get(rule_id or "")
        if rule is None or string_at(rule, "category") != "duplicate_or_subsumed":
            continue
        decision = mapping_at(route, "exclusion_decision")
        capability_ids = (
            non_empty_string_list(decision.get("capability_ids")) if decision is not None else None
        )
        replacement_ids = (
            non_empty_string_list(decision.get("replacement_route_ids"))
            if decision is not None
            else None
        )
        if capability_ids is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_SUBSUMED_CAPABILITY_REQUIRED",
                "subsumed exclusion requires unique capability ids",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/exclusion_decision/capability_ids",
            )
        if replacement_ids is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_SUBSUMED_REPLACEMENT_REQUIRED",
                "subsumed exclusion requires unique replacement route ids",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/exclusion_decision/replacement_route_ids",
            )
        if capability_ids is None or replacement_ids is None:
            continue

        replacement_operations: set[str] = set()
        closure_valid = True
        for replacement_id in replacement_ids:
            replacement = routes.get(replacement_id)
            if replacement_id == route_id or replacement is None:
                closure_valid = False
                continue
            _, replacement_route = replacement
            replacement_operation = string_at(replacement_route, "operation_id")
            if (
                string_at(replacement_route, "eligibility") != "eligible"
                or string_at(replacement_route, "disposition") not in {"planned", "composed"}
                or replacement_operation is None
                or replacement_id not in operation_traces.get(replacement_operation, set())
            ):
                closure_valid = False
            else:
                replacement_operations.add(replacement_operation)
        for capability_id in capability_ids:
            capability_entry = capabilities.get(capability_id)
            if capability_entry is None:
                closure_valid = False
                continue
            _, capability = capability_entry
            dependencies = set(string_list_at(capability, "operation_dependencies") or [])
            if not replacement_operations.issubset(dependencies):
                closure_valid = False
        if closure_valid and replacement_operations:
            valid_routes.add(route_id)
        else:
            add_issue(
                diagnostics,
                "ACC_SCOPE_SUBSUMED_CLOSURE_INVALID",
                "subsumed exclusion must close through replacement routes, operations, "
                "and capabilities",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/exclusion_decision",
            )
    return valid_routes, diagnostics


def audit_subjective_exclusion_approval(
    inventory: Mapping[str, object], rules: Mapping[str, Mapping[str, object]]
) -> list[dict[str, object]]:
    diagnostics: list[dict[str, object]] = []
    scope = mapping_at(inventory, "scope") or {}
    if string_at(scope, "mode") != "system_readonly_complete":
        return diagnostics
    approved = approved_exclusion_route_ids(inventory)
    for route_id, (index, route) in index_routes(inventory).items():
        rule = rules.get(string_at(route, "exclusion_rule_id") or "")
        if (
            rule is not None
            and string_at(rule, "category") in SUBJECTIVE_EXCLUSION_CATEGORIES
            and route_id not in approved
        ):
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_APPROVAL_REQUIRED",
                "subjective route exclusion requires exact user approval",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/exclusion_rule_id",
            )
    return diagnostics


def audit_frontend_used_exclusions(
    inventory: Mapping[str, object],
) -> list[dict[str, object]]:
    diagnostics: list[dict[str, object]] = []
    scope = mapping_at(inventory, "scope") or {}
    mode = string_at(scope, "mode")
    approved = approved_exclusion_route_ids(inventory)
    for route_id, (index, route) in index_routes(inventory).items():
        usage = non_empty_string_list(route.get("usage_evidence_sources"))
        if (
            string_at(route, "eligibility") != "eligible"
            or string_at(route, "disposition") != "excluded"
            or usage is None
        ):
            continue
        add_issue(
            diagnostics,
            "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED",
            "frontend-used eligible route is excluded",
            path="scope-inventory.yaml",
            pointer=f"/routes/{index}/usage_evidence_sources",
            severity="warning",
        )
        if mode == "system_readonly_complete" and route_id not in approved:
            add_issue(
                diagnostics,
                "ACC_SCOPE_FRONTEND_USED_ROUTE_EXCLUDED",
                "frontend-used eligible route exclusion requires exact user approval",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/usage_evidence_sources",
            )
    return diagnostics


def audit_domain_capability_coverage(
    inventory: Mapping[str, object], *, valid_subsumed_routes: set[str]
) -> list[dict[str, object]]:
    diagnostics: list[dict[str, object]] = []
    scope = mapping_at(inventory, "scope") or {}
    if string_at(scope, "mode") != "system_readonly_complete":
        return diagnostics
    routes_by_domain: dict[str, list[tuple[str, int, Mapping[str, object]]]] = defaultdict(list)
    for route_id, (index, route) in index_routes(inventory).items():
        domain = string_at(route, "domain")
        if domain and string_at(route, "eligibility") == "eligible":
            routes_by_domain[domain].append((route_id, index, route))
    for routes in routes_by_domain.values():
        if any(
            string_at(route, "disposition") not in {"planned", "composed", "excluded"}
            for _, _, route in routes
        ):
            continue
        if any(
            string_at(route, "disposition") in {"planned", "composed"} for _, _, route in routes
        ):
            continue
        if routes and all(route_id in valid_subsumed_routes for route_id, _, _ in routes):
            replacement_is_external = True
            domain = string_at(routes[0][2], "domain")
            indexed = index_routes(inventory)
            for _, _, route in routes:
                decision = mapping_at(route, "exclusion_decision") or {}
                for replacement_id in string_list_at(decision, "replacement_route_ids") or []:
                    replacement = indexed.get(replacement_id)
                    if replacement is None or string_at(replacement[1], "domain") == domain:
                        replacement_is_external = False
            if replacement_is_external:
                continue
        add_issue(
            diagnostics,
            "ACC_SCOPE_DOMAIN_ZERO_CAPABILITY",
            "eligible route domain requires a direct capability or valid cross-domain subsumption",
            path="scope-inventory.yaml",
            pointer=f"/routes/{routes[0][1]}/domain",
        )
    return diagnostics


def audit_exclusion_heuristics(
    inventory: Mapping[str, object], rules: Mapping[str, Mapping[str, object]]
) -> list[dict[str, object]]:
    diagnostics: list[dict[str, object]] = []
    rationale_domains: dict[str, set[str]] = defaultdict(set)
    rule_indexes: dict[str, int] = {}
    raw_rules = inventory.get("exclusion_rules")
    if isinstance(raw_rules, list):
        for index, raw_rule in enumerate(raw_rules):
            if isinstance(raw_rule, Mapping):
                rule_id = string_at(raw_rule, "id")
                if rule_id:
                    rule_indexes[rule_id] = index
    indexed = index_routes(inventory)
    for rule_id, rule in rules.items():
        rationale = string_at(rule, "rationale")
        route_ids = string_list_at(rule, "route_ids") or []
        if rationale is None or not rationale.strip():
            continue
        for route_id in route_ids:
            route = indexed.get(route_id)
            domain = string_at(route[1], "domain") if route is not None else None
            if domain:
                rationale_domains[normalize_rationale(rationale)].add(domain)
        if len(rationale_domains[normalize_rationale(rationale)]) > 1:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_TEMPLATE_REUSED",
                "exclusion rule rationale is reused across domains",
                path="scope-inventory.yaml",
                pointer=f"/exclusion_rules/{rule_indexes.get(rule_id, 0)}/rationale",
                severity="warning",
            )
    eligible = [
        route for _, route in indexed.values() if string_at(route, "eligibility") == "eligible"
    ]
    excluded = sum(string_at(route, "disposition") == "excluded" for route in eligible)
    if len(eligible) >= 10 and excluded * 10 >= len(eligible) * 7:
        add_issue(
            diagnostics,
            "ACC_SCOPE_HIGH_EXCLUSION_RATIO",
            "eligible route exclusion ratio is unusually high",
            path="scope-inventory.yaml",
            pointer="/summary/excluded",
            severity="warning",
        )
    return diagnostics


def audit_cross_artifacts(
    result: Mapping[str, object],
    *,
    inventory: Mapping[str, object],
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
    diagnostics.extend(
        audit_operation_route_traces(
            inventory, system_map=system_map, capability_plan=capability_plan
        )
    )
    valid_subsumed_routes, subsumed_diagnostics = audit_subsumed_replacement_closure(
        inventory, system_map=system_map, capability_plan=capability_plan
    )
    diagnostics.extend(subsumed_diagnostics)
    rules, _ = audit_exclusion_rules(inventory, path="scope-inventory.yaml")
    diagnostics.extend(audit_subjective_exclusion_approval(inventory, rules))
    diagnostics.extend(audit_frontend_used_exclusions(inventory))
    diagnostics.extend(
        audit_domain_capability_coverage(inventory, valid_subsumed_routes=valid_subsumed_routes)
    )
    diagnostics.extend(audit_exclusion_heuristics(inventory, rules))
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
        inventory = load_document(inventory_path)
        system_map = load_document(system_map_path)
        capability_plan = load_document(capability_plan_path)
        result, diagnostics = audit_inventory(inventory, path="scope-inventory.yaml")
        diagnostics.extend(
            audit_cross_artifacts(
                result,
                inventory=inventory,
                system_map=system_map,
                capability_plan=capability_plan,
                coverage_baseline=load_document(coverage_baseline_path),
            )
        )
        diagnostics.sort(
            key=lambda item: (
                str(item.get("path", "")),
                str(item.get("pointer", "")),
                str(item.get("severity", "")),
                str(item.get("code", "")),
            )
        )
        failed = has_error(diagnostics)
        emit(
            command,
            ok=not failed,
            result=result if not failed else None,
            diagnostics=diagnostics,
        )
        return 0 if not failed else 3
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
