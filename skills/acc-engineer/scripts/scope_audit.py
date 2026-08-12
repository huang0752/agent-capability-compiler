#!/usr/bin/env python3
"""Audit ACC source-scope modes and route dispositions deterministically."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml
from pydantic import ValidationError
from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    diagnostic,
    emit,
    read_file_bytes,
    safe_existing_path,
)

from acc_core.domains import CapabilityCandidate, CapabilityCandidateLedger
from acc_core.models import Evidence
from acc_core.scope import ScopeInventory

SCOPE_MODES = {"pilot", "domain_complete", "system_complete"}
SUPPORTED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
DISPOSITIONS = {
    "planned",
    "composed",
    "excluded",
    "blocked_on_evidence",
    "out_of_scope",
}
TERMINAL_COMPLETE = {"planned", "composed", "excluded"}
ELIGIBILITIES = {"undetermined", "eligible", "ineligible"}
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
    "eligible_routes",
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
        "eligible_routes": source_scope.get("eligible_routes"),
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


def parse_core_inventory(document: Mapping[str, object]) -> ScopeInventory:
    """Parse a valid inventory through the public Core route contract."""

    return ScopeInventory.model_validate(document)


def load_candidate_ledger(
    project: Path,
) -> tuple[CapabilityCandidateLedger | None, list[dict[str, object]]]:
    """Load the optional Core candidate ledger through its public typed contract."""

    ledger_path = project / "capability-candidates.yaml"
    if not ledger_path.exists() and not ledger_path.is_symlink():
        return None, []
    safe_path = safe_existing_path(str(ledger_path), kind="file")
    try:
        return CapabilityCandidateLedger.model_validate(load_document(safe_path)), []
    except ValidationError:
        diagnostics: list[dict[str, object]] = []
        add_issue(
            diagnostics,
            "ACC_SCOPE_CANDIDATE_LEDGER_INVALID",
            "declared capability candidate ledger does not satisfy the Core contract",
            path="capability-candidates.yaml",
            pointer="/",
        )
        return None, diagnostics


def load_evidence_ids(project: Path) -> tuple[set[str], list[dict[str, object]]]:
    """Load independently materialized Evidence identifiers without trusting snapshots."""

    evidence_dir = project / "evidence"
    if not evidence_dir.exists() and not evidence_dir.is_symlink():
        return set(), []
    safe_directory = safe_existing_path(str(evidence_dir), kind="directory")
    core_fields = set(Evidence.model_fields)
    result: set[str] = set()
    seen: set[str] = set()
    diagnostics: list[dict[str, object]] = []
    for child in sorted(safe_directory.iterdir(), key=lambda item: item.name):
        if child.suffix not in {".yaml", ".yml", ".json"}:
            continue
        safe_child = safe_existing_path(str(child), kind="file")
        document = load_document(safe_child)
        core_document = {key: value for key, value in document.items() if key in core_fields}
        try:
            evidence = Evidence.model_validate(core_document)
        except ValidationError:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EVIDENCE_ARTIFACT_INVALID",
                "declared Evidence artifact does not satisfy the Core contract",
                path=str(child.relative_to(project)),
                pointer="/",
            )
            continue
        if evidence.source_id in seen:
            result.discard(evidence.source_id)
            add_issue(
                diagnostics,
                "ACC_SCOPE_EVIDENCE_SOURCE_ID_DUPLICATE",
                "Evidence source_id must be unique before it can be trusted",
                path=str(child.relative_to(project)),
                pointer="/source_id",
            )
            continue
        seen.add(evidence.source_id)
        result.add(evidence.source_id)
    return result, diagnostics


def claim_is_evidence_proven(
    claim: object, *, expected_status: str, evidence_ids: set[str]
) -> bool:
    """Require the authoritative status and independently registered Evidence refs."""

    status = getattr(claim, "status", None)
    evidence_refs = getattr(claim, "evidence_refs", None)
    return (
        status == expected_status
        and isinstance(evidence_refs, list)
        and bool(evidence_refs)
        and set(evidence_refs) <= evidence_ids
    )


def action_candidate_has_blocking_gaps(
    candidate: CapabilityCandidate,
    *,
    route_effect: str | None,
    evidence_ids: set[str],
) -> bool:
    """Return whether an Action lacks any independently evidenced safety fact."""

    claims = candidate.claims
    required_fact_claims = (
        claims.schema_,
        claims.effect,
        claims.risk,
        claims.reversibility,
        claims.approval,
        claims.retry,
        claims.conflict_control,
        claims.idempotency,
        claims.lifecycle,
        claims.outcome_resolution,
    )
    return any(
        (
            bool(candidate.gaps),
            candidate.kind_claim != "action",
            candidate.effect_claim != route_effect,
            any(
                not claim_is_evidence_proven(
                    claim, expected_status="proven", evidence_ids=evidence_ids
                )
                for claim in required_fact_claims
            ),
            not claim_is_evidence_proven(
                claims.authorization_boundary,
                expected_status="upstream_authoritative",
                evidence_ids=evidence_ids,
            ),
            not claim_is_evidence_proven(
                claims.identity_binding,
                expected_status="identity_binding_proven",
                evidence_ids=evidence_ids,
            ),
            not claim_is_evidence_proven(
                claims.context_isolation,
                expected_status="context_isolation_proven",
                evidence_ids=evidence_ids,
            ),
        )
    )


def action_ineligibility_is_proven(
    candidate: CapabilityCandidate, *, evidence_ids: set[str]
) -> bool:
    """Accept ineligibility only from an objective, independently evidenced claim."""

    claim = candidate.ineligibility_claim
    return claim is not None and claim_is_evidence_proven(
        claim, expected_status="proven", evidence_ids=evidence_ids
    )


def audit_candidate_routes(
    inventory: Mapping[str, object],
    *,
    ledger: CapabilityCandidateLedger | None,
    evidence_ids: set[str],
) -> list[dict[str, object]]:
    """Bind unknown/Action routes to candidates and enforce Action evidence states."""

    diagnostics: list[dict[str, object]] = []
    routes = index_routes(inventory)
    candidates = {candidate.id: candidate for candidate in ledger.candidates} if ledger else {}
    raw_routes = inventory.get("routes")
    if not isinstance(raw_routes, list):
        return diagnostics

    for index, raw_route in enumerate(raw_routes):
        if not isinstance(raw_route, Mapping):
            continue
        route = cast(Mapping[str, object], raw_route)
        kind = string_at(route, "kind")
        candidate_id = string_at(route, "candidate_id")
        pointer = f"/routes/{index}/candidate_id"
        if candidate_id is None or not candidate_id.strip():
            if kind in {"unknown", "action"}:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_CANDIDATE_REFERENCE_REQUIRED",
                    "unknown and action routes require a capability candidate reference",
                    path="scope-inventory.yaml",
                    pointer=pointer,
                )
            continue
        candidate = candidates.get(candidate_id)
        route_id = string_at(route, "id")
        if candidate is None or route_id is None or route_id not in candidate.route_ids:
            add_issue(
                diagnostics,
                "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH",
                "route and capability candidate route identifiers must match bidirectionally",
                path="scope-inventory.yaml",
                pointer=pointer,
            )
            continue
        route_effect = string_at(route, "effect")
        if candidate.kind_claim != kind or candidate.effect_claim != route_effect:
            add_issue(
                diagnostics,
                "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH",
                "route kind and effect must exactly match the referenced capability candidate",
                path="scope-inventory.yaml",
                pointer=pointer,
            )
            continue
        if kind != "action":
            continue
        objective_ineligibility = action_ineligibility_is_proven(
            candidate, evidence_ids=evidence_ids
        )
        if string_at(route, "eligibility") == "ineligible" and not objective_ineligibility:
            add_issue(
                diagnostics,
                "ACC_SCOPE_ACTION_INELIGIBILITY_UNPROVEN",
                "action ineligibility requires an independent Evidence-backed objective claim",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/eligibility",
            )
        if (
            action_candidate_has_blocking_gaps(
                candidate,
                route_effect=route_effect,
                evidence_ids=evidence_ids,
            )
            and not objective_ineligibility
            and (
                string_at(route, "eligibility") != "undetermined"
                or string_at(route, "disposition") != "blocked_on_evidence"
            )
        ):
            add_issue(
                diagnostics,
                "ACC_SCOPE_ACTION_GAP_MISCLASSIFIED",
                "action safety gaps require eligibility=undetermined and blocked_on_evidence",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/disposition",
            )

    for candidate_index, candidate in enumerate(ledger.candidates if ledger else []):
        for route_index, route_id in enumerate(candidate.route_ids):
            route_entry = routes.get(route_id)
            if route_entry is None or string_at(route_entry[1], "candidate_id") != candidate.id:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH",
                    "candidate and scope route identifiers must match bidirectionally",
                    path="capability-candidates.yaml",
                    pointer=f"/candidates/{candidate_index}/route_ids/{route_index}",
                )
    return diagnostics


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
        if rule_id is None or not rule_id.strip() or rule_id != rule_id.strip() or rule_id in rules:
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
    if mode == "system_complete":
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
    if string_at(scope, "mode") != "system_complete":
        return diagnostics
    raw_routes = document.get("routes")
    routes = raw_routes if isinstance(raw_routes, list) else []
    rationale_counts: dict[str, int] = defaultdict(int)
    for raw_route in routes:
        if not isinstance(raw_route, Mapping):
            continue
        route = cast(Mapping[str, object], raw_route)
        decision = mapping_at(route, "exclusion_decision")
        rationale = string_at(decision or {}, "rationale")
        if rationale is not None and rationale.strip():
            rationale_counts[normalize_rationale(rationale)] += 1
    for index, raw_route in enumerate(routes):
        if not isinstance(raw_route, Mapping):
            continue
        route = cast(Mapping[str, object], raw_route)
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
            if rationale_counts[normalized] > 1:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EXCLUSION_DECISION_REUSED",
                    "route-level exclusion rationale must not be reused",
                    path=path,
                    pointer=f"/routes/{index}/exclusion_decision/rationale",
                )
        if non_empty_string_list(decision.get("evidence_sources")) is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXCLUSION_EVIDENCE_REQUIRED",
                "route-level exclusion evidence is required and unique",
                path=path,
                pointer=f"/routes/{index}/exclusion_decision/evidence_sources",
            )
    return diagnostics


def subsumed_decision_fields(
    decision: Mapping[str, object],
) -> tuple[list[str] | None, list[str] | None]:
    """Return the two dedicated subsumption relations through one shared contract."""

    return (
        non_empty_string_list(decision.get("capability_ids")),
        non_empty_string_list(decision.get("replacement_route_ids")),
    )


def audit_structured_exclusion_authorities(
    document: Mapping[str, object], *, path: str
) -> tuple[set[int], list[dict[str, object]]]:
    """Audit structured exclusions and return only fully valid reason authorities."""

    rules, rule_diagnostics = audit_exclusion_rules(document, path=path)
    decision_diagnostics = audit_route_exclusion_decision(document, path=path)
    diagnostics = [*rule_diagnostics, *decision_diagnostics]
    invalid_route_indexes: set[int] = set()
    invalid_rule_ids: set[str] = set()
    raw_routes = document.get("routes")
    routes = raw_routes if isinstance(raw_routes, list) else []
    route_indexes_by_id: dict[str, list[int]] = defaultdict(list)
    for route_index, raw_route in enumerate(routes):
        if not isinstance(raw_route, Mapping):
            continue
        route_id = string_at(cast(Mapping[str, object], raw_route), "id")
        if route_id:
            route_indexes_by_id[route_id].append(route_index)
    for indexes in route_indexes_by_id.values():
        if len(indexes) > 1:
            invalid_route_indexes.update(indexes)
    raw_rules = document.get("exclusion_rules")
    rules_list = raw_rules if isinstance(raw_rules, list) else []
    for issue in diagnostics:
        pointer = issue.get("pointer")
        if not isinstance(pointer, str):
            continue
        route_match = re.match(r"/routes/([0-9]+)(?:/|$)", pointer)
        if route_match is not None:
            invalid_route_indexes.add(int(route_match.group(1)))
        rule_match = re.match(r"/exclusion_rules/([0-9]+)(?:/|$)", pointer)
        if rule_match is None:
            continue
        rule_index = int(rule_match.group(1))
        if rule_index >= len(rules_list) or not isinstance(rules_list[rule_index], Mapping):
            continue
        invalid_rule = cast(Mapping[str, object], rules_list[rule_index])
        invalid_rule_id = string_at(invalid_rule, "id")
        if invalid_rule_id is not None:
            invalid_rule_ids.add(invalid_rule_id)
        for route_id in string_list_at(invalid_rule, "route_ids") or []:
            invalid_route_indexes.update(route_indexes_by_id.get(route_id, []))

    valid: set[int] = set()
    for route_index, raw_route in enumerate(routes):
        if not isinstance(raw_route, Mapping):
            continue
        route = cast(Mapping[str, object], raw_route)
        route_id = string_at(route, "id")
        if route_index in invalid_route_indexes:
            continue
        rule_id = string_at(route, "exclusion_rule_id")
        if (
            string_at(route, "eligibility") != "eligible"
            or string_at(route, "disposition") != "excluded"
            or route_id is None
            or not route_id
            or rule_id is None
            or not rule_id.strip()
            or rule_id != rule_id.strip()
            or rule_id in invalid_rule_ids
        ):
            continue
        rule = rules.get(rule_id)
        decision = mapping_at(route, "exclusion_decision")
        if rule is None or decision is None:
            continue
        if string_at(rule, "category") == "duplicate_or_subsumed":
            capability_ids, replacement_ids = subsumed_decision_fields(decision)
            if capability_ids is None or replacement_ids is None:
                continue
        valid.add(route_index)
    return valid, diagnostics


def audit_inventory(
    document: Mapping[str, object], *, path: str
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Validate scope mode, route dispositions, and recomputed summary counts."""

    diagnostics: list[dict[str, object]] = []
    if string_at(document, "schema_version") != "2":
        add_issue(
            diagnostics,
            "ACC_SCOPE_SCHEMA_VERSION_INVALID",
            'schema_version must be "2"',
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
    discovery = mapping_at(document, "discovery")
    methods = string_list_at(discovery, "methods") if discovery is not None else None
    if mode in {"domain_complete", "system_complete"} and (
        methods is None or len(methods) != len(set(methods)) or set(methods) != SUPPORTED_METHODS
    ):
        add_issue(
            diagnostics,
            "ACC_SCOPE_DISCOVERY_METHODS_INCOMPLETE",
            "complete scope discovery must list every supported method exactly once",
            path=path,
            pointer="/discovery/methods",
        )

    valid_structured_exclusions, structured_diagnostics = audit_structured_exclusion_authorities(
        document, path=path
    )
    seen: set[str] = set()
    operation_ids: set[str] = set()
    counters = {name: 0 for name in SUMMARY_FIELDS}
    source_counters = {name: 0 for name in SUMMARY_FIELDS}
    readiness_counts = {
        "discovery_complete": 0,
        "executable_ready": 0,
        "blocked": 0,
        "unknown": 0,
    }
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
            source_counters["eligible_routes"] += 1
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

        if string_at(route, "method") not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            add_issue(
                diagnostics,
                "ACC_SCOPE_METHOD_INVALID",
                "scope inventory method is unsupported",
                path=path,
                pointer=f"{pointer}/method",
            )
        route_kind = string_at(route, "kind")
        route_effect = string_at(route, "effect")
        classification_unknown = route_kind == "unknown" or route_effect == "unknown"
        if route_kind not in {"unknown", "read", "action"}:
            add_issue(
                diagnostics,
                "ACC_SCOPE_KIND_INVALID",
                "route kind must be unknown, read, or action",
                path=path,
                pointer=f"{pointer}/kind",
            )
        if route_effect not in {
            "unknown",
            "read",
            "create",
            "update",
            "delete",
            "transition",
            "execute",
        }:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EFFECT_INVALID",
                "route effect must be explicitly declared",
                path=path,
                pointer=f"{pointer}/effect",
            )
        elif (
            (route_kind == "unknown" and route_effect != "unknown")
            or (route_kind == "read" and route_effect != "read")
            or (
                route_kind == "action"
                and route_effect not in {"create", "update", "delete", "transition", "execute"}
            )
        ):
            add_issue(
                diagnostics,
                "ACC_SCOPE_KIND_EFFECT_MISMATCH",
                "route kind and effect must consistently describe unknown, read, or action",
                path=path,
                pointer=f"{pointer}/effect",
            )
        if classification_unknown:
            readiness_counts["unknown"] += 1
            if mode == "system_complete":
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_CLASSIFICATION_UNKNOWN",
                    "system scope requires every route kind and effect to be classified",
                    path=path,
                    pointer=f"{pointer}/kind",
                )
        evidence = non_empty_string_list(route.get("evidence_sources"))
        if evidence is None:
            add_issue(
                diagnostics,
                "ACC_SCOPE_EVIDENCE_REQUIRED",
                "route evidence is required",
                path=path,
                pointer=f"{pointer}/evidence_sources",
            )
        if "usage_evidence_sources" in route:
            usage = string_list_at(route, "usage_evidence_sources")
            if (
                usage is None
                or any(not item.strip() for item in usage)
                or len(usage) != len(set(usage))
            ):
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_EVIDENCE_REQUIRED",
                    "route usage evidence must contain unique non-empty references",
                    path=path,
                    pointer=f"{pointer}/usage_evidence_sources",
                )
        if "interaction_ids" in route:
            interaction_ids = string_list_at(route, "interaction_ids")
            if (
                interaction_ids is None
                or any(not item.strip() for item in interaction_ids)
                or len(interaction_ids) != len(set(interaction_ids))
                or interaction_ids != sorted(interaction_ids)
            ):
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_INTERACTION_IDS_INVALID",
                    "route interaction identifiers must be unique non-empty sorted references",
                    path=path,
                    pointer=f"{pointer}/interaction_ids",
                )

        eligibility = string_at(route, "eligibility")
        if eligibility not in ELIGIBILITIES:
            add_issue(
                diagnostics,
                "ACC_SCOPE_ELIGIBILITY_INVALID",
                "route eligibility must be undetermined, eligible, or ineligible",
                path=path,
                pointer=f"{pointer}/eligibility",
            )
        if eligibility == "eligible":
            counters["eligible_routes"] += 1
        elif eligibility == "undetermined":
            counters["unresolved"] += 1
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
        if not classification_unknown:
            readiness_counts["discovery_complete"] += 1
            if disposition in {"planned", "composed"} and eligibility == "eligible":
                readiness_counts["executable_ready"] += 1
            elif disposition == "blocked_on_evidence":
                readiness_counts["blocked"] += 1

        if disposition in {"planned", "composed"} and eligibility != "eligible":
            add_issue(
                diagnostics,
                "ACC_SCOPE_EXECUTABLE_NOT_READY",
                "planned or composed route must be eligible before executable release",
                path=path,
                pointer=f"{pointer}/eligibility",
            )

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
        structured_reason_authority = (
            mode == "system_complete"
            and eligibility == "eligible"
            and disposition == "excluded"
            and index in valid_structured_exclusions
        )
        if (
            disposition in {"excluded", "blocked_on_evidence", "out_of_scope"}
            and not structured_reason_authority
            and (reason is None or not reason.strip())
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
        if mode == "system_complete" and disposition == "out_of_scope":
            add_issue(
                diagnostics,
                "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
                "system scope cannot omit an eligible route",
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
        "release_readiness": {
            "status": "limited" if readiness_counts["blocked"] else "ready",
            **readiness_counts,
        },
    }
    diagnostics.extend(structured_diagnostics)
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
    raw_operations = system_map.get("candidate_operations")
    operations = raw_operations if isinstance(raw_operations, list) else []
    seen_operation_ids: set[str] = set()
    operation_traces: dict[str, set[str]] = defaultdict(set)
    for index, raw_operation in enumerate(operations):
        if not isinstance(raw_operation, Mapping):
            add_issue(
                diagnostics,
                "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED",
                "candidate operation must be an object with a unique id",
                path="system-map.yaml",
                pointer=f"/candidate_operations/{index}",
            )
            continue
        operation = cast(Mapping[str, object], raw_operation)
        operation_id = string_at(operation, "id")
        if operation_id is None or not operation_id.strip() or operation_id in seen_operation_ids:
            add_issue(
                diagnostics,
                "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED",
                "candidate operation id must be non-empty and unique",
                path="system-map.yaml",
                pointer=f"/candidate_operations/{index}/id",
            )
            if operation_id is None or not operation_id.strip():
                continue
        seen_operation_ids.add(operation_id)
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
        operation_traces[operation_id].update(route_ids)
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

    for route_id, (index, route) in routes.items():
        if string_at(route, "eligibility") == "eligible" and string_at(route, "disposition") in {
            "planned",
            "composed",
        }:
            operation_id = string_at(route, "operation_id")
            if operation_id is not None and route_id not in operation_traces.get(
                operation_id, set()
            ):
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_OPERATION_ROUTE_TRACE_REQUIRED",
                    "planned or composed route must be traced by its candidate operation",
                    path="scope-inventory.yaml",
                    pointer=f"/routes/{index}/operation_id",
                )

    mapped_ids = seen_operation_ids
    raw_capabilities = capability_plan.get("capabilities")
    capabilities = raw_capabilities if isinstance(raw_capabilities, list) else []
    seen_capability_ids: set[str] = set()
    for index, raw_capability in enumerate(capabilities):
        if not isinstance(raw_capability, Mapping):
            add_issue(
                diagnostics,
                "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN",
                "capability must be an object with a unique id",
                path="capability-plan.yaml",
                pointer=f"/capabilities/{index}",
            )
            continue
        capability = cast(Mapping[str, object], raw_capability)
        capability_id = string_at(capability, "id")
        if (
            capability_id is None
            or not capability_id.strip()
            or capability_id in seen_capability_ids
        ):
            add_issue(
                diagnostics,
                "ACC_SCOPE_CAPABILITY_DEPENDENCY_UNKNOWN",
                "capability id must be non-empty and unique",
                path="capability-plan.yaml",
                pointer=f"/capabilities/{index}/id",
            )
        if capability_id:
            seen_capability_ids.add(capability_id)
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
        capability_ids, replacement_ids = (
            subsumed_decision_fields(decision) if decision is not None else (None, None)
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
    if string_at(scope, "mode") != "system_complete":
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
        if mode == "system_complete" and route_id not in approved:
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
    mode = string_at(scope, "mode")
    if mode not in {"system_complete", "domain_complete"}:
        return diagnostics
    selected_domains = set(string_list_at(scope, "selected_domains") or [])
    routes_by_domain: dict[str, list[tuple[str, int, Mapping[str, object]]]] = defaultdict(list)
    for route_id, (index, route) in index_routes(inventory).items():
        domain = string_at(route, "domain")
        if domain and string_at(route, "eligibility") == "eligible":
            routes_by_domain[domain].append((route_id, index, route))
    for routes in routes_by_domain.values():
        domain = string_at(routes[0][2], "domain") if routes else None
        if mode == "domain_complete" and domain not in selected_domains:
            continue
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


def audit_plan_scope_coverage(
    inventory: Mapping[str, object], capability_plan: Mapping[str, object]
) -> list[dict[str, object]]:
    """Close system-complete Capability Plan coverage over the Scope Inventory."""

    diagnostics: list[dict[str, object]] = []
    scope = mapping_at(inventory, "scope") or {}
    if string_at(scope, "mode") != "system_complete":
        return diagnostics
    coverage = mapping_at(capability_plan, "coverage")
    if coverage is None:
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_ROUTE_DISPOSITIONS_MISMATCH",
            "system-complete capability plan requires structured route dispositions",
            path="capability-plan.yaml",
            pointer="/coverage",
        )
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID",
            "system-complete capability plan requires exact exclusion decision references",
            path="capability-plan.yaml",
            pointer="/coverage",
        )
        return diagnostics
    if (
        string_at(coverage, "scope_mode") != "system_complete"
        or string_at(coverage, "scope_inventory") != "scope-inventory.yaml"
    ):
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_COVERAGE_BINDING_INVALID",
            "capability plan coverage must bind to the current system-complete inventory",
            path="capability-plan.yaml",
            pointer="/coverage",
        )
    if "deliberately_excluded" in coverage:
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_FREE_TEXT_EXCLUSION_FORBIDDEN",
            "capability plan must not duplicate authoritative exclusion facts",
            path="capability-plan.yaml",
            pointer="/coverage/deliberately_excluded",
        )

    expected_dispositions: dict[str, set[str]] = {
        disposition: set() for disposition in sorted(DISPOSITIONS)
    }
    expected_decision_refs: set[str] = set()
    routes = inventory.get("routes")
    if isinstance(routes, list):
        for index, raw_route in enumerate(routes):
            if not isinstance(raw_route, Mapping):
                continue
            route = cast(Mapping[str, object], raw_route)
            route_id = string_at(route, "id")
            disposition = string_at(route, "disposition")
            if route_id and disposition in expected_dispositions:
                expected_dispositions[disposition].add(route_id)
            if string_at(route, "eligibility") == "eligible" and disposition == "excluded":
                expected_decision_refs.add(f"/routes/{index}/exclusion_decision")

    route_dispositions = mapping_at(coverage, "route_dispositions")
    dispositions_valid = route_dispositions is not None and set(route_dispositions) == set(
        expected_dispositions
    )
    seen_route_ids: set[str] = set()
    if route_dispositions is not None:
        for disposition, expected_ids in expected_dispositions.items():
            raw_ids = route_dispositions.get(disposition)
            if (
                not isinstance(raw_ids, list)
                or not all(isinstance(item, str) and bool(item.strip()) for item in raw_ids)
                or len(raw_ids) != len(set(raw_ids))
                or set(cast(list[str], raw_ids)) != expected_ids
            ):
                dispositions_valid = False
                continue
            if seen_route_ids.intersection(cast(list[str], raw_ids)):
                dispositions_valid = False
            seen_route_ids.update(cast(list[str], raw_ids))
    if not dispositions_valid:
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_ROUTE_DISPOSITIONS_MISMATCH",
            "capability plan route dispositions must exactly match the inventory",
            path="capability-plan.yaml",
            pointer="/coverage/route_dispositions",
        )

    raw_refs = coverage.get("exclusion_decision_refs")
    refs_valid = (
        isinstance(raw_refs, list)
        and all(isinstance(item, str) and bool(item.strip()) for item in raw_refs)
        and len(raw_refs) == len(set(raw_refs))
        and set(cast(list[str], raw_refs)) == expected_decision_refs
    )
    if refs_valid and isinstance(routes, list):
        for reference in cast(list[str], raw_refs):
            match = re.fullmatch(r"/routes/(0|[1-9][0-9]*)/exclusion_decision", reference)
            if match is None:
                refs_valid = False
                break
            route_index = int(match.group(1))
            if route_index >= len(routes):
                refs_valid = False
                break
            referenced_route = routes[route_index]
            if (
                not isinstance(referenced_route, Mapping)
                or mapping_at(cast(Mapping[str, object], referenced_route), "exclusion_decision")
                is None
            ):
                refs_valid = False
                break
    if not refs_valid:
        add_issue(
            diagnostics,
            "ACC_SCOPE_PLAN_EXCLUSION_DECISION_REFS_INVALID",
            "capability plan must exactly reference existing structured exclusion decisions",
            path="capability-plan.yaml",
            pointer="/coverage/exclusion_decision_refs",
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
    diagnostics.extend(audit_plan_scope_coverage(inventory, capability_plan))
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
        candidate_ledger, candidate_diagnostics = load_candidate_ledger(project)
        evidence_ids, evidence_diagnostics = load_evidence_ids(project)
        result, diagnostics = audit_inventory(inventory, path="scope-inventory.yaml")
        diagnostics.extend(candidate_diagnostics)
        diagnostics.extend(evidence_diagnostics)
        diagnostics.extend(
            audit_candidate_routes(
                inventory,
                ledger=candidate_ledger,
                evidence_ids=evidence_ids,
            )
        )
        diagnostics.extend(
            audit_cross_artifacts(
                result,
                inventory=inventory,
                system_map=system_map,
                capability_plan=capability_plan,
                coverage_baseline=load_document(coverage_baseline_path),
            )
        )
        if not has_error(diagnostics):
            try:
                parse_core_inventory(inventory)
            except ValidationError:
                add_issue(
                    diagnostics,
                    "ACC_SCOPE_CORE_CONTRACT_INVALID",
                    "scope inventory does not satisfy the public Core contract",
                    path="scope-inventory.yaml",
                    pointer="/",
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
