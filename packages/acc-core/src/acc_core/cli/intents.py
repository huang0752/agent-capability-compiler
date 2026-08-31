"""Deterministic CLI views for evidence-driven AI intent planning."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from acc_core.diagnostics import Diagnostic
from acc_core.domains import analyze_candidate_readiness
from acc_core.quality import audit_intent_plan, capability_operation_dependencies
from acc_core.validation import ValidationReport, validate_project


def _diagnostic(code: str, message: str, *, path: str | None = None) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity="error",
        message=message,
        path=path,
        pointer=None,
    )


def _load_planning_project(project: Path) -> tuple[ValidationReport, list[Diagnostic]]:
    report = validate_project(project)
    missing: list[Diagnostic] = []
    if report.scope_inventory is None:
        missing.append(
            _diagnostic(
                "ACC_INTENT_SCOPE_INVENTORY_REQUIRED",
                "Intent planning requires scope-inventory.yaml as the complete route denominator.",
                path="scope-inventory.yaml",
            )
        )
    if report.domain_map is None:
        missing.append(
            _diagnostic(
                "ACC_INTENT_DOMAIN_MAP_REQUIRED",
                "Intent planning requires domain-map.yaml.",
                path="domain-map.yaml",
            )
        )
    if report.capability_candidate_ledger is None:
        missing.append(
            _diagnostic(
                "ACC_INTENT_CANDIDATE_LEDGER_REQUIRED",
                "Intent planning requires capability-candidates.yaml.",
                path="capability-candidates.yaml",
            )
        )
    return report, [*report.diagnostics, *missing]


def build_intent_brief(
    project: Path,
    *,
    domain_id: str | None = None,
) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Build bounded facts for the Coding Agent without selecting a tool count."""

    report, diagnostics = _load_planning_project(project)
    plan_diagnostics = [item for item in diagnostics if item.path == "intent-plan.yaml"]
    project_diagnostics = [item for item in diagnostics if item.path != "intent-plan.yaml"]
    if any(item.severity == "error" for item in project_diagnostics):
        return None, project_diagnostics
    assert report.scope_inventory is not None
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None

    domains = {item.id: item for item in report.domain_map.domains}
    if domain_id is not None and domain_id not in domains:
        return None, [
            _diagnostic(
                "ACC_INTENT_DOMAIN_UNKNOWN",
                "Requested planning domain does not exist.",
                path="domain-map.yaml",
            )
        ]

    selected_domain_ids = set(domains) if domain_id is None else {domain_id}
    routes = [
        route for route in report.scope_inventory.routes if route.domain in selected_domain_ids
    ]
    selected_route_ids = {route.id for route in routes}
    candidates = [
        candidate
        for candidate in report.capability_candidate_ledger.candidates
        if candidate.domain_id in selected_domain_ids
        or bool(set(candidate.route_ids) & selected_route_ids)
    ]
    selected_candidate_ids = {candidate.id for candidate in candidates}
    selected_capability_ids = {
        capability_id for route in routes for capability_id in route.capability_ids
    }
    operation_dependencies = capability_operation_dependencies(report.capabilities)

    evidence_refs = {
        reference
        for route in routes
        for reference in (*route.evidence_sources, *route.usage_evidence_sources)
    }
    for domain in domains.values():
        if domain.id in selected_domain_ids:
            evidence_refs.update(domain.evidence_refs)
    for candidate in candidates:
        for claim_name in (
            "schema_",
            "effect",
            "risk",
            "reversibility",
            "approval",
            "retry",
            "conflict_control",
            "idempotency",
            "outcome_resolution",
            "lifecycle",
            "authorization_boundary",
            "identity_binding",
            "context_isolation",
        ):
            evidence_refs.update(getattr(candidate.claims, claim_name).evidence_refs)

    result: dict[str, Any] = {
        "schema_version": "2",
        "planner": "coding_agent",
        "planning_contract": {
            "quantity_basis": "evidence_derived",
            "fixed_tool_quota": "forbidden",
            "route_per_tool_default": "forbidden",
            "runtime_model_dependency": "none",
            "required_output": "intent-plan.yaml",
        },
        "denominator": {
            "scope_mode": report.scope_inventory.scope.mode,
            "total_route_count": len(report.scope_inventory.routes),
            "selected_route_count": len(routes),
            "selected_domain_id": domain_id,
        },
        "domains": [
            {
                "id": domain.id,
                "title": domain.title,
                "status": domain.status,
                "candidate_ids": domain.candidate_ids,
                "route_ids": domain.route_ids,
                "interaction_ids": domain.interaction_ids,
                "dependency_domain_ids": domain.dependency_domain_ids,
                "evidence_refs": domain.evidence_refs,
            }
            for domain in report.domain_map.domains
            if domain.id in selected_domain_ids
        ],
        "routes": [
            {
                "id": route.id,
                "domain": route.domain,
                "method": route.method,
                "path": route.path,
                "kind": route.kind,
                "effect": route.effect,
                "eligibility": route.eligibility,
                "disposition": route.disposition,
                "candidate_id": route.candidate_id,
                "interaction_ids": route.interaction_ids,
                "operation_id": route.operation_id,
                "capability_ids": route.capability_ids,
                "evidence_sources": route.evidence_sources,
                "usage_evidence_sources": route.usage_evidence_sources,
            }
            for route in routes
        ],
        "candidates": [
            {
                "id": candidate.id,
                "domain_id": candidate.domain_id,
                "business_intent": candidate.business_intent,
                "route_ids": candidate.route_ids,
                "interaction_ids": candidate.interaction_ids,
                "kind": candidate.kind_claim,
                "effect": candidate.effect_claim,
                "verification_level": candidate.verification_level,
                "blocking_gaps": list(analyze_candidate_readiness(candidate).blocking_gaps),
            }
            for candidate in candidates
        ],
        "capabilities": [
            {
                "id": capability_id,
                "kind": report.capabilities[capability_id].kind,
                "title": report.capabilities[capability_id].title,
                "operation_dependencies": list(operation_dependencies.get(capability_id, ())),
            }
            for capability_id in sorted(selected_capability_ids)
            if capability_id in report.capabilities
        ],
        "evidence": [
            {
                "source_id": evidence.source_id,
                "kind": evidence.kind,
                "path": evidence.path,
                "line_start": evidence.line_start,
                "line_end": evidence.line_end,
                "json_pointer": evidence.json_pointer,
                "openapi_operation": evidence.openapi_operation,
                "locator": evidence.locator,
                "digest": evidence.digest,
            }
            for evidence_id, evidence in sorted(report.evidence_registry.items())
            if evidence_id in evidence_refs
        ],
        "existing_intent_plan": (
            (project / "intent-plan.yaml").exists() or (project / "intent-plan.yaml").is_symlink()
        ),
        "existing_intent_plan_valid": report.intent_plan is not None,
        "existing_intent_plan_diagnostics": [
            item.model_dump(mode="json") for item in plan_diagnostics
        ],
        "unclassified_candidate_ids": [
            candidate_id
            for candidate_id in report.domain_map.unclassified_candidate_ids
            if candidate_id in selected_candidate_ids
        ],
    }
    return result, [item for item in project_diagnostics if item.severity != "error"]


def audit_project_intents(
    project: Path,
) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    """Audit the AI-authored plan against current deterministic project facts."""

    report, diagnostics = _load_planning_project(project)
    if any(item.severity == "error" for item in diagnostics):
        return None, diagnostics
    if report.intent_plan is None:
        return None, [
            _diagnostic(
                "ACC_INTENT_PLAN_REQUIRED",
                "Intent audit requires intent-plan.yaml produced by the Coding Agent.",
                path="intent-plan.yaml",
            )
        ]
    assert report.scope_inventory is not None
    assert report.domain_map is not None
    assert report.capability_candidate_ledger is not None
    analysis = audit_intent_plan(
        scope_inventory=report.scope_inventory,
        candidate_ledger=report.capability_candidate_ledger,
        domain_map=report.domain_map,
        capabilities=report.capabilities,
        qualities=report.capability_quality,
        operation_dependencies=capability_operation_dependencies(report.capabilities),
        intent_plan=report.intent_plan,
    )
    audit_diagnostics = list(analysis.diagnostics)
    if any(item.severity == "error" for item in audit_diagnostics):
        return None, audit_diagnostics
    portfolio = analysis.tool_portfolio
    recommendation_counts = Counter(intent.recommendation for intent in report.intent_plan.intents)
    confidence_counts = Counter(intent.confidence for intent in report.intent_plan.intents)
    domain_intent_counts = Counter(intent.domain_id for intent in report.intent_plan.intents)
    result: dict[str, Any] = {
        "accepted": analysis.accepted,
        "intent_count": len(report.intent_plan.intents),
        "recommendation_counts": dict(sorted(recommendation_counts.items())),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "domain_intent_counts": dict(sorted(domain_intent_counts.items())),
        "route_accounting": {
            "discovered": analysis.route_accounting.discovered,
            "assigned": list(analysis.route_accounting.assigned),
            "unassigned": list(analysis.route_accounting.unassigned),
            "multiply_assigned": list(analysis.route_accounting.multiply_assigned),
            "materializable": list(analysis.route_accounting.materializable),
            "blocked_on_evidence": list(analysis.route_accounting.blocked_on_evidence),
            "excluded": list(analysis.route_accounting.excluded),
        },
        "orphan_candidate_ids": list(analysis.orphan_candidate_ids),
        "orphan_capability_ids": list(analysis.orphan_capability_ids),
        "fragmented_business_intents": {
            key: list(value) for key, value in analysis.fragmented_business_intents.items()
        },
        "suggested_next_domains": [
            {
                "domain_id": item.domain_id,
                "dependency_domain_ids": list(item.dependency_domain_ids),
                "ready_candidate_ids": list(item.ready_candidate_ids),
                "blocked_candidate_ids": list(item.blocked_candidate_ids),
            }
            for item in analysis.suggested_next_domains
        ],
        "portfolio": {
            "capability_count": len(report.capabilities),
            "projected_mcp_tool_count": portfolio.projected_mcp_tool_count,
            "projected_mcp_tool_names": list(portfolio.projected_mcp_tool_names),
            "blocked_route_count": portfolio.blocked_route_count,
            "covered_route_ids": list(portfolio.covered_route_ids),
            "uncovered_materialized_route_ids": list(portfolio.uncovered_materialized_route_ids),
            "quantity_target": None,
        },
    }
    return result, [*diagnostics, *audit_diagnostics]


__all__ = ["audit_project_intents", "build_intent_brief"]
