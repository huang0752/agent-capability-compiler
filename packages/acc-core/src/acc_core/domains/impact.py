"""Pure, deterministic Evidence impact analysis for versioned domain decisions."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence, Set
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

from acc_core.domains.models import (
    CapabilityCandidate,
    CapabilityCandidateLedger,
    ChangedEvidenceRef,
    DomainChangeRequest,
    DomainDecision,
    DomainEntry,
    DomainMap,
    DomainModel,
    UtcTimestamp,
    domain_decision_digest,
)
from acc_core.interactions import CapabilityInteractionContract, UIInteractionInventory
from acc_core.models import Capability, Evidence, Operation
from acc_core.scope import ScopeInventory

if TYPE_CHECKING:
    from acc_core.validation import ValidationReport

_SECURITY_CLAIM_AXES = frozenset(
    {
        "approval",
        "authorization_boundary",
        "conflict_control",
        "context_isolation",
        "effect",
        "idempotency",
        "identity_binding",
        "outcome_resolution",
        "risk",
    }
)
_ACTION_SECURITY_CLAIM_AXES = frozenset(
    {"ineligibility", "lifecycle", "retry", "reversibility", "schema"}
)


class EvidenceChangeSet(DomainModel):
    """Bounded, typed input produced by an external deterministic change locator."""

    schema_version: Literal["2"]
    observed_at: UtcTimestamp
    changed_evidence: Annotated[list[ChangedEvidenceRef], Field(min_length=1, max_length=1000)]

    @model_validator(mode="after")
    def validate_stable_order(self) -> EvidenceChangeSet:
        evidence_ids = [item.evidence_ref for item in self.changed_evidence]
        if evidence_ids != sorted(set(evidence_ids)):
            raise ValueError("changed evidence must use sorted unique references")
        return self


@dataclass(frozen=True, slots=True)
class DomainEvidenceImpact:
    """Exact impact facts for one directly or transitively affected domain."""

    domain_id: str
    direct: bool
    upstream_domain_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    affected_candidate_ids: tuple[str, ...]
    affected_capability_ids: tuple[str, ...]
    security_axes: tuple[str, ...]

    @property
    def impact_class(self) -> str:
        return "security_relevant" if self.security_axes else "descriptive_only"


@dataclass(frozen=True, slots=True)
class DomainImpactAnalysis:
    """Stable graph result without source content, Git state, or inferred permissions."""

    domains: tuple[DomainEvidenceImpact, ...]
    affected_domain_ids: tuple[str, ...]
    stale_domain_ids: tuple[str, ...]
    unaffected_domain_ids: tuple[str, ...]
    matched_evidence_ids: tuple[str, ...]
    unmatched_evidence_ids: tuple[str, ...]
    unmatched_evidence_digests: tuple[str, ...]
    changed_evidence: tuple[ChangedEvidenceRef, ...]
    evidence_graph_scope: Literal["candidate_only", "provided_documents", "validated_project"]

    def domain(self, domain_id: str) -> DomainEvidenceImpact:
        for item in self.domains:
            if item.domain_id == domain_id:
                return item
        raise KeyError(domain_id)


@dataclass(frozen=True, slots=True)
class _EvidenceBinding:
    evidence_ref: str
    domain_id: str
    candidate_id: str | None
    capability_id: str | None
    axis: str | None
    security_relevant: bool
    digests: tuple[str, ...]


@dataclass(slots=True)
class _MutableDomainImpact:
    direct: bool
    upstream_domain_ids: set[str]
    evidence_refs: set[str]
    candidate_ids: set[str]
    capability_ids: set[str]
    security_axes: set[str]


def _claim_evidence(candidate: CapabilityCandidate) -> list[tuple[str, str]]:
    claims = candidate.claims
    output: list[tuple[str, str]] = []
    for axis in claims.__class__.model_fields:
        claim = getattr(claims, axis)
        output.extend((evidence_ref, axis.rstrip("_")) for evidence_ref in claim.evidence_refs)
    ineligibility = getattr(candidate, "ineligibility_claim", None)
    if ineligibility is not None:
        output.extend(
            (evidence_ref, "ineligibility") for evidence_ref in ineligibility.evidence_refs
        )
    return output


def _decision_values(
    decisions: Mapping[Any, DomainDecision] | Sequence[DomainDecision],
) -> tuple[DomainDecision, ...]:
    values = decisions.values() if isinstance(decisions, Mapping) else decisions
    return tuple(
        sorted(
            values,
            key=lambda item: (item.domain_id, item.revision, domain_decision_digest(item)),
        )
    )


def _active_decisions(
    domain_map: DomainMap,
    decisions: Mapping[Any, DomainDecision] | Sequence[DomainDecision],
) -> dict[str, DomainDecision]:
    values = _decision_values(decisions)
    active: dict[str, DomainDecision] = {}
    for domain in domain_map.domains:
        reference = domain.active_decision_ref
        if reference is None:
            continue
        matches = [
            decision
            for decision in values
            if decision.domain_id == reference.domain_id
            and decision.revision == reference.revision
            and domain_decision_digest(decision) == reference.decision_digest
        ]
        if len(matches) == 1:
            active[domain.id] = matches[0]
    return active


def _accepted_capabilities(
    domain_map: DomainMap,
    decisions: Mapping[Any, DomainDecision] | Sequence[DomainDecision],
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for decision in _active_decisions(domain_map, decisions).values():
        for disposition in decision.candidate_dispositions:
            if disposition.disposition == "accepted":
                result[disposition.candidate_id].update(disposition.materialized_capability_ids)
    return result


def _build_bindings(
    *,
    domain_map: DomainMap,
    candidates: CapabilityCandidateLedger,
    decisions: Mapping[Any, DomainDecision] | Sequence[DomainDecision],
    capabilities: Mapping[str, Capability],
    operations: Mapping[str, Operation],
    scope_inventory: ScopeInventory | None,
    interactions: UIInteractionInventory | None,
    interaction_contracts: Mapping[str, CapabilityInteractionContract],
    evidence_registry: Mapping[str, Evidence],
) -> tuple[_EvidenceBinding, ...]:
    domains = {domain.id: domain for domain in domain_map.domains}
    mutable: dict[tuple[str, str, str | None, str | None, str | None, bool], set[str]] = (
        defaultdict(set)
    )

    def add(
        evidence_ref: str,
        domain_id: str,
        *,
        candidate_id: str | None = None,
        capability_id: str | None = None,
        axis: str | None = None,
        security_relevant: bool = False,
        digest: str | None = None,
    ) -> None:
        key = (
            evidence_ref,
            domain_id,
            candidate_id,
            capability_id,
            axis,
            security_relevant,
        )
        if digest is not None:
            mutable[key].add(digest)
        else:
            mutable[key]

    for domain in domain_map.domains:
        for evidence_ref in domain.evidence_refs:
            add(evidence_ref, domain.id)

    for candidate in candidates.candidates:
        if candidate.domain_id not in domains:
            continue
        assert candidate.domain_id is not None
        for evidence_ref, axis in _claim_evidence(candidate):
            security_relevant = axis in _SECURITY_CLAIM_AXES or (
                candidate.kind_claim == "action" and axis in _ACTION_SECURITY_CLAIM_AXES
            )
            add(
                evidence_ref,
                candidate.domain_id,
                candidate_id=candidate.id,
                axis=axis,
                security_relevant=security_relevant,
            )

    candidates_by_id = {candidate.id: candidate for candidate in candidates.candidates}
    capabilities_by_candidate = _accepted_capabilities(domain_map, decisions)
    for candidate_id, capability_ids in sorted(capabilities_by_candidate.items()):
        materialized_candidate = candidates_by_id.get(candidate_id)
        if materialized_candidate is None or materialized_candidate.domain_id not in domains:
            continue
        assert materialized_candidate.domain_id is not None
        security_axis = (
            "operation_safety"
            if materialized_candidate.kind_claim == "action"
            else "operation_contract"
        )
        interaction_axis = (
            "interaction_semantics"
            if materialized_candidate.kind_claim == "action"
            else "interaction_contract"
        )
        for capability_id in sorted(capability_ids):
            capability = capabilities.get(capability_id)
            if capability is not None:
                for operation_id in _capability_operation_ids(capability):
                    operation = operations.get(operation_id)
                    if operation is None:
                        continue
                    for evidence in operation.evidence:
                        add(
                            evidence.source_id,
                            materialized_candidate.domain_id,
                            candidate_id=materialized_candidate.id,
                            capability_id=capability_id,
                            axis=security_axis,
                            security_relevant=materialized_candidate.kind_claim == "action",
                            digest=evidence.digest,
                        )
            contract = interaction_contracts.get(capability_id)
            if contract is not None:
                for evidence in _embedded_evidence(contract):
                    add(
                        evidence.source_id,
                        materialized_candidate.domain_id,
                        candidate_id=materialized_candidate.id,
                        capability_id=capability_id,
                        axis=interaction_axis,
                        security_relevant=materialized_candidate.kind_claim == "action",
                        digest=evidence.digest,
                    )

    interaction_by_id = (
        {item.id: item for item in interactions.interactions} if interactions is not None else {}
    )
    surfaces_by_id = (
        {item.id: item for item in interactions.surfaces} if interactions is not None else {}
    )
    for candidate in candidates.candidates:
        if candidate.domain_id not in domains:
            continue
        assert candidate.domain_id is not None
        interaction_axis = (
            "interaction_semantics" if candidate.kind_claim == "action" else "interaction_contract"
        )
        for interaction_id in candidate.interaction_ids:
            interaction = interaction_by_id.get(interaction_id)
            if interaction is None:
                continue
            for evidence in _embedded_evidence(interaction):
                add(
                    evidence.source_id,
                    candidate.domain_id,
                    candidate_id=candidate.id,
                    axis=interaction_axis,
                    security_relevant=candidate.kind_claim == "action",
                    digest=evidence.digest,
                )
            surface = surfaces_by_id.get(interaction.surface_id)
            if surface is not None:
                for evidence_ref in surface.evidence_sources:
                    add(
                        evidence_ref,
                        candidate.domain_id,
                        candidate_id=candidate.id,
                        axis=interaction_axis,
                        security_relevant=candidate.kind_claim == "action",
                    )

    scope_routes = (
        {route.id: route for route in scope_inventory.routes} if scope_inventory is not None else {}
    )
    for candidate in candidates.candidates:
        if candidate.domain_id not in domains:
            continue
        assert candidate.domain_id is not None
        for route_id in candidate.route_ids:
            route = scope_routes.get(route_id)
            if (
                route is None
                or route.operation_id is None
                or route.disposition not in {"planned", "composed"}
                or route.eligibility != "eligible"
                or route.kind == "unknown"
                or (route.candidate_id is not None and route.candidate_id != candidate.id)
            ):
                continue
            operation = operations.get(route.operation_id)
            if operation is None:
                continue
            axis = "operation_safety" if candidate.kind_claim == "action" else "operation_contract"
            for evidence in operation.evidence:
                if route.capability_ids:
                    for capability_id in route.capability_ids:
                        add(
                            evidence.source_id,
                            candidate.domain_id,
                            candidate_id=candidate.id,
                            capability_id=capability_id,
                            axis=axis,
                            security_relevant=candidate.kind_claim == "action",
                            digest=evidence.digest,
                        )
                else:
                    add(
                        evidence.source_id,
                        candidate.domain_id,
                        candidate_id=candidate.id,
                        axis=axis,
                        security_relevant=candidate.kind_claim == "action",
                        digest=evidence.digest,
                    )

    active = _active_decisions(domain_map, decisions)
    for domain_id, decision in active.items():
        for snapshot in decision.evidence_snapshot:
            matching_keys = [
                key for key in mutable if key[0] == snapshot.evidence_ref and key[1] == domain_id
            ]
            if matching_keys:
                for key in matching_keys:
                    mutable[key].add(snapshot.digest)
            else:
                add(snapshot.evidence_ref, domain_id, digest=snapshot.digest)

    registry_by_ref = {evidence.source_id: evidence for evidence in evidence_registry.values()}
    for key in list(mutable):
        registry_evidence = registry_by_ref.get(key[0])
        if registry_evidence is not None:
            mutable[key].add(registry_evidence.digest)

    return tuple(
        _EvidenceBinding(
            evidence_ref=key[0],
            domain_id=key[1],
            candidate_id=key[2],
            capability_id=key[3],
            axis=key[4],
            security_relevant=key[5],
            digests=tuple(sorted(digests)),
        )
        for key, digests in sorted(
            mutable.items(),
            key=lambda item: tuple(part or "" for part in item[0]),
        )
    )


def _capability_operation_ids(capability: Capability) -> tuple[str, ...]:
    operation_ids: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            call = value.get("call")
            if isinstance(call, Mapping):
                operation_id = call.get("operation")
                if isinstance(operation_id, str):
                    operation_ids.add(operation_id)
            for item in value.values():
                visit(item)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                visit(item)

    visit(capability.model_dump(mode="json", by_alias=True))
    return tuple(sorted(operation_ids))


def _embedded_evidence(value: object) -> Iterable[Evidence]:
    if isinstance(value, Evidence):
        yield value
        return
    if isinstance(value, BaseModel):
        for field_name in value.__class__.model_fields:
            yield from _embedded_evidence(getattr(value, field_name))
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _embedded_evidence(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            yield from _embedded_evidence(item)


def _all_domain_candidate_ids(domain: DomainEntry) -> set[str]:
    return set(domain.candidate_ids)


def _direct_impacts(
    *,
    bindings: Sequence[_EvidenceBinding],
    domains: Mapping[str, DomainEntry],
    capabilities_by_candidate: Mapping[str, set[str]],
    changed_ids: set[str],
    changed_digests: set[str],
    structured_deltas: Mapping[str, ChangedEvidenceRef],
) -> tuple[dict[str, _MutableDomainImpact], set[str], set[str]]:
    impacts: dict[str, _MutableDomainImpact] = {}
    matched_ids: set[str] = set()
    matched_digests: set[str] = set()
    for binding in bindings:
        delta = structured_deltas.get(binding.evidence_ref)
        delta_digests = (
            {digest for digest in (delta.old_digest, delta.new_digest) if digest is not None}
            if delta is not None
            else set()
        )
        id_match = binding.evidence_ref in changed_ids or bool(set(binding.digests) & delta_digests)
        digest_matches = set(binding.digests) & changed_digests
        if not id_match and not digest_matches:
            continue
        matched_ids.add(binding.evidence_ref)
        matched_digests.update(digest_matches)
        impact = impacts.setdefault(
            binding.domain_id,
            _MutableDomainImpact(True, set(), set(), set(), set(), set()),
        )
        impact.evidence_refs.add(binding.evidence_ref)
        if binding.candidate_id is None:
            impact.candidate_ids.update(_all_domain_candidate_ids(domains[binding.domain_id]))
        else:
            impact.candidate_ids.add(binding.candidate_id)
        if binding.capability_id is not None:
            impact.capability_ids.add(binding.capability_id)
        if binding.security_relevant and binding.axis is not None:
            impact.security_axes.add(binding.axis)

    for impact in impacts.values():
        for candidate_id in impact.candidate_ids:
            impact.capability_ids.update(capabilities_by_candidate.get(candidate_id, set()))
    return impacts, matched_ids, matched_digests


def _propagate_dependencies(
    *,
    domains: Mapping[str, DomainEntry],
    impacts: dict[str, _MutableDomainImpact],
    capabilities_by_candidate: Mapping[str, set[str]],
) -> None:
    dependents: dict[str, set[str]] = defaultdict(set)
    for domain in domains.values():
        for dependency_id in domain.dependency_domain_ids:
            dependents[dependency_id].add(domain.id)

    queue = deque(sorted(impacts))
    while queue:
        changed_domain_id = queue.popleft()
        changed = impacts[changed_domain_id]
        source_ids = {changed_domain_id, *changed.upstream_domain_ids}
        for dependent_id in sorted(dependents.get(changed_domain_id, set())):
            dependent = impacts.get(dependent_id)
            created = dependent is None
            if dependent is None:
                candidate_ids = _all_domain_candidate_ids(domains[dependent_id])
                capability_ids = {
                    capability_id
                    for candidate_id in candidate_ids
                    for capability_id in capabilities_by_candidate.get(candidate_id, set())
                }
                dependent = _MutableDomainImpact(
                    False,
                    set(),
                    set(),
                    candidate_ids,
                    capability_ids,
                    set(),
                )
                impacts[dependent_id] = dependent
            before = (
                len(dependent.upstream_domain_ids),
                len(dependent.evidence_refs),
                len(dependent.security_axes),
            )
            dependent.upstream_domain_ids.update(source_ids)
            dependent.evidence_refs.update(changed.evidence_refs)
            dependent.security_axes.update(
                f"dependency:{axis.removeprefix('dependency:')}" for axis in changed.security_axes
            )
            after = (
                len(dependent.upstream_domain_ids),
                len(dependent.evidence_refs),
                len(dependent.security_axes),
            )
            if created or after != before:
                queue.append(dependent_id)


def analyze_domain_impact(
    *,
    domain_map: DomainMap,
    candidates: CapabilityCandidateLedger,
    decisions: Mapping[Any, DomainDecision] | Sequence[DomainDecision],
    capabilities: Mapping[str, Capability] | None = None,
    operations: Mapping[str, Operation] | None = None,
    scope_inventory: ScopeInventory | None = None,
    interactions: UIInteractionInventory | None = None,
    interaction_contracts: Mapping[str, CapabilityInteractionContract] | None = None,
    evidence_registry: Mapping[str, Evidence] | None = None,
    changed_evidence_ids: Set[str] = frozenset(),
    changed_evidence_digests: Set[str] = frozenset(),
    changed_evidence: Sequence[ChangedEvidenceRef] = (),
    _evidence_graph_scope: Literal["candidate_only", "provided_documents", "validated_project"]
    | None = None,
) -> DomainImpactAnalysis:
    """Trace exact changed Evidence through candidates and domain dependencies.

    The analyzer has no Git, filesystem, LLM, JWT, or source-permission behavior. The
    source API therefore remains the final authorization authority at execution time.
    """

    deltas = tuple(sorted(changed_evidence, key=lambda item: item.evidence_ref))
    if len({item.evidence_ref for item in deltas}) != len(deltas):
        raise ValueError("changed evidence references must be unique")
    structured_deltas = {item.evidence_ref: item for item in deltas}
    requested_ids = set(changed_evidence_ids) | set(structured_deltas)
    requested_digests = set(changed_evidence_digests)

    domains = {domain.id: domain for domain in domain_map.domains}
    capabilities_by_candidate = _accepted_capabilities(domain_map, decisions)
    bindings = _build_bindings(
        domain_map=domain_map,
        candidates=candidates,
        decisions=decisions,
        capabilities=capabilities or {},
        operations=operations or {},
        scope_inventory=scope_inventory,
        interactions=interactions,
        interaction_contracts=interaction_contracts or {},
        evidence_registry=evidence_registry or {},
    )
    impacts, matched_ids, matched_digests = _direct_impacts(
        bindings=bindings,
        domains=domains,
        capabilities_by_candidate=capabilities_by_candidate,
        changed_ids=set(changed_evidence_ids),
        changed_digests=requested_digests,
        structured_deltas=structured_deltas,
    )
    _propagate_dependencies(
        domains=domains,
        impacts=impacts,
        capabilities_by_candidate=capabilities_by_candidate,
    )

    domain_impacts = tuple(
        DomainEvidenceImpact(
            domain_id=domain_id,
            direct=impact.direct,
            upstream_domain_ids=tuple(sorted(impact.upstream_domain_ids - {domain_id})),
            evidence_refs=tuple(sorted(impact.evidence_refs)),
            affected_candidate_ids=tuple(sorted(impact.candidate_ids)),
            affected_capability_ids=tuple(sorted(impact.capability_ids)),
            security_axes=tuple(sorted(impact.security_axes)),
        )
        for domain_id, impact in sorted(impacts.items())
    )
    affected_ids = tuple(item.domain_id for item in domain_impacts)
    stale_ids = tuple(
        item.domain_id
        for item in domain_impacts
        if domains[item.domain_id].active_decision_ref is not None
    )
    unmatched_raw_digests = set(changed_evidence_digests) - matched_digests
    return DomainImpactAnalysis(
        domains=domain_impacts,
        affected_domain_ids=affected_ids,
        stale_domain_ids=stale_ids,
        unaffected_domain_ids=tuple(sorted(set(domains) - set(affected_ids))),
        matched_evidence_ids=tuple(sorted(matched_ids)),
        unmatched_evidence_ids=tuple(sorted(requested_ids - matched_ids)),
        unmatched_evidence_digests=tuple(sorted(unmatched_raw_digests)),
        changed_evidence=deltas,
        evidence_graph_scope=(
            _evidence_graph_scope
            or (
                "provided_documents"
                if any(
                    (
                        capabilities,
                        operations,
                        scope_inventory,
                        interactions,
                        interaction_contracts,
                        evidence_registry,
                    )
                )
                else "candidate_only"
            )
        ),
    )


def analyze_project_domain_impact(
    *,
    report: ValidationReport,
    changed_evidence_ids: Set[str] = frozenset(),
    changed_evidence_digests: Set[str] = frozenset(),
    changed_evidence: Sequence[ChangedEvidenceRef] = (),
) -> DomainImpactAnalysis:
    """Analyze the complete typed Evidence graph from one valid project report."""

    if not report.ok or report.domain_map is None or report.capability_candidate_ledger is None:
        raise ValueError("impact analysis requires a valid typed domain Project")
    return analyze_domain_impact(
        domain_map=report.domain_map,
        candidates=report.capability_candidate_ledger,
        decisions=report.domain_decisions,
        capabilities=report.capabilities,
        operations=report.operations,
        scope_inventory=report.scope_inventory,
        interactions=report.ui_interaction_inventory,
        interaction_contracts=report.interaction_contracts,
        evidence_registry=report.evidence_registry,
        changed_evidence_ids=changed_evidence_ids,
        changed_evidence_digests=changed_evidence_digests,
        changed_evidence=changed_evidence,
        _evidence_graph_scope="validated_project",
    )


def _change_request_id(
    *,
    impact: DomainEvidenceImpact,
    previous_decision: DomainDecision,
    changed_evidence: Sequence[ChangedEvidenceRef],
    created_at: str,
) -> str:
    payload = {
        "domain_id": impact.domain_id,
        "previous_revision": previous_decision.revision,
        "previous_digest": domain_decision_digest(previous_decision),
        "affected_candidate_ids": list(impact.affected_candidate_ids),
        "affected_capability_ids": list(impact.affected_capability_ids),
        "changed_evidence": [item.model_dump(mode="json") for item in changed_evidence],
        "security_axes": list(impact.security_axes),
        "created_at": created_at,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    suffix = hashlib.sha256(encoded).hexdigest()[:20]
    return f"domain-change.{impact.domain_id}.{previous_decision.revision}.{suffix}"


def build_change_request(
    *,
    impact: DomainEvidenceImpact,
    previous_decision: DomainDecision,
    changed_evidence: Sequence[ChangedEvidenceRef],
    created_at: str = "1970-01-01T00:00:00Z",
) -> DomainChangeRequest:
    """Build one deterministic proposed request bound to an exact prior decision."""

    if previous_decision.domain_id != impact.domain_id:
        raise ValueError("impact and previous decision must belong to the same domain")
    relevant = tuple(
        sorted(
            (item for item in changed_evidence if item.evidence_ref in impact.evidence_refs),
            key=lambda item: item.evidence_ref,
        )
    )
    if not relevant:
        raise ValueError("change request requires an exact changed Evidence delta")

    recommended_document = previous_decision.model_dump(mode="json", by_alias=True)
    recommended_document.update(
        {
            "revision": previous_decision.revision + 1,
            "status": "stale",
            "user_confirmation": None,
        }
    )
    recommended_decision = DomainDecision.model_validate(recommended_document)
    security_relevant = bool(impact.security_axes)
    return DomainChangeRequest.model_validate(
        {
            "schema_version": "2",
            "id": _change_request_id(
                impact=impact,
                previous_decision=previous_decision,
                changed_evidence=relevant,
                created_at=created_at,
            ),
            "domain_id": impact.domain_id,
            "status": "proposed",
            "created_at": created_at,
            "previous_decision": {
                "domain_id": previous_decision.domain_id,
                "revision": previous_decision.revision,
                "decision_digest": domain_decision_digest(previous_decision),
            },
            "affected_candidate_ids": list(impact.affected_candidate_ids),
            "affected_capability_ids": list(impact.affected_capability_ids),
            "changed_evidence": [item.model_dump(mode="json") for item in relevant],
            "impact_class": ("security_relevant" if security_relevant else "descriptive_only"),
            "recommended_domain_status": "stale",
            "recommended_decision_digest": domain_decision_digest(recommended_decision),
            "deployment_effect": (
                "disable_affected_capabilities" if security_relevant else "audit_warning"
            ),
            "impact_summary": (
                f"Evidence change affects domain {impact.domain_id}: "
                f"{len(impact.affected_candidate_ids)} candidate(s), "
                f"{len(impact.affected_capability_ids)} capability(s)."
            ),
            "confirmation": None,
            "applied_decision_ref": None,
        }
    )


__all__ = [
    "DomainEvidenceImpact",
    "DomainImpactAnalysis",
    "EvidenceChangeSet",
    "analyze_domain_impact",
    "analyze_project_domain_impact",
    "build_change_request",
]
