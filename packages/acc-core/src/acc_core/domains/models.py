"""Strict platform-neutral contracts for domain-guided capability discovery."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    PositiveInt,
    field_validator,
    model_validator,
)

from acc_core.models import Sha256Digest, StrictModel
from acc_core.models.actions import Effect, Risk


def _clean_string(value: str) -> str:
    if value != value.strip():
        raise ValueError("value must not contain surrounding whitespace")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise ValueError("value must not contain control or surrogate characters")
    return value


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=512),
    AfterValidator(_clean_string),
]
BoundedText = Annotated[
    str,
    Field(min_length=1, max_length=16_384),
    AfterValidator(_clean_string),
]


def _utc_timestamp(value: str) -> str:
    _clean_string(value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be an RFC 3339 UTC time") from None
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return value


UtcTimestamp = Annotated[
    str,
    Field(min_length=20, max_length=40),
    AfterValidator(_utc_timestamp),
]

type DomainStatus = Literal[
    "not_started",
    "in_progress",
    "awaiting_user",
    "validation_failed",
    "ready_for_review",
    "completed",
    "stale",
]
type VerificationLevel = Literal[
    "discovered",
    "action_discovered",
    "semantics_evidenced",
    "contract_ready",
    "offline_verified",
    "sandbox_verified",
    "source_connected_verified",
]


class DomainModel(StrictModel):
    """Frozen secret-safe base shared only by domain-discovery sidecars."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)


def _sorted_unique(value: list[str]) -> list[str]:
    if value != sorted(set(value)):
        raise ValueError("identifier lists must be sorted and unique")
    return value


def _json_value(value: object) -> object:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return value


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        _json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def aggregate_reference_digest(references: Sequence[object]) -> str:
    """Digest one already sorted reference ledger without omitting details."""

    return _canonical_digest(references)


class DomainDecisionRef(DomainModel):
    domain_id: Identifier
    revision: PositiveInt
    decision_digest: Sha256Digest


class DomainEntry(DomainModel):
    id: Identifier
    title: BoundedText
    status: DomainStatus
    candidate_ids: list[Identifier]
    route_ids: list[Identifier]
    interaction_ids: list[Identifier]
    dependency_domain_ids: list[Identifier]
    evidence_refs: list[Identifier]
    active_decision_ref: DomainDecisionRef | None

    @field_validator(
        "candidate_ids",
        "route_ids",
        "interaction_ids",
        "dependency_domain_ids",
        "evidence_refs",
    )
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def reject_self_dependency(self) -> Self:
        if self.id in self.dependency_domain_ids:
            raise ValueError("a domain cannot depend on itself")
        if self.status in {"completed", "stale"}:
            if self.active_decision_ref is None:
                raise ValueError("a completed or stale domain requires an active decision ref")
            if self.active_decision_ref.domain_id != self.id:
                raise ValueError("an active decision ref must belong to the same domain")
        elif self.active_decision_ref is not None:
            raise ValueError("only a completed or stale domain may have an active decision ref")
        return self


class DomainMap(DomainModel):
    schema_version: Literal["2"]
    domains: list[DomainEntry]
    unclassified_candidate_ids: list[Identifier]
    preferred_order: list[Identifier] = Field(default_factory=list)

    @field_validator("unclassified_candidate_ids")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @field_validator("preferred_order")
    @classmethod
    def validate_preferred_order(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("preferred_order must contain unique identifiers")
        return value

    @model_validator(mode="after")
    def validate_graph_and_candidate_identity(self) -> Self:
        domain_ids = [domain.id for domain in self.domains]
        if domain_ids != sorted(set(domain_ids)):
            raise ValueError("domains must be sorted by unique identifiers")
        domain_id_set = set(domain_ids)
        for domain in self.domains:
            if not set(domain.dependency_domain_ids) <= domain_id_set:
                raise ValueError("domain dependencies must reference known domains")

        seen_candidates: set[str] = set()
        for candidate_id in (
            candidate for domain in self.domains for candidate in domain.candidate_ids
        ):
            if candidate_id in seen_candidates:
                raise ValueError("a candidate ID may occur at most once in a DomainMap")
            seen_candidates.add(candidate_id)
        for candidate_id in self.unclassified_candidate_ids:
            if candidate_id in seen_candidates:
                raise ValueError("a candidate ID may occur at most once in a DomainMap")
            seen_candidates.add(candidate_id)

        if (
            self.preferred_order
            and self.preferred_order != domain_ids
            and set(self.preferred_order) != domain_id_set
        ):
            raise ValueError("preferred_order must be a complete domain permutation")

        dependencies = {domain.id: set(domain.dependency_domain_ids) for domain in self.domains}
        remaining = {domain_id: set(values) for domain_id, values in dependencies.items()}
        while remaining:
            ready = sorted(
                domain_id
                for domain_id, values in remaining.items()
                if not values & remaining.keys()
            )
            if not ready:
                raise ValueError("domain dependency graph contains a cycle")
            for domain_id in ready:
                remaining.pop(domain_id)
        return self


type FactClaimStatus = Literal["unknown", "missing", "candidate", "proven", "contradicted", "stale"]


class _EvidenceClaim(DomainModel):
    evidence_refs: list[Identifier] = Field(default_factory=list)

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)


class FactClaim(_EvidenceClaim):
    status: FactClaimStatus

    @model_validator(mode="after")
    def authoritative_status_requires_evidence(self) -> Self:
        if self.status in {"proven", "contradicted", "stale"} and not self.evidence_refs:
            raise ValueError("authoritative claim requires evidence")
        return self


class AuthorizationBoundaryClaim(_EvidenceClaim):
    status: Literal["unknown", "upstream_authoritative", "contradicted", "stale"]

    @model_validator(mode="after")
    def authoritative_status_requires_evidence(self) -> Self:
        if self.status != "unknown" and not self.evidence_refs:
            raise ValueError("authoritative claim requires evidence")
        return self


class IdentityBindingClaim(_EvidenceClaim):
    status: Literal[
        "unknown",
        "missing",
        "candidate",
        "identity_binding_proven",
        "contradicted",
        "stale",
    ]

    @model_validator(mode="after")
    def authoritative_status_requires_evidence(self) -> Self:
        if (
            self.status
            in {
                "identity_binding_proven",
                "contradicted",
                "stale",
            }
            and not self.evidence_refs
        ):
            raise ValueError("authoritative claim requires evidence")
        return self


class ContextIsolationClaim(_EvidenceClaim):
    status: Literal[
        "unknown",
        "missing",
        "candidate",
        "context_isolation_proven",
        "contradicted",
        "stale",
    ]

    @model_validator(mode="after")
    def authoritative_status_requires_evidence(self) -> Self:
        if (
            self.status
            in {
                "context_isolation_proven",
                "contradicted",
                "stale",
            }
            and not self.evidence_refs
        ):
            raise ValueError("authoritative claim requires evidence")
        return self


class CandidateClaims(DomainModel):
    schema_: FactClaim = Field(alias="schema")
    effect: FactClaim
    risk: FactClaim
    reversibility: FactClaim
    approval: FactClaim
    retry: FactClaim
    conflict_control: FactClaim
    idempotency: FactClaim
    outcome_resolution: FactClaim
    lifecycle: FactClaim
    authorization_boundary: AuthorizationBoundaryClaim
    identity_binding: IdentityBindingClaim
    context_isolation: ContextIsolationClaim


class CapabilityCandidate(DomainModel):
    id: Identifier
    domain_id: Identifier | None
    business_intent: Identifier
    route_ids: list[Identifier]
    interaction_ids: list[Identifier]
    kind_claim: Literal["unknown", "read", "action"]
    effect_claim: Literal["unknown", "read", "create", "update", "delete", "transition", "execute"]
    claims: CandidateClaims
    verification_level: VerificationLevel
    gaps: list[Identifier]
    ineligibility_claim: FactClaim | None = None

    @field_validator("route_ids", "interaction_ids", "gaps")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)


class CapabilityCandidateLedger(DomainModel):
    schema_version: Literal["2"]
    candidates: list[CapabilityCandidate]

    @model_validator(mode="after")
    def validate_candidate_order(self) -> Self:
        candidate_ids = [candidate.id for candidate in self.candidates]
        if candidate_ids != sorted(set(candidate_ids)):
            raise ValueError("candidates must be sorted by unique identifiers")
        return self


class DomainPolicy(DomainModel):
    """Business choices only; source permissions are intentionally not representable."""

    goals: Annotated[list[Identifier], Field(min_length=1)]
    allowed_effects: Annotated[list[Effect], Field(min_length=1)]
    maximum_risk: Risk
    approval_required_for: list[Identifier]
    excluded_intents: list[Identifier]

    @field_validator("goals", "allowed_effects", "approval_required_for", "excluded_intents")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_business_sets(self) -> Self:
        goals = set(self.goals)
        if goals & set(self.excluded_intents):
            raise ValueError("goals and excluded intents must be disjoint")
        if not set(self.approval_required_for) <= goals:
            raise ValueError("approval_required_for must be a subset of goals")
        return self


class UserDecision(DomainModel):
    kind: Literal["domain_policy", "candidate_disposition", "domain_completion", "change_request"]
    subject_ref: Identifier
    decision: Literal["confirmed", "accepted", "deferred", "rejected", "blocked", "approved"]
    rationale: BoundedText

    @model_validator(mode="after")
    def validate_kind_decision(self) -> Self:
        allowed = {
            "domain_policy": {"confirmed"},
            "candidate_disposition": {"accepted", "deferred", "rejected", "blocked"},
            "domain_completion": {"confirmed"},
            "change_request": {"approved", "deferred", "rejected"},
        }
        if self.decision not in allowed[self.kind]:
            raise ValueError("user decision is invalid for its kind")
        return self


class UserConfirmation(DomainModel):
    confirmer_ref: Identifier
    authority: Literal["authenticated_user", "delegated_reviewer"]
    confirmation_summary: BoundedText
    source_evidence_ref: Identifier
    source_text_digest: Sha256Digest
    confirmed_at: UtcTimestamp
    confirmed_decision_digest: Sha256Digest
    decisions: Annotated[list[UserDecision], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_confirmation(self) -> Self:
        identities = [(decision.kind, decision.subject_ref) for decision in self.decisions]
        if identities != sorted(set(identities)):
            raise ValueError("user decisions must be sorted and unique")
        return self


class CandidateDisposition(DomainModel):
    candidate_id: Identifier
    disposition: Literal["accepted", "deferred", "rejected", "blocked"]
    materialized_capability_ids: list[Identifier]
    rationale: BoundedText

    @field_validator("materialized_capability_ids")
    @classmethod
    def validate_materialized_capability_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def only_accepted_candidates_materialize(self) -> Self:
        if self.disposition == "accepted" and not self.materialized_capability_ids:
            raise ValueError("accepted candidate must materialize at least one capability")
        if self.disposition != "accepted" and self.materialized_capability_ids:
            raise ValueError("only accepted candidates may materialize capabilities")
        return self


class DependencyDecisionRef(DomainDecisionRef):
    pass


class EvidenceSnapshotRef(DomainModel):
    evidence_ref: Identifier
    digest: Sha256Digest


def domain_decision_digest(value: DomainDecision | Mapping[str, Any]) -> str:
    """Digest all decision facts while intentionally excluding confirmation metadata."""

    if isinstance(value, DomainDecision):
        document = value.model_dump(mode="json", by_alias=True)
    else:
        document = dict(value)
    document.pop("user_confirmation", None)
    return _canonical_digest(document)


class DomainDecision(DomainModel):
    schema_version: Literal["2"]
    domain_id: Identifier
    revision: PositiveInt
    status: Literal["ready_for_review", "completed", "stale"]
    policy: DomainPolicy
    candidate_dispositions: list[CandidateDisposition]
    candidate_snapshot_ids: list[Identifier]
    candidate_snapshot_digest: Sha256Digest
    candidate_ledger_digest: Sha256Digest
    unresolved_questions: list[BoundedText]
    dependency_decisions: list[DependencyDecisionRef]
    evidence_snapshot: list[EvidenceSnapshotRef]
    dependency_snapshot_digest: Sha256Digest
    evidence_digest: Sha256Digest
    user_confirmation: UserConfirmation | None

    @field_validator("candidate_snapshot_ids")
    @classmethod
    def validate_candidate_snapshot_ids(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("candidate snapshot must not be empty")
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_decision_closure(self) -> Self:
        disposition_ids = [item.candidate_id for item in self.candidate_dispositions]
        if disposition_ids != sorted(set(disposition_ids)):
            raise ValueError("candidate_dispositions require sorted unique candidate IDs")
        if disposition_ids != self.candidate_snapshot_ids:
            raise ValueError("candidate dispositions must exactly match candidate snapshot IDs")
        if self.candidate_snapshot_digest != aggregate_reference_digest(
            self.candidate_snapshot_ids
        ):
            raise ValueError("candidate snapshot digest does not match its identifiers")
        dependency_ids = [item.domain_id for item in self.dependency_decisions]
        if dependency_ids != sorted(set(dependency_ids)):
            raise ValueError("dependency decisions require sorted unique domain IDs")
        evidence_ids = [item.evidence_ref for item in self.evidence_snapshot]
        if evidence_ids != sorted(set(evidence_ids)):
            raise ValueError("evidence snapshot requires sorted unique evidence refs")
        if self.dependency_snapshot_digest != aggregate_reference_digest(self.dependency_decisions):
            raise ValueError("dependency snapshot digest does not match its references")
        if self.evidence_digest != aggregate_reference_digest(self.evidence_snapshot):
            raise ValueError("evidence snapshot digest does not match its references")
        if self.user_confirmation is not None:
            if self.user_confirmation.confirmed_decision_digest != domain_decision_digest(self):
                raise ValueError("confirmed decision digest does not match the canonical decision")
            if self.status != "completed":
                raise ValueError("only completed domain decisions may have confirmation")
        if self.status == "completed":
            if (
                any(item.disposition == "blocked" for item in self.candidate_dispositions)
                or self.unresolved_questions
                or self.user_confirmation is None
            ):
                raise ValueError("completed domain decisions must be closed and confirmed")
            if not (
                len(self.user_confirmation.decisions) == 1
                and self.user_confirmation.decisions[0].kind == "domain_completion"
                and self.user_confirmation.decisions[0].subject_ref == self.domain_id
                and self.user_confirmation.decisions[0].decision == "confirmed"
            ):
                raise ValueError("confirmation requires the unique domain completion decision")
        return self


class ChangedEvidenceRef(DomainModel):
    evidence_ref: Identifier
    change: Literal["added", "modified", "removed"]
    old_digest: Sha256Digest | None
    new_digest: Sha256Digest | None

    @model_validator(mode="after")
    def validate_delta(self) -> Self:
        if self.change == "added" and (self.old_digest is not None or self.new_digest is None):
            raise ValueError("added evidence requires only a new digest")
        if self.change == "removed" and (self.old_digest is None or self.new_digest is not None):
            raise ValueError("removed evidence requires only an old digest")
        if self.change == "modified" and (
            self.old_digest is None or self.new_digest is None or self.old_digest == self.new_digest
        ):
            raise ValueError("modified evidence requires distinct old and new digests")
        return self


class DomainChangeRequest(DomainModel):
    schema_version: Literal["2"]
    id: Identifier
    domain_id: Identifier
    status: Literal["proposed", "confirmed", "applied", "superseded"]
    created_at: UtcTimestamp
    previous_decision: DomainDecisionRef
    affected_candidate_ids: list[Identifier]
    affected_capability_ids: list[Identifier]
    changed_evidence: Annotated[list[ChangedEvidenceRef], Field(min_length=1)]
    impact_class: Literal["security_relevant", "descriptive_only"]
    recommended_domain_status: DomainStatus
    recommended_decision_digest: Sha256Digest
    deployment_effect: Literal["disable_affected_capabilities", "audit_warning"]
    impact_summary: BoundedText
    confirmation: UserConfirmation | None
    applied_decision_ref: DomainDecisionRef | None

    @field_validator("affected_candidate_ids", "affected_capability_ids")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_change_lifecycle(self) -> Self:
        if self.previous_decision.domain_id != self.domain_id:
            raise ValueError("previous decision must belong to the changed domain")
        evidence_ids = [item.evidence_ref for item in self.changed_evidence]
        if evidence_ids != sorted(set(evidence_ids)):
            raise ValueError("changed evidence must use sorted unique references")
        if not self.affected_candidate_ids and not self.affected_capability_ids:
            raise ValueError("a change request requires an affected candidate or capability")
        expected_effect = (
            "disable_affected_capabilities"
            if self.impact_class == "security_relevant"
            else "audit_warning"
        )
        if self.deployment_effect != expected_effect:
            raise ValueError("deployment effect must match the security classification")
        if self.impact_class == "security_relevant" and self.recommended_domain_status != "stale":
            raise ValueError("a security-relevant change must recommend stale domain status")
        if self.status in {"proposed", "superseded"} and (
            self.confirmation is not None or self.applied_decision_ref is not None
        ):
            raise ValueError(
                "a proposed or superseded change request cannot be confirmed or applied"
            )
        if self.status == "applied" and (
            self.confirmation is None or self.applied_decision_ref is None
        ):
            raise ValueError(
                "applied change request requires confirmation and its new decision reference"
            )
        if self.status in {"confirmed", "applied"} and (
            self.confirmation is None
            or self.confirmation.confirmed_decision_digest != self.recommended_decision_digest
        ):
            raise ValueError("confirmed change request must bind the recommended decision")
        if self.status in {"confirmed", "applied"}:
            assert self.confirmation is not None
            if not (
                len(self.confirmation.decisions) == 1
                and self.confirmation.decisions[0].kind == "change_request"
                and self.confirmation.decisions[0].subject_ref == self.id
                and self.confirmation.decisions[0].decision == "approved"
            ):
                raise ValueError("confirmation requires the unique change request approval")
        if self.status == "applied":
            assert self.applied_decision_ref is not None
            if (
                self.applied_decision_ref.domain_id != self.domain_id
                or self.applied_decision_ref.revision <= self.previous_decision.revision
                or self.applied_decision_ref.decision_digest != self.recommended_decision_digest
            ):
                raise ValueError("applied change request requires its new decision reference")
        elif self.applied_decision_ref is not None:
            raise ValueError("only an applied change request may reference an applied decision")
        return self


__all__ = [
    "AuthorizationBoundaryClaim",
    "CandidateClaims",
    "CandidateDisposition",
    "CapabilityCandidate",
    "CapabilityCandidateLedger",
    "ChangedEvidenceRef",
    "ContextIsolationClaim",
    "DependencyDecisionRef",
    "DomainChangeRequest",
    "DomainDecision",
    "DomainDecisionRef",
    "DomainEntry",
    "DomainMap",
    "DomainPolicy",
    "DomainStatus",
    "EvidenceSnapshotRef",
    "FactClaim",
    "FactClaimStatus",
    "IdentityBindingClaim",
    "UserConfirmation",
    "UserDecision",
    "VerificationLevel",
    "aggregate_reference_digest",
    "domain_decision_digest",
]
