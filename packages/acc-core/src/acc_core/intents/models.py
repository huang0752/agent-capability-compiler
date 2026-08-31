"""Strict, platform-neutral contracts for evidence-driven intent planning."""

from __future__ import annotations

import unicodedata
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, ConfigDict, Field, field_validator, model_validator

from acc_core.models import StrictModel


def _clean_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("value must not contain surrounding whitespace")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise ValueError("value must not contain control or surrogate characters")
    return value


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=512),
    AfterValidator(_clean_text),
]
BoundedText = Annotated[
    str,
    Field(min_length=1, max_length=16_384),
    AfterValidator(_clean_text),
]

type IntentKind = Literal["unknown", "read", "action"]
type IntentEffect = Literal[
    "unknown", "read", "create", "update", "delete", "transition", "execute"
]
type IntentDecision = Literal["materialize", "compose", "blocked_on_evidence", "exclude"]
type IntentRelationshipKind = Literal["merged", "split", "composed", "shared_support"]
type Confidence = Literal["low", "medium", "high"]
type SafetyStatus = Literal["proven", "missing", "not_applicable"]


class IntentModel(StrictModel):
    """Frozen, secret-safe base for planner artifacts."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)


def _sorted_unique(value: list[str]) -> list[str]:
    if value != sorted(set(value)):
        raise ValueError("identifier lists must be sorted and unique")
    return value


class IntentEvidenceRef(IntentModel):
    """Evidence identity plus the exact planning claim it supports."""

    evidence_ref: Identifier
    supports: BoundedText


class IntentGap(IntentModel):
    """One explicit blocker that prevents an intent from being safely published."""

    code: Identifier
    summary: BoundedText
    required_evidence: BoundedText


class ActionSafetyClaim(IntentModel):
    """Evidence status for one independently enforced Action safety dimension."""

    status: SafetyStatus
    rationale: BoundedText
    evidence_refs: list[Identifier] = Field(default_factory=list)

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_status_evidence(self) -> Self:
        if self.status == "proven" and not self.evidence_refs:
            raise ValueError("proven Action safety claims require evidence_refs")
        if self.status != "proven" and self.evidence_refs:
            raise ValueError("only proven Action safety claims may cite evidence_refs")
        return self


class ActionSafetyAssessment(IntentModel):
    """Minimum safety closure required before an Action may be materialized."""

    authorization: ActionSafetyClaim
    idempotency: ActionSafetyClaim
    concurrency: ActionSafetyClaim
    approval: ActionSafetyClaim
    outcome_resolution: ActionSafetyClaim

    def is_closed(self) -> bool:
        return all(
            claim.status == "proven"
            for claim in (
                self.authorization,
                self.idempotency,
                self.concurrency,
                self.approval,
                self.outcome_resolution,
            )
        )


class IntentRationale(IntentModel):
    """Auditable merge, split, or composition reasoning without prescribing a count."""

    summary: BoundedText
    merge: BoundedText | None = None
    split: BoundedText | None = None
    compose: BoundedText | None = None


class DomainIntentCandidate(IntentModel):
    """One proposed user-goal boundary derived from source-system evidence."""

    id: Identifier
    domain_id: Identifier
    resource: Identifier
    user_goal: BoundedText
    route_ids: Annotated[list[Identifier], Field(min_length=1)]
    interaction_ids: list[Identifier] = Field(default_factory=list)
    candidate_ids: list[Identifier]
    capability_ids: list[Identifier]
    kind: IntentKind
    effect: IntentEffect
    rationale: IntentRationale
    evidence: Annotated[list[IntentEvidenceRef], Field(min_length=1)]
    confidence: Confidence
    gaps: list[IntentGap] = Field(default_factory=list)
    recommendation: IntentDecision
    action_safety: ActionSafetyAssessment | None = None

    @field_validator("route_ids", "interaction_ids", "candidate_ids", "capability_ids")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if self.kind == "read" and self.effect != "read":
            raise ValueError("read intents require effect=read")
        if self.kind == "action" and self.effect in {"unknown", "read"}:
            raise ValueError("Action intents require a mutation effect")
        if self.kind == "unknown" and self.effect != "unknown":
            raise ValueError("unknown intents require effect=unknown")
        if self.kind == "action":
            if self.action_safety is None:
                raise ValueError("Action intents require action_safety")
            if (
                self.recommendation in {"materialize", "compose"}
                and not self.action_safety.is_closed()
            ):
                raise ValueError("publishable Action intents require closed action_safety")
        elif self.action_safety is not None:
            raise ValueError("only Action intents may declare action_safety")
        if self.kind == "unknown" and self.recommendation != "blocked_on_evidence":
            raise ValueError("unknown intents must remain blocked_on_evidence")
        if self.recommendation == "blocked_on_evidence" and not self.gaps:
            raise ValueError("blocked_on_evidence intents require at least one gap")
        if self.recommendation in {"materialize", "compose"} and self.gaps:
            raise ValueError("publishable intents cannot retain evidence gaps")
        if self.recommendation == "compose" and self.rationale.compose is None:
            raise ValueError("compose recommendations require compose rationale")
        if (
            self.recommendation == "materialize"
            and len(self.candidate_ids) > 1
            and self.rationale.merge is None
        ):
            raise ValueError("multi-candidate materialization requires merge rationale")
        if self.recommendation in {"materialize", "compose"} and not self.capability_ids:
            raise ValueError("materialize or compose recommendations require capability_ids")
        if self.recommendation == "blocked_on_evidence" and self.capability_ids:
            raise ValueError("blocked_on_evidence intents cannot bind Capabilities")
        return self


class IntentRelationship(IntentModel):
    """Explicit explanation for a route or boundary shared by multiple intents."""

    kind: IntentRelationshipKind
    intent_ids: Annotated[list[Identifier], Field(min_length=2)]
    route_ids: Annotated[list[Identifier], Field(min_length=1)]
    rationale: BoundedText
    evidence_refs: Annotated[list[Identifier], Field(min_length=1)]

    @field_validator("intent_ids", "route_ids", "evidence_refs")
    @classmethod
    def validate_identifier_lists(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value)


class IntentPlan(IntentModel):
    """Complete intent proposal over a declared route denominator."""

    schema_version: Literal["2"]
    intents: Annotated[list[DomainIntentCandidate], Field(min_length=1)]
    relationships: list[IntentRelationship] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_internal_references(self) -> Self:
        intent_ids = [intent.id for intent in self.intents]
        if intent_ids != sorted(set(intent_ids)):
            raise ValueError("intents must use unique ids in sorted order")
        known = set(intent_ids)
        for relationship in self.relationships:
            if not set(relationship.intent_ids) <= known:
                raise ValueError("relationships must reference known intent ids")

        route_to_intents: dict[str, set[str]] = {}
        for intent in self.intents:
            for route_id in intent.route_ids:
                route_to_intents.setdefault(route_id, set()).add(intent.id)
        for route_id, shared_intents in route_to_intents.items():
            if len(shared_intents) < 2:
                continue
            if not any(
                route_id in relationship.route_ids
                and relationship.kind in {"merged", "composed", "shared_support"}
                and shared_intents <= set(relationship.intent_ids)
                for relationship in self.relationships
            ):
                raise ValueError(
                    f"route {route_id!r} belongs to multiple intents without an explicit "
                    "relationship"
                )
        return self


__all__ = [
    "ActionSafetyAssessment",
    "ActionSafetyClaim",
    "Confidence",
    "DomainIntentCandidate",
    "IntentDecision",
    "IntentEffect",
    "IntentEvidenceRef",
    "IntentGap",
    "IntentKind",
    "IntentPlan",
    "IntentRationale",
    "IntentRelationship",
    "IntentRelationshipKind",
    "SafetyStatus",
]
