"""Public contracts for evidence-backed source request and response schemas."""

from __future__ import annotations

import json
from typing import Annotated, Literal, Self

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import AfterValidator, Field, field_validator, model_validator

from acc_core.models import Evidence, JsonObject, NonEmptyString, StrictModel
from acc_core.models.actions import (
    ConcurrencyContractV2,
    Effect,
    HttpMethodV2,
    IdempotencyContractV2,
    OutcomeResolutionContractV2,
    RetryContractV2,
    Reversibility,
    Risk,
    ServerSerializedStatePredicateV2,
)


def _validate_json_pointer(value: str) -> str:
    if not value.startswith("/"):
        raise ValueError("value must be an absolute RFC 6901 JSON Pointer")
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] != "~":
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                raise ValueError("value must be a valid RFC 6901 JSON Pointer")
            index += 2
    return value


JsonPointer = Annotated[str, AfterValidator(_validate_json_pointer)]


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _resolve_pointer(document: object, pointer: str) -> object:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        if isinstance(current, list):
            if not token.isdecimal() or (len(token) > 1 and token.startswith("0")):
                raise LookupError(pointer)
            index = int(token)
            if index >= len(current):
                raise LookupError(pointer)
            current = current[index]
            continue
        raise LookupError(pointer)
    return current


def _checked_json_schema(value: JsonObject) -> JsonObject:
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as exc:
        raise ValueError(f"invalid Draft 2020-12 JSON Schema: {exc.message}") from exc
    return value


class SchemaProvenance(StrictModel):
    """Bind one source-schema claim to immutable evidence."""

    target_pointer: JsonPointer
    evidence: Evidence
    evidence_schema_pointer: JsonPointer
    authority: Literal["contract", "implementation", "test", "observation"]


class ActionSemanticsProvenance(StrictModel):
    """Bind one Action safety field to trusted source Evidence."""

    field: Literal[
        "conflict_control",
        "effect",
        "idempotency",
        "outcome_resolution",
        "reversibility",
        "retry",
        "risk",
    ]
    evidence: Evidence
    evidence_pointer: JsonPointer
    authority: Literal["contract", "implementation", "test"]


class ActionSemantics(StrictModel):
    """Evidence-backed source semantics for one mutating Operation."""

    method: HttpMethodV2
    effect: Effect
    risk: Risk
    reversibility: Reversibility
    retry: RetryContractV2
    idempotency: IdempotencyContractV2
    concurrency: ConcurrencyContractV2
    outcome_resolution: OutcomeResolutionContractV2 | None = None
    evidence: Evidence
    authority: Literal["contract", "implementation", "test"]
    provenance: list[ActionSemanticsProvenance] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_replay_contract(self) -> Self:
        if self.retry.mode == "idempotent_only" and self.idempotency.mode != "source_key":
            raise ValueError("idempotent_only mutation retry requires source_key idempotency")
        if isinstance(self.concurrency, ServerSerializedStatePredicateV2):
            if self.outcome_resolution is None or self.outcome_resolution.mode != "status_query":
                raise ValueError(
                    "server-serialized semantics require status_query outcome resolution"
                )
            expected = [
                "conflict_control",
                "effect",
                "idempotency",
                "outcome_resolution",
                "reversibility",
                "retry",
                "risk",
            ]
            if [claim.field for claim in self.provenance] != expected:
                raise ValueError("server-serialized semantics require exact field provenance")
        return self


class SourceContract(StrictModel):
    """An evidence-backed request and response contract for one Operation."""

    schema_version: Literal["2"]
    id: NonEmptyString
    operation_id: NonEmptyString
    request_schema: JsonObject
    response_schema: JsonObject
    request_completeness: Literal["complete", "partial", "unknown"]
    response_completeness: Literal["complete", "partial", "unknown"]
    provenance: list[SchemaProvenance]
    action_semantics: ActionSemantics | None = None

    @field_validator("request_schema", "response_schema")
    @classmethod
    def validate_json_schema(cls, value: JsonObject) -> JsonObject:
        return _checked_json_schema(value)

    @model_validator(mode="after")
    def validate_provenance(self) -> SourceContract:
        roots: dict[str, JsonObject] = {
            "request_schema": self.request_schema,
            "response_schema": self.response_schema,
        }
        identities: set[tuple[str, str, str, str]] = set()
        for claim in self.provenance:
            tokens = _pointer_tokens(claim.target_pointer)
            if not tokens or tokens[0] not in roots:
                raise ValueError(
                    "provenance target_pointer must address request_schema or response_schema"
                )
            relative_pointer = "/" + "/".join(
                token.replace("~", "~0").replace("/", "~1") for token in tokens[1:]
            )
            if len(tokens) == 1:
                relative_pointer = ""
            try:
                if relative_pointer:
                    _resolve_pointer(roots[tokens[0]], relative_pointer)
            except LookupError:
                raise ValueError(
                    f"provenance target_pointer does not exist: {claim.target_pointer}"
                ) from None

            evidence_identity = json.dumps(
                claim.evidence.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            identity = (
                claim.target_pointer,
                evidence_identity,
                claim.evidence_schema_pointer,
                claim.authority,
            )
            if identity in identities:
                raise ValueError("source contract contains a duplicate provenance claim")
            identities.add(identity)
        return self


__all__ = [
    "ActionSemantics",
    "ActionSemanticsProvenance",
    "JsonPointer",
    "SchemaProvenance",
    "SourceContract",
]
