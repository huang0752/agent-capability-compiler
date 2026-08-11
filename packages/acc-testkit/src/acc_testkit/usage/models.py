"""Secret-free result models for deterministic Agent Usage evaluation."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, PrivateAttr, model_validator

from acc_core.usage import DomainUsageContract, UsageScenario

type UsageOutcomeKind = Literal[
    "success",
    "empty",
    "unauthorized",
    "forbidden",
    "not_found",
    "timeout",
    "conflict",
    "outcome_unknown",
    "source_error",
    "not_provisioned",
]


class _UsageTestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class UsageAttestation(_UsageTestModel):
    """Exact frozen inputs against which fake headless evaluation is allowed."""

    pack_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ir_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_schema_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    test_report_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scenario_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_mode: Literal["fake", "real_mcp"]


class UsageToolOutcome(_UsageTestModel):
    """Transient fake-caller outcome; its result is never copied into a report."""

    outcome: UsageOutcomeKind
    result: JsonValue | None = None

    @classmethod
    def success(cls, result: JsonValue) -> UsageToolOutcome:
        return cls(outcome="success", result=result)

    @classmethod
    def empty(cls) -> UsageToolOutcome:
        return cls(outcome="empty")

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.outcome not in {"success", "empty"} and self.result is not None:
            raise ValueError("failure outcomes cannot carry a result payload")
        return self


class UsageTraceEntry(_UsageTestModel):
    """One data-free attempted fake Tool call in deterministic order."""

    scenario_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    step_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    phase: Literal["prepare", "approve", "commit", "status"] | None = None
    attempt: int = Field(ge=1, le=2)
    outcome: UsageOutcomeKind
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class UsageScenarioResult(_UsageTestModel):
    """Independent result for exactly one declared Usage scenario."""

    scenario_id: str = Field(min_length=1)
    domain_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    status: Literal["passed", "failed", "stale", "prohibited", "outcome_unknown"]
    outcome: UsageOutcomeKind | Literal["stale", "prohibited"]
    status_outcome: UsageOutcomeKind | None = None
    trace: tuple[UsageTraceEntry, ...]
    _evaluator_derived: bool = PrivateAttr(default=False)
    _verification_fingerprint: str | None = PrivateAttr(default=None)
    _origin_identity: int | None = PrivateAttr(default=None)

    @property
    def call_count(self) -> int:
        return len(self.trace)

    def _public_fingerprint(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @property
    def evaluator_derived(self) -> bool:
        return (
            self._evaluator_derived
            and self._origin_identity == id(self)
            and self._verification_fingerprint == self._public_fingerprint()
        )


class RealMcpUsageScenarioResult(_UsageTestModel):
    """Payload-free result observed through a public MCP client protocol."""

    result: UsageScenarioResult
    runtime_tool_schema_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    _runner_derived: bool = PrivateAttr(default=False)
    _verification_fingerprint: str | None = PrivateAttr(default=None)
    _origin_identity: int | None = PrivateAttr(default=None)

    def _public_fingerprint(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @property
    def runner_derived(self) -> bool:
        return (
            self._runner_derived
            and self._origin_identity == id(self)
            and self._verification_fingerprint == self._public_fingerprint()
        )


def _model_digest(value: DomainUsageContract | UsageScenario) -> str:
    payload = json.dumps(
        value.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def usage_contract_digest(contract: DomainUsageContract) -> str:
    """Bind an attestation to every validated Usage contract field."""

    return _model_digest(contract)


def usage_scenario_digest(scenario: UsageScenario) -> str:
    """Bind an attestation to every validated Usage scenario field."""

    return _model_digest(scenario)


__all__ = [
    "RealMcpUsageScenarioResult",
    "UsageAttestation",
    "UsageOutcomeKind",
    "UsageScenarioResult",
    "UsageToolOutcome",
    "UsageTraceEntry",
    "usage_contract_digest",
    "usage_scenario_digest",
]
