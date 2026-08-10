"""Strict profiles and truthful reports for attaching to a live Gateway."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SecretRef(_StrictModel):
    """Reference one credential through an environment variable name only."""

    env: str

    @field_validator("env")
    @classmethod
    def _validate_env(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
            raise ValueError("SecretRef.env must be an environment variable name")
        return value


class LiveGatewayAccount(_StrictModel):
    alias: str
    identity: SecretRef
    password: SecretRef

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, value: str) -> str:
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("account alias must be a nonempty exact value")
        return value


class LiveGatewayAttestation(_StrictModel):
    pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_id: str = Field(min_length=1)
    project_version: str = Field(min_length=1)
    interaction_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LiveGatewayCase(_StrictModel):
    id: str = Field(min_length=1)
    account: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    arguments: dict[str, JsonValue]
    expected_structured_content: JsonValue | None = None
    expect_error: bool = False
    expected_error_code: str | None = None
    required: bool = True

    @model_validator(mode="after")
    def _validate_error_expectation(self) -> Self:
        if self.expected_error_code is not None and not self.expect_error:
            raise ValueError("expected_error_code requires expect_error")
        return self


class LiveGatewayIsolationCase(_StrictModel):
    accounts: tuple[str, str]
    tool: str = Field(min_length=1)
    arguments: dict[str, JsonValue]
    expected_structured_content: dict[str, JsonValue]
    required: bool = True

    @model_validator(mode="after")
    def _validate_accounts(self) -> Self:
        if self.accounts[0] == self.accounts[1]:
            raise ValueError("isolation accounts must be distinct")
        if set(self.expected_structured_content) != set(self.accounts):
            raise ValueError("isolation expectations must match both accounts")
        if (
            self.expected_structured_content[self.accounts[0]]
            == self.expected_structured_content[self.accounts[1]]
        ):
            raise ValueError("isolation expectations must distinguish the two accounts")
        return self


class LiveGatewayProfile(_StrictModel):
    gateway_url: str
    attestation: LiveGatewayAttestation
    accounts: tuple[LiveGatewayAccount, ...] = Field(min_length=2)
    cases: tuple[LiveGatewayCase, ...] = Field(min_length=1)
    isolation: LiveGatewayIsolationCase

    @field_validator("gateway_url")
    @classmethod
    def _validate_gateway_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Gateway base URL must be an absolute HTTP(S) origin")
        return f"{parsed.scheme}://{parsed.netloc}"

    @model_validator(mode="after")
    def _validate_references(self) -> Self:
        aliases = [account.alias for account in self.accounts]
        if len(set(aliases)) != len(aliases):
            raise ValueError("account aliases must be unique")
        case_ids = [case.id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("live case ids must be unique")
        referenced = {case.account for case in self.cases} | set(self.isolation.accounts)
        if not referenced <= set(aliases):
            raise ValueError("live cases must reference declared accounts")
        return self


class LiveStepStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class LiveStepResult(_StrictModel):
    id: str
    required: bool
    status: LiveStepStatus
    code: str | None = None
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class LiveGatewayReport(_StrictModel):
    planned: int = Field(ge=0)
    executed: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    transport: Literal["streamable_http"] = "streamable_http"
    pack_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    validation_level: Literal["source_connected_verified", "unverified"]
    verified: bool
    steps: tuple[LiveStepResult, ...]

    @classmethod
    def from_steps(
        cls,
        steps: list[LiveStepResult],
        *,
        pack_sha256: str | None,
    ) -> LiveGatewayReport:
        passed = sum(step.status is LiveStepStatus.PASSED for step in steps)
        failed = sum(step.status is LiveStepStatus.FAILED for step in steps)
        skipped = sum(step.status is LiveStepStatus.SKIPPED for step in steps)
        verified = failed == 0 and not any(
            step.required and step.status is LiveStepStatus.SKIPPED for step in steps
        )
        return cls(
            planned=len(steps),
            executed=len(steps) - skipped,
            passed=passed,
            failed=failed,
            skipped=skipped,
            pack_sha256=pack_sha256,
            validation_level="source_connected_verified" if verified else "unverified",
            verified=verified,
            steps=tuple(steps),
        )


__all__ = [
    "LiveGatewayAccount",
    "LiveGatewayAttestation",
    "LiveGatewayCase",
    "LiveGatewayIsolationCase",
    "LiveGatewayProfile",
    "LiveGatewayReport",
    "LiveStepResult",
    "LiveStepStatus",
    "SecretRef",
]
