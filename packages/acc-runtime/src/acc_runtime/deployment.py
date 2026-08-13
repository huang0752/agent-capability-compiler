"""Immutable deployment authorization for read and Action capabilities."""

from __future__ import annotations

import unicodedata
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Literal

from acc_core.models.actions import Effect, Risk

type DeploymentDenialReason = Literal[
    "effect_not_allowed",
    "risk_exceeds_maximum",
    "capability_not_allowed",
]
type ActionAuditMode = Literal["required", "best_effort"]
type ActionSandboxMode = Literal["disabled", "local_development"]

_EFFECTS: frozenset[str] = frozenset(
    {"read", "create", "update", "delete", "transition", "execute"}
)
_RISK_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
_AUDIT_MODES = frozenset({"required", "best_effort"})
_ACTION_SANDBOX_MODES = frozenset({"disabled", "local_development"})


def _exact_identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a nonempty exact value")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise ValueError(f"{field_name} cannot contain control or surrogate characters")
    return value


def _effect_set(effects: object, *, require_nonempty: bool) -> frozenset[Effect]:
    if not isinstance(effects, Collection) or isinstance(effects, (str, bytes, Mapping)):
        raise TypeError("effects must be a collection")
    normalized: set[Effect] = set()
    for effect in effects:
        if not isinstance(effect, str) or effect not in _EFFECTS:
            raise ValueError("effects contain an unsupported value")
        normalized.add(effect)  # type: ignore[arg-type]
    if require_nonempty and not normalized:
        raise ValueError("at least one effect is required")
    return frozenset(normalized)


def _risk(value: object, *, field_name: str) -> Risk:
    if not isinstance(value, str) or value not in _RISK_ORDER:
        raise ValueError(f"{field_name} must be a supported risk")
    return value  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class DeploymentDecision:
    """One deterministic decision without granting or mutating policy state."""

    allowed: bool
    reasons: tuple[DeploymentDenialReason, ...]
    missing_effects: tuple[Effect, ...]
    capability_id: str
    required_effects: tuple[Effect, ...]
    risk: Risk


@dataclass(frozen=True, slots=True)
class DeploymentPolicy:
    """Operator-owned ceiling; Pack declarations can only be checked against it."""

    allowed_effects: frozenset[Effect] = frozenset({"read"})
    max_risk: Risk = "low"
    capability_allowlist: frozenset[str] | None = None
    require_durable_action_store: bool = True
    action_audit_mode: ActionAuditMode = "required"
    action_sandbox_mode: ActionSandboxMode = "disabled"

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_effects, frozenset):
            raise TypeError("allowed_effects must be a frozenset")
        _effect_set(self.allowed_effects, require_nonempty=False)
        _risk(self.max_risk, field_name="max_risk")
        if self.capability_allowlist is not None:
            if not isinstance(self.capability_allowlist, frozenset):
                raise TypeError("capability_allowlist must be a frozenset or None")
            for capability_id in self.capability_allowlist:
                _exact_identifier(capability_id, field_name="capability allowlist entry")
        if not isinstance(self.require_durable_action_store, bool):
            raise TypeError("require_durable_action_store must be a boolean")
        if (
            not isinstance(self.action_audit_mode, str)
            or self.action_audit_mode not in _AUDIT_MODES
        ):
            raise ValueError("action_audit_mode must be required or best_effort")
        if (
            not isinstance(self.action_sandbox_mode, str)
            or self.action_sandbox_mode not in _ACTION_SANDBOX_MODES
        ):
            raise ValueError("action_sandbox_mode must be disabled or local_development")

    def evaluate(
        self,
        *,
        capability_id: str,
        effects: Collection[Effect],
        risk: Risk,
    ) -> DeploymentDecision:
        """Compare declared requirements without widening this deployment ceiling."""

        checked_capability_id = _exact_identifier(capability_id, field_name="capability_id")
        required = _effect_set(effects, require_nonempty=True)
        checked_risk = _risk(risk, field_name="risk")
        missing_effects = required - self.allowed_effects

        reasons: list[DeploymentDenialReason] = []
        if missing_effects:
            reasons.append("effect_not_allowed")
        if _RISK_ORDER[checked_risk] > _RISK_ORDER[self.max_risk]:
            reasons.append("risk_exceeds_maximum")
        if (
            self.capability_allowlist is not None
            and checked_capability_id not in self.capability_allowlist
        ):
            reasons.append("capability_not_allowed")

        return DeploymentDecision(
            allowed=not reasons,
            reasons=tuple(reasons),
            missing_effects=tuple(sorted(missing_effects)),
            capability_id=checked_capability_id,
            required_effects=tuple(sorted(required)),
            risk=checked_risk,
        )

    def allows(
        self,
        *,
        capability_id: str,
        effects: Collection[Effect],
        risk: Risk,
    ) -> bool:
        """Return the boolean form of :meth:`evaluate` for runtime gates."""

        return self.evaluate(
            capability_id=capability_id,
            effects=effects,
            risk=risk,
        ).allowed


__all__ = [
    "ActionAuditMode",
    "ActionSandboxMode",
    "DeploymentDecision",
    "DeploymentDenialReason",
    "DeploymentPolicy",
]
