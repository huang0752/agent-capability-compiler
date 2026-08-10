from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from acc_runtime.deployment import DeploymentDecision, DeploymentPolicy


def test_default_policy_is_immutable_and_read_only() -> None:
    policy = DeploymentPolicy()

    assert policy.allowed_effects == frozenset({"read"})
    assert policy.max_risk == "low"
    assert policy.capability_allowlist is None
    assert policy.require_durable_action_store is True
    assert policy.action_audit_mode == "required"
    assert policy.allows(capability_id="orders.get", effects={"read"}, risk="low")
    assert not policy.allows(capability_id="orders.update", effects={"update"}, risk="low")

    with pytest.raises(FrozenInstanceError):
        policy.max_risk = "critical"  # type: ignore[misc]


def test_effects_must_all_be_explicitly_allowed() -> None:
    policy = DeploymentPolicy(allowed_effects=frozenset({"read", "update"}))

    assert policy.allows(
        capability_id="orders.update",
        effects={"read", "update"},
        risk="low",
    )
    decision = policy.evaluate(
        capability_id="orders.replace",
        effects={"read", "update", "delete"},
        risk="low",
    )
    assert decision == DeploymentDecision(
        allowed=False,
        reasons=("effect_not_allowed",),
        missing_effects=("delete",),
        capability_id="orders.replace",
        required_effects=("delete", "read", "update"),
        risk="low",
    )


@pytest.mark.parametrize(
    ("maximum", "risk", "allowed"),
    [
        ("low", "low", True),
        ("low", "medium", False),
        ("medium", "medium", True),
        ("medium", "high", False),
        ("high", "high", True),
        ("high", "critical", False),
        ("critical", "critical", True),
    ],
)
def test_risk_is_compared_by_explicit_order(maximum: str, risk: str, allowed: bool) -> None:
    policy = DeploymentPolicy(
        allowed_effects=frozenset({"read", "update"}),
        max_risk=maximum,  # type: ignore[arg-type]
    )
    decision = policy.evaluate(
        capability_id="orders.update",
        effects={"update"},
        risk=risk,  # type: ignore[arg-type]
    )

    assert decision.allowed is allowed
    assert ("risk_exceeds_maximum" in decision.reasons) is (not allowed)


def test_none_allowlist_allows_every_capability_but_empty_allowlist_denies_all() -> None:
    unrestricted = DeploymentPolicy()
    deny_all = DeploymentPolicy(capability_allowlist=frozenset())

    assert unrestricted.allows(capability_id="orders.get", effects={"read"}, risk="low")
    decision = deny_all.evaluate(capability_id="orders.get", effects={"read"}, risk="low")
    assert not decision.allowed
    assert decision.reasons == ("capability_not_allowed",)


def test_capability_allowlist_is_exact_and_applies_to_reads_and_actions() -> None:
    policy = DeploymentPolicy(
        allowed_effects=frozenset({"read", "update"}),
        max_risk="medium",
        capability_allowlist=frozenset({"orders.get", "orders.update"}),
    )

    assert policy.allows(capability_id="orders.get", effects={"read"}, risk="low")
    assert policy.allows(capability_id="orders.update", effects={"update"}, risk="medium")
    assert not policy.allows(capability_id="orders.update.any", effects={"update"}, risk="medium")


def test_evaluation_reports_all_denials_in_stable_order() -> None:
    policy = DeploymentPolicy(
        allowed_effects=frozenset({"read"}),
        max_risk="low",
        capability_allowlist=frozenset({"orders.get"}),
    )
    decision = policy.evaluate(
        capability_id="orders.delete",
        effects={"delete", "read"},
        risk="critical",
    )

    assert decision.reasons == (
        "effect_not_allowed",
        "risk_exceeds_maximum",
        "capability_not_allowed",
    )
    assert decision.missing_effects == ("delete",)


def test_empty_effect_set_is_rejected_instead_of_becoming_implicitly_read() -> None:
    policy = DeploymentPolicy()
    with pytest.raises(ValueError, match="at least one effect"):
        policy.evaluate(capability_id="orders.get", effects=set(), risk="low")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_effects": {"read"}},
        {"allowed_effects": frozenset({"write"})},
        {"max_risk": "irreversible"},
        {"capability_allowlist": {"orders.get"}},
        {"capability_allowlist": frozenset({""})},
        {"require_durable_action_store": 1},
        {"action_audit_mode": "disabled"},
    ],
)
def test_policy_constructor_rejects_mutable_coerced_or_unknown_values(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        DeploymentPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("capability_id", "effects", "risk"),
    [
        ("", {"read"}, "low"),
        ("orders.get", "read", "low"),
        ("orders.get", {"write"}, "low"),
        ("orders.get", {"read"}, "irreversible"),
    ],
)
def test_evaluate_rejects_malformed_inputs(
    capability_id: object,
    effects: object,
    risk: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        DeploymentPolicy().evaluate(
            capability_id=capability_id,  # type: ignore[arg-type]
            effects=effects,  # type: ignore[arg-type]
            risk=risk,  # type: ignore[arg-type]
        )


def test_decision_payload_is_immutable_and_contains_no_policy_mutation_api() -> None:
    decision = DeploymentPolicy().evaluate(capability_id="orders.get", effects={"read"}, risk="low")
    assert decision.allowed
    assert decision.reasons == ()
    assert decision.missing_effects == ()
    with pytest.raises(FrozenInstanceError):
        decision.allowed = False  # type: ignore[misc]
