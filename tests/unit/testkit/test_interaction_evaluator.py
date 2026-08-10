from __future__ import annotations

import pytest
from pydantic import JsonValue, ValidationError

from acc_testkit.interactions import (
    ClientAdapterConformanceReport,
    ClientAdapterConformanceStep,
    HeadlessInteractionEvaluator,
    InteractionEvaluationError,
    evaluate_condition,
)


def _contract() -> dict[str, object]:
    return {
        "fields": {
            "/missing": {"default": "fallback", "submission": "send"},
            "/nullable": {"default": "fallback", "submission": "send"},
            "/explicit": {"default": "fallback", "submission": "send"},
            "/omitted": {"default": "hidden", "submission": "omit"},
            "/changed": {"default": "initial", "submission": "send_if_changed"},
        }
    }


TEST_IDENTITY_SALT = b"offline-interaction-test-salt"
INTERACTION_DIGEST = "a" * 64


def test_defaults_distinguish_missing_null_and_explicit_values() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        initial_values={"nullable": None, "explicit": "caller"},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert evaluator.values == {
        "missing": "fallback",
        "nullable": None,
        "explicit": "caller",
        "omitted": "hidden",
        "changed": "initial",
    }
    assert [entry.event for entry in evaluator.trace] == ["initialized"]


def test_submission_policies_omit_send_and_send_only_changed_values() -> None:
    evaluator = HeadlessInteractionEvaluator(
        _contract(),
        initial_values={"nullable": None, "explicit": "caller"},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    assert evaluator.submission() == {
        "missing": "fallback",
        "nullable": None,
        "explicit": "caller",
    }
    evaluator.set_value("/changed", "updated")
    assert evaluator.submission() == {
        "missing": "fallback",
        "nullable": None,
        "explicit": "caller",
        "changed": "updated",
    }


def test_safe_condition_evaluator_uses_the_canonical_typed_ast() -> None:
    state: dict[str, JsonValue] = {
        "mode": "advanced",
        "region": {"id": "east"},
        "archived": False,
    }
    condition = {
        "operator": "all",
        "operands": [
            {
                "operator": "eq",
                "left": {"kind": "reference", "pointer": "/mode"},
                "right": {"kind": "literal", "value": "advanced"},
            },
            {
                "operator": "present",
                "operand": {"kind": "reference", "pointer": "/region/id"},
            },
            {
                "operator": "not",
                "operand": {
                    "operator": "ne",
                    "left": {"kind": "reference", "pointer": "/archived"},
                    "right": {"kind": "literal", "value": False},
                },
            },
            {
                "operator": "any",
                "operands": [
                    {
                        "operator": "in",
                        "left": {"kind": "reference", "pointer": "/mode"},
                        "right": {
                            "kind": "literal",
                            "value": ["advanced", "expert"],
                        },
                    }
                ],
            },
        ],
    }

    assert evaluate_condition(condition, state) is True
    with pytest.raises(InteractionEvaluationError, match="unsupported condition operator"):
        evaluate_condition({"op": "and", "args": []}, state)


@pytest.mark.parametrize("operator", ["eq", "ne", "in"])
def test_comparisons_fail_closed_when_a_required_operand_is_missing(operator: str) -> None:
    right: dict[str, JsonValue]
    if operator == "in":
        right = {"kind": "literal", "value": ["advanced"]}
    else:
        right = {"kind": "literal", "value": "advanced"}
    condition = {
        "operator": operator,
        "left": {"kind": "reference", "pointer": "/missing"},
        "right": right,
    }

    assert evaluate_condition(condition, {}) is False


@pytest.mark.parametrize("operator", ["all", "any"])
def test_boolean_combinations_reject_empty_operands(operator: str) -> None:
    with pytest.raises(InteractionEvaluationError, match="condition operands must be nonempty"):
        evaluate_condition({"operator": operator, "operands": []}, {})


def test_stale_option_generation_cannot_replace_newer_options() -> None:
    evaluator = HeadlessInteractionEvaluator(
        {"fields": {"/customer_id": {"submission": "send"}}},
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    first = evaluator.begin_option_request("/customer_id")
    second = evaluator.begin_option_request("/customer_id")

    assert evaluator.resolve_option_request("/customer_id", first, [{"id": "old"}]) is False
    assert evaluator.resolve_option_request("/customer_id", second, [{"id": "new"}]) is True
    assert evaluator.options("/customer_id") == ({"id": "new"},)
    assert [entry.event for entry in evaluator.trace] == [
        "initialized",
        "options_requested",
        "options_requested",
        "options_stale",
        "options_resolved",
    ]


def test_selector_cache_key_is_partitioned_by_principal_and_tenant() -> None:
    contract = {"fields": {"/customer_id": {"submission": "send"}}}
    first = HeadlessInteractionEvaluator(
        contract,
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    other_principal = HeadlessInteractionEvaluator(
        contract,
        initial_values={},
        principal_id="principal-b",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )
    other_tenant = HeadlessInteractionEvaluator(
        contract,
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-b",
        identity_salt=TEST_IDENTITY_SALT,
    )

    first_key = first.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key != other_principal.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key != other_tenant.option_cache_key("/customer_id", {"q": "acme"})
    assert first_key == first.option_cache_key("/customer_id", {"q": "acme"})
    assert "principal-a" not in repr(first_key)
    assert "tenant-a" not in repr(first_key)
    assert all(len(digest) == 64 for digest in first_key[:2])


def test_state_trace_records_value_changes_without_mutating_prior_entries() -> None:
    evaluator = HeadlessInteractionEvaluator(
        {"fields": {"/mode": {"default": "basic", "submission": "send"}}},
        initial_values={},
        principal_id="principal-a",
        tenant_id="tenant-a",
        identity_salt=TEST_IDENTITY_SALT,
    )

    evaluator.set_value("/mode", "advanced")

    assert evaluator.trace[0].state == {"mode": "basic"}
    assert evaluator.trace[1].event == "value_changed"
    assert evaluator.trace[1].field == "/mode"
    assert evaluator.trace[1].state == {"mode": "advanced"}


def test_required_skipped_conformance_step_prevents_verified_report() -> None:
    report = ClientAdapterConformanceReport.from_steps(
        [
            ClientAdapterConformanceStep(id="defaults", required=True, status="passed"),
            ClientAdapterConformanceStep(id="selector", required=True, status="skipped"),
            ClientAdapterConformanceStep(id="empty-state", required=False, status="skipped"),
        ],
        adapter_id="reference-web-adapter",
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults", "selector"),
        evidence_sources=("adapter-test-suite",),
    )

    assert report.model_dump(mode="json") == {
        "schema_version": "2",
        "adapter_id": "reference-web-adapter",
        "interaction_digest": INTERACTION_DIGEST,
        "required_scenarios": ["defaults", "selector"],
        "passed_scenarios": ["defaults"],
        "failed_scenarios": [],
        "skipped_scenarios": ["empty-state", "selector"],
        "evidence_sources": ["adapter-test-suite"],
    }
    assert report.planned == 3
    assert report.executed == 1
    assert report.verified is False


def test_report_verification_binds_digest_and_exact_required_scenarios() -> None:
    report = ClientAdapterConformanceReport.from_steps(
        [ClientAdapterConformanceStep(id="defaults", required=True, status="passed")],
        adapter_id="reference-web-adapter",
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults",),
        evidence_sources=("adapter-test-suite",),
    )

    assert report.is_verified_for(
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults",),
    )
    assert not report.is_verified_for(
        interaction_digest="b" * 64,
        required_scenarios=("defaults",),
    )
    assert not report.is_verified_for(
        interaction_digest=INTERACTION_DIGEST,
        required_scenarios=("defaults", "empty-state"),
    )


def test_report_factory_rejects_required_scenario_metadata_mismatch() -> None:
    with pytest.raises(ValueError, match="required scenarios must match required steps"):
        ClientAdapterConformanceReport.from_steps(
            [ClientAdapterConformanceStep(id="selector", required=True, status="skipped")],
            adapter_id="reference-web-adapter",
            interaction_digest=INTERACTION_DIGEST,
            required_scenarios=(),
            evidence_sources=("adapter-test-suite",),
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("adapter_id", " reference-web-adapter "),
        ("required_scenarios", ()),
        ("evidence_sources", ()),
    ],
)
def test_report_model_rejects_identity_or_verification_denominator_gaps(
    field: str, invalid_value: object
) -> None:
    document: dict[str, object] = {
        "schema_version": "2",
        "adapter_id": "reference-web-adapter",
        "interaction_digest": INTERACTION_DIGEST,
        "required_scenarios": ("defaults",),
        "passed_scenarios": ("defaults",),
        "failed_scenarios": (),
        "skipped_scenarios": (),
        "evidence_sources": ("adapter-test-suite",),
    }
    document[field] = invalid_value

    with pytest.raises(ValidationError):
        ClientAdapterConformanceReport.model_validate(document)


@pytest.mark.parametrize(
    ("adapter_id", "required_scenarios", "evidence_sources"),
    [
        (" reference-web-adapter ", ("defaults",), ("adapter-test-suite",)),
        ("reference-web-adapter", (), ("adapter-test-suite",)),
        ("reference-web-adapter", ("defaults",), ()),
    ],
)
def test_report_factory_rejects_identity_or_verification_denominator_gaps(
    adapter_id: str,
    required_scenarios: tuple[str, ...],
    evidence_sources: tuple[str, ...],
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        ClientAdapterConformanceReport.from_steps(
            [ClientAdapterConformanceStep(id="defaults", required=True, status="passed")],
            adapter_id=adapter_id,
            interaction_digest=INTERACTION_DIGEST,
            required_scenarios=required_scenarios,
            evidence_sources=evidence_sources,
        )
