from __future__ import annotations

from collections.abc import Mapping

from acc_core.models import Capability, Operation, Policy
from acc_core.scope import CapabilityScopeRequirements, analyze_capability_scope_requirements


def _operation(operation_id: str, *scopes: str) -> Operation:
    return Operation.model_validate(
        {
            "schema_version": "1",
            "id": operation_id,
            "title": operation_id,
            "kind": "http",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {"type": "object"},
            "http": {
                "method": "GET",
                "path": f"/{operation_id}",
                "scopes": list(scopes),
            },
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": operation_id,
                    "locator": f"routes.py#{operation_id}",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        }
    )


def _policy(*scopes: str) -> Policy:
    return Policy.model_validate(
        {
            "schema_version": "1",
            "id": "read-policy",
            "required_scopes": list(scopes),
            "tenant_mode": "none",
            "readable_fields": ["value"],
            "denied_fields": [],
            "redaction_rules": [],
        }
    )


def _capability(workflow: list[dict[str, object]]) -> Capability:
    return Capability.model_validate(
        {
            "schema_version": "1",
            "id": "inspect_records",
            "title": "Inspect records",
            "description": "Inspect records through a deterministic workflow.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {"type": "object"},
            "workflow": workflow,
            "policy": "read-policy",
            "evals": ["normal"],
        }
    )


def _analyze(
    workflow: list[dict[str, object]],
    operations: Mapping[str, Operation],
    *,
    policy_scopes: tuple[str, ...] = ("policy.read",),
) -> CapabilityScopeRequirements:
    return analyze_capability_scope_requirements(
        capability=_capability(workflow),
        policy=_policy(*policy_scopes),
        operations=operations,
    )


def test_sequential_calls_and_policy_are_always_required() -> None:
    operations = {
        "list": _operation("list", "records.list"),
        "detail": _operation("detail", "records.detail"),
    }

    requirements = _analyze(
        [
            {"id": "listed", "call": {"operation": "list", "arguments": {}}},
            {"id": "detail", "call": {"operation": "detail", "arguments": {}}},
            {"emit": {"value": {}}},
        ],
        operations,
    )

    expected = frozenset({"policy.read", "records.list", "records.detail"})
    assert requirements.policy_always_required == frozenset({"policy.read"})
    assert requirements.completion_alternatives == (expected,)
    assert requirements.always_required == expected
    assert requirements.conditionally_required == frozenset()
    assert requirements.all_referenced == expected


def test_branch_preserves_path_alternatives_and_separates_conditional_scopes() -> None:
    operations = {
        "common": _operation("common", "records.common"),
        "then": _operation("then", "records.then"),
        "else": _operation("else", "records.else"),
        "post": _operation("post", "records.post"),
    }

    requirements = _analyze(
        [
            {"id": "common", "call": {"operation": "common", "arguments": {}}},
            {
                "branch": {
                    "condition": "$.input.use_then",
                    "then": [{"id": "then", "call": {"operation": "then", "arguments": {}}}],
                    "else": [{"id": "else", "call": {"operation": "else", "arguments": {}}}],
                }
            },
            {"id": "post", "call": {"operation": "post", "arguments": {}}},
            {"emit": {"value": {}}},
        ],
        operations,
    )

    common = frozenset({"policy.read", "records.common", "records.post"})
    assert requirements.completion_alternatives == (
        common | {"records.else"},
        common | {"records.then"},
    )
    assert requirements.always_required == common
    assert requirements.conditionally_required == frozenset({"records.else", "records.then"})


def test_parallel_children_all_contribute_required_scopes() -> None:
    operations = {
        "left": _operation("left", "records.left"),
        "right": _operation("right", "records.right"),
    }

    requirements = _analyze(
        [
            {
                "parallel": [
                    {"id": "left", "call": {"operation": "left", "arguments": {}}},
                    {"id": "right", "call": {"operation": "right", "arguments": {}}},
                ]
            },
            {"emit": {"value": {}}},
        ],
        operations,
    )

    expected = frozenset({"policy.read", "records.left", "records.right"})
    assert requirements.completion_alternatives == (expected,)
    assert requirements.always_required == expected


def test_dynamic_foreach_keeps_zero_iteration_feasibility_and_body_scope_visibility() -> None:
    operations = {"detail": _operation("detail", "records.detail")}

    requirements = _analyze(
        [
            {
                "foreach": {
                    "items": "$.input.items",
                    "item_name": "item",
                    "max_items": 10,
                    "workflow": [
                        {"id": "detail", "call": {"operation": "detail", "arguments": {}}}
                    ],
                }
            },
            {"emit": {"value": {}}},
        ],
        operations,
    )

    assert requirements.completion_alternatives == (frozenset({"policy.read"}),)
    assert requirements.always_required == frozenset({"policy.read"})
    assert requirements.conditionally_required == frozenset({"records.detail"})
    assert requirements.all_referenced == frozenset({"policy.read", "records.detail"})


def test_literal_nonempty_foreach_requires_body_but_literal_empty_foreach_does_not() -> None:
    operations = {"detail": _operation("detail", "records.detail")}

    nonempty = _analyze(
        [
            {
                "foreach": {
                    "items": [{"id": "one"}],
                    "item_name": "item",
                    "max_items": 10,
                    "workflow": [
                        {"id": "detail", "call": {"operation": "detail", "arguments": {}}}
                    ],
                }
            },
            {"emit": {"value": {}}},
        ],
        operations,
    )
    empty = _analyze(
        [
            {
                "foreach": {
                    "items": [],
                    "item_name": "item",
                    "max_items": 10,
                    "workflow": [
                        {"id": "detail", "call": {"operation": "detail", "arguments": {}}}
                    ],
                }
            },
            {"emit": {"value": {}}},
        ],
        operations,
    )

    assert nonempty.always_required == frozenset({"policy.read", "records.detail"})
    assert nonempty.conditionally_required == frozenset()
    assert empty.always_required == frozenset({"policy.read"})
    assert empty.conditionally_required == frozenset()
    assert empty.all_referenced == frozenset({"policy.read", "records.detail"})


def test_completion_alternatives_are_deterministic_minimal_antichain() -> None:
    operations = {
        "base": _operation("base", "records.base"),
        "extra": _operation("extra", "records.extra"),
    }

    requirements = _analyze(
        [
            {
                "branch": {
                    "condition": "$.input.extended",
                    "then": [
                        {"id": "base_then", "call": {"operation": "base", "arguments": {}}},
                        {"id": "extra", "call": {"operation": "extra", "arguments": {}}},
                    ],
                    "else": [{"id": "base_else", "call": {"operation": "base", "arguments": {}}}],
                }
            },
            {"emit": {"value": {}}},
        ],
        operations,
    )

    assert requirements.completion_alternatives == (frozenset({"policy.read", "records.base"}),)
    assert requirements.always_required == frozenset({"policy.read", "records.base"})
    assert requirements.conditionally_required == frozenset({"records.extra"})
