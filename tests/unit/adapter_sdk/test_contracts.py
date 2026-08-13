from __future__ import annotations

import pytest
from pydantic import ValidationError

import acc_adapter_sdk.contracts as contracts


def _operation(**overrides: object) -> contracts.AdapterOperation:
    document: dict[str, object] = {
        "id": "crm.get_customer",
        "method": "GET",
        "path": "/customers/{customer_id}",
        "summary": "Get one customer",
    }
    document.update(overrides)
    return contracts.AdapterOperation.model_validate(document)


def _contract(**overrides: object) -> contracts.AdapterContract:
    document: dict[str, object] = {
        "schema_version": "2",
        "id": "example-crm-adapter",
        "version": "0.1.0",
        "base_path": "/adapter/v2",
        "health": {
            "path": "/healthz",
            "metadata": {"system": "example-crm", "mode": "fake"},
        },
        "operations": [_operation()],
    }
    document.update(overrides)
    return contracts.AdapterContract.model_validate(document)


def _action(**overrides: object) -> contracts.AdapterActionOperation:
    document: dict[str, object] = {
        "id": "crm.close_customer",
        "method": "POST",
        "path": "/customers/{customer_id}/close",
        "summary": "Close one customer",
        "safety": {
            "idempotency": {
                "mode": "source_key",
                "target": {"kind": "header", "name": "Idempotency-Key"},
            },
            "concurrency": {
                "mode": "required",
                "token": {"kind": "response_header", "name": "ETag"},
                "precondition": {"kind": "header", "name": "If-Match"},
            },
            "transactional_outcome": True,
            "authorization": "source_revalidated",
            "max_request_bytes": 4096,
            "max_response_bytes": 4096,
        },
    }
    document.update(overrides)
    return contracts.AdapterActionOperation.model_validate(document)


def test_adapter_contract_is_strict_and_preserves_health_metadata() -> None:
    contract = _contract()

    assert contract.model_dump(mode="json") == {
        "schema_version": "2",
        "id": "example-crm-adapter",
        "version": "0.1.0",
        "base_path": "/adapter/v2",
        "health": {
            "path": "/healthz",
            "metadata": {"system": "example-crm", "mode": "fake"},
        },
        "operations": [
            {
                "id": "crm.get_customer",
                "method": "GET",
                "path": "/customers/{customer_id}",
                "summary": "Get one customer",
            }
        ],
    }

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        contracts.AdapterContract.model_validate(
            {
                **contract.model_dump(mode="python"),
                "dynamic_routes": True,
            }
        )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_read_adapter_operations_remain_read_only(method: str) -> None:
    with pytest.raises(ValidationError):
        _operation(method=method)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_action_contract_accepts_only_declared_mutation_methods(method: str) -> None:
    assert _action(method=method).method == method


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_action_contract_rejects_non_mutation_methods(method: str) -> None:
    with pytest.raises(ValidationError):
        _action(method=method)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("idempotency", {"mode": "runtime_deduplicate"}),
        ("concurrency", {"mode": "not_supported"}),
        ("transactional_outcome", False),
        ("authorization", "trusted_proxy"),
        ("max_request_bytes", 0),
        ("max_response_bytes", 0),
    ],
)
def test_action_contract_requires_all_production_safety_invariants(
    field: str, value: object
) -> None:
    safety = _action().safety.model_dump(mode="python")
    safety[field] = value

    with pytest.raises(ValidationError):
        _action(safety=safety)


def test_action_controls_require_distinct_safe_targets_and_valid_pointers() -> None:
    action = _action()
    safety = action.safety.model_dump(mode="python")
    safety["concurrency"]["precondition"] = {
        "kind": "header",
        "name": "Idempotency-Key",
    }
    with pytest.raises(ValidationError, match="distinct targets"):
        _action(safety=safety)

    safety = action.safety.model_dump(mode="python")
    safety["idempotency"]["target"] = {"kind": "body", "pointer": "request/id"}
    with pytest.raises(ValidationError, match="JSON Pointer"):
        _action(safety=safety)

    safety = action.safety.model_dump(mode="python")
    safety["idempotency"]["target"] = {"kind": "header", "name": "Authorization"}
    with pytest.raises(ValidationError, match="reserved"):
        _action(safety=safety)


def test_mixed_contract_preserves_read_compatibility_and_action_metadata() -> None:
    contract = _contract(operations=[_operation(), _action()])

    assert isinstance(contract.operations[0], contracts.AdapterOperation)
    assert isinstance(contract.operations[1], contracts.AdapterActionOperation)
    action = contract.operations[1]
    assert action.safety.transactional_outcome is True
    assert action.safety.authorization == "source_revalidated"


@pytest.mark.parametrize(
    "path",
    [
        "customers",
        "//other.example/customers",
        "https://other.example/customers",
        "/customers/../secrets",
        "/customers/%2e%2e/secrets",
        r"/customers\secrets",
        "/customers?admin=true",
        "/customers#fragment",
    ],
)
def test_adapter_operation_paths_are_origin_relative_and_safe(path: str) -> None:
    with pytest.raises(ValidationError):
        _operation(path=path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_path", "/adapter/v2/"),
        ("base_path", "/adapter/{tenant}"),
        ("base_path", "/adapter/../admin"),
        ("health", {"path": "/health/{probe}", "metadata": {}}),
        ("health", {"path": "healthz", "metadata": {}}),
    ],
)
def test_base_and_health_paths_are_static(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _contract(**{field: value})


def test_adapter_contract_rejects_duplicate_ids_routes_and_health_collisions() -> None:
    first = _operation()
    duplicate_id = _operation(path="/customers/{customer_id}/summary")
    with pytest.raises(ValidationError, match="operation ids must be unique"):
        _contract(operations=[first, duplicate_id])

    duplicate_route = _operation(id="crm.find_customer")
    with pytest.raises(ValidationError, match="operation routes must be unique"):
        _contract(operations=[first, duplicate_route])

    with pytest.raises(ValidationError, match="health path must not collide"):
        _contract(
            health={"path": "/adapter/v2/customers", "metadata": {}},
            operations=[_operation(path="/customers")],
        )


def test_adapter_contract_allows_an_empty_scaffold_with_default_health_metadata() -> None:
    contract = contracts.AdapterContract.model_validate(
        {
            "schema_version": "2",
            "id": "new-adapter",
            "version": "0.1.0",
            "base_path": "/adapter/v2",
            "operations": [],
        }
    )

    assert contract.operations == []
    assert contract.health.model_dump() == {"path": "/healthz", "metadata": {}}


def test_adapter_contract_rejects_legacy_schema_version() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        _contract(schema_version="1")
