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
def test_adapter_operations_are_read_only(method: str) -> None:
    with pytest.raises(ValidationError):
        _operation(method=method)


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
