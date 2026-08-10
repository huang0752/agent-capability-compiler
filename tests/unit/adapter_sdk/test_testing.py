from __future__ import annotations

import pytest

import acc_adapter_sdk.testing as adapter_testing
from acc_adapter_sdk.contracts import AdapterContract
from acc_adapter_sdk.server import AdapterServer


def _server() -> AdapterServer:
    contract = AdapterContract.model_validate(
        {
            "schema_version": "2",
            "id": "test-adapter",
            "version": "0.1.0",
            "base_path": "/adapter/v2",
            "operations": [
                {
                    "id": "items.list",
                    "method": "GET",
                    "path": "/items",
                    "summary": "List items",
                },
                {
                    "id": "items.exists",
                    "method": "HEAD",
                    "path": "/items/{item_id}",
                    "summary": "Check item",
                },
            ],
        }
    )
    return AdapterServer(contract)


async def _handler() -> dict[str, bool]:
    return {"ok": True}


def test_contract_assertion_accepts_exactly_registered_read_only_routes() -> None:
    server = _server()
    server.register_operation("items.list", _handler)
    server.register_operation("items.exists", _handler)

    adapter_testing.assert_adapter_contract(server)


def test_contract_assertion_reports_missing_operation_registration() -> None:
    server = _server()
    server.register_operation("items.list", _handler)

    with pytest.raises(
        adapter_testing.AdapterContractAssertionError,
        match=r"missing registered operations: items\.exists",
    ):
        adapter_testing.assert_adapter_contract(server)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_contract_assertion_rejects_dynamically_added_write_routes(method: str) -> None:
    server = _server()
    server.register_operation("items.list", _handler)
    server.register_operation("items.exists", _handler)
    server.app.add_api_route("/dynamic", _handler, methods=[method])

    with pytest.raises(
        adapter_testing.AdapterContractAssertionError,
        match="unsafe adapter route methods",
    ):
        adapter_testing.assert_adapter_contract(server)


def test_contract_assertion_rejects_undeclared_read_routes() -> None:
    server = _server()
    server.register_operation("items.list", _handler)
    server.register_operation("items.exists", _handler)
    server.app.add_api_route("/dynamic", _handler, methods=["GET"])

    with pytest.raises(
        adapter_testing.AdapterContractAssertionError,
        match="undeclared adapter routes",
    ):
        adapter_testing.assert_adapter_contract(server)
