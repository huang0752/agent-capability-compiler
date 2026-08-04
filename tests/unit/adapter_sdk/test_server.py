from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import acc_adapter_sdk.server as server_module
from acc_adapter_sdk.contracts import AdapterContract, AdapterHealth, AdapterOperation


def _contract() -> AdapterContract:
    return AdapterContract.model_validate(
        {
            "schema_version": "1",
            "id": "example-crm-adapter",
            "version": "0.1.0",
            "base_path": "/adapter/v1",
            "health": {
                "path": "/healthz",
                "metadata": {"system": "example-crm", "mode": "test"},
            },
            "operations": [
                {
                    "id": "crm.get_customer",
                    "method": "GET",
                    "path": "/customers/{customer_id}",
                    "summary": "Get one customer",
                },
                {
                    "id": "crm.head_customer",
                    "method": "HEAD",
                    "path": "/customers/{customer_id}",
                    "summary": "Check customer existence",
                },
            ],
        }
    )


def _client(server: server_module.AdapterServer) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app),
        base_url="http://adapter.test",
    )


@pytest.mark.asyncio
async def test_adapter_server_exposes_health_metadata() -> None:
    server = server_module.AdapterServer(_contract())

    async with _client(server) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "schema_version": "1",
        "adapter": {"id": "example-crm-adapter", "version": "0.1.0"},
        "metadata": {"system": "example-crm", "mode": "test"},
    }


@pytest.mark.asyncio
async def test_adapter_server_registers_declared_get_and_head_routes_under_base_path() -> None:
    server = server_module.AdapterServer(_contract())

    async def get_customer(customer_id: str) -> dict[str, str]:
        return {"id": customer_id, "name": "Ada"}

    async def head_customer(customer_id: str) -> None:
        del customer_id

    server.register_operation("crm.get_customer", get_customer)
    server.register_operation("crm.head_customer", head_customer)

    async with _client(server) as client:
        get_response = await client.get("/adapter/v1/customers/c-1")
        head_response = await client.head("/adapter/v1/customers/c-1")
        write_response = await client.post("/adapter/v1/customers/c-1", json={"name": "Eve"})

    assert get_response.status_code == 200
    assert get_response.json() == {"id": "c-1", "name": "Ada"}
    assert head_response.status_code == 200
    assert head_response.content == b""
    assert write_response.status_code == 405
    assert server.registered_operation_ids == (
        "crm.get_customer",
        "crm.head_customer",
    )


def test_adapter_server_rejects_unknown_and_duplicate_registrations() -> None:
    server = server_module.AdapterServer(_contract())

    async def handler() -> dict[str, bool]:
        return {"ok": True}

    with pytest.raises(server_module.AdapterRegistrationError, match="not declared"):
        server.register_operation("crm.delete_customer", handler)

    server.register_operation("crm.get_customer", handler)
    with pytest.raises(server_module.AdapterRegistrationError, match="already registered"):
        server.register_operation("crm.get_customer", handler)


def test_adapter_server_rejects_write_routes_even_if_model_validation_was_bypassed() -> None:
    unsafe_operation = AdapterOperation.model_construct(
        id="crm.delete_customer",
        method="DELETE",
        path="/customers/{customer_id}",
        summary="Delete one customer",
    )
    unsafe_contract = AdapterContract.model_construct(
        schema_version="1",
        id="unsafe-adapter",
        version="0.1.0",
        base_path="/adapter/v1",
        health=AdapterHealth(path="/healthz", metadata={}),
        operations=[unsafe_operation],
    )

    with pytest.raises(server_module.AdapterRegistrationError, match="read-only"):
        server_module.AdapterServer(unsafe_contract)


@pytest.mark.asyncio
async def test_adapter_server_loads_scaffold_contract_yaml(tmp_path: Path) -> None:
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(
        """\
schema_version: "1"
id: generated-adapter
version: 0.1.0
base_path: /adapter/v1
operations: []
""",
        encoding="utf-8",
    )

    server = server_module.AdapterServer.from_contract_file(contract_path)

    assert server.contract.id == "generated-adapter"
    assert server.contract.operations == []
    async with _client(server) as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["metadata"] == {}
