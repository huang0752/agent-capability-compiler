from __future__ import annotations

import importlib

import httpx
import pytest

import acc_adapter_sdk as adapter_sdk


def test_adapter_sdk_exports_its_public_contract_server_and_testing_api() -> None:
    expected = {
        "AdapterContract",
        "AdapterContractAssertionError",
        "AdapterActionOperation",
        "AdapterActionSafety",
        "AdapterHealth",
        "AdapterOperation",
        "AdapterRegistrationError",
        "AdapterServer",
        "assert_adapter_contract",
    }

    assert expected <= set(adapter_sdk.__all__)
    assert all(hasattr(adapter_sdk, name) for name in expected)


@pytest.mark.asyncio
async def test_fake_adapter_is_a_deployable_read_only_example() -> None:
    fake_adapter = importlib.import_module("acc_adapter_sdk.fake_adapter")
    server = fake_adapter.create_fake_adapter()

    adapter_sdk.assert_adapter_contract(server)
    assert fake_adapter.app is fake_adapter.server.app
    assert fake_adapter.FAKE_ADAPTER_CONTRACT.health.metadata == {
        "system": "fake-system",
        "purpose": "contract-example",
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app),
        base_url="http://adapter.test",
    ) as client:
        health = await client.get("/healthz")
        record = await client.get("/adapter/v2/records/r-1")
        exists = await client.head("/adapter/v2/records/r-1")
        missing = await client.get("/adapter/v2/records/missing")
        write = await client.delete("/adapter/v2/records/r-1")

    assert health.status_code == 200
    assert health.json()["adapter"] == {
        "id": "fake-readonly-adapter",
        "version": "0.1.0",
    }
    assert record.status_code == 200
    assert record.json() == {"id": "r-1", "label": "Example One", "scope": "scope-a"}
    assert exists.status_code == 200
    assert exists.content == b""
    assert missing.status_code == 404
    assert write.status_code == 405
