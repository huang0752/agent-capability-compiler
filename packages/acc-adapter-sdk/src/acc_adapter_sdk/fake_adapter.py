"""Deployable, domain-neutral read-only adapter demonstrating the SDK."""

from __future__ import annotations

from fastapi import HTTPException, Response

from acc_adapter_sdk.contracts import AdapterContract
from acc_adapter_sdk.server import AdapterServer

FAKE_ADAPTER_CONTRACT = AdapterContract.model_validate(
    {
        "schema_version": "2",
        "id": "fake-readonly-adapter",
        "version": "0.1.0",
        "base_path": "/adapter/v2",
        "health": {
            "path": "/healthz",
            "metadata": {
                "system": "fake-system",
                "purpose": "contract-example",
            },
        },
        "operations": [
            {
                "id": "records.get",
                "method": "GET",
                "path": "/records/{record_id}",
                "summary": "Get one fake record",
            },
            {
                "id": "records.head",
                "method": "HEAD",
                "path": "/records/{record_id}",
                "summary": "Check whether a fake record exists",
            },
        ],
    }
)

_RECORDS = {
    "r-1": {"id": "r-1", "label": "Example One", "scope": "scope-a"},
    "r-2": {"id": "r-2", "label": "Example Two", "scope": "scope-b"},
}


def _record(record_id: str) -> dict[str, str]:
    record = _RECORDS.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="record not found")
    return dict(record)


def create_fake_adapter() -> AdapterServer:
    """Create an isolated Fake Adapter server with all operations registered."""

    adapter = AdapterServer(FAKE_ADAPTER_CONTRACT)

    async def get_record(record_id: str) -> dict[str, str]:
        return _record(record_id)

    async def head_record(record_id: str) -> Response:
        _record(record_id)
        return Response(status_code=200)

    adapter.register_operation("records.get", get_record)
    adapter.register_operation("records.head", head_record)
    return adapter


server = create_fake_adapter()
app = server.app

__all__ = ["FAKE_ADAPTER_CONTRACT", "app", "create_fake_adapter", "server"]
