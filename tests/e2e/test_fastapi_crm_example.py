from __future__ import annotations

import hashlib
import importlib
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryFile
from typing import Any, cast

import httpx
import pytest
import uvicorn
from mcp.client.stdio import StdioServerParameters

from acc_core.compiler import compile_project
from acc_core.packaging import build_pack
from acc_runtime import GenericRuntime
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.providers import (
    HttpForbiddenError,
    HttpNotFoundError,
    HttpProvider,
    HttpResponseTooLargeError,
    HttpTimeoutError,
)
from acc_testkit import McpStdioTestClient

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "examples" / "fastapi-crm" / "acc-project"
SYSTEM_SOURCE = ROOT / "examples" / "fastapi-crm" / "system" / "src"
FULL_TOKEN = "demo-tenant-a-reader"
CUSTOMER_ONLY_TOKEN = "demo-tenant-a-customer-reader"
FULL_SCOPES = {"customer.read", "contact.read", "followup.read", "todo.read"}


@contextmanager
def _crm_server() -> Iterator[str]:
    old_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(SYSTEM_SOURCE))
    try:
        app = importlib.import_module("fastapi_crm_system").app
    finally:
        sys.path.remove(str(SYSTEM_SOURCE))
        sys.dont_write_bytecode = old_bytecode

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    host, port = cast(tuple[str, int], listener.getsockname())
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False, lifespan="off"))
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        raise RuntimeError("synthetic CRM did not start")
    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()


@pytest.fixture(scope="module")
def crm_base_url() -> Iterator[str]:
    with _crm_server() as base_url:
        yield base_url


@pytest.fixture
def compiled_ir() -> dict[str, Any]:
    report = compile_project(PROJECT)
    assert report.ok, report.diagnostics
    assert report.ir is not None
    return cast(dict[str, Any], report.ir)


def _environment(base_url: str, token: str = FULL_TOKEN) -> dict[str, str]:
    return {"CRM_BASE_URL": base_url, "CRM_DEMO_TOKEN": token}


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def test_pack_is_deterministic_and_contains_no_demo_token(
    tmp_path: Path,
    compiled_ir: dict[str, Any],
) -> None:
    first = build_pack(PROJECT, tmp_path / "first.accpkg", compiled_ir=compiled_ir)
    second = build_pack(PROJECT, tmp_path / "second.accpkg", compiled_ir=compiled_ir)

    assert first.sha256 == second.sha256
    assert first.path.read_bytes() == second.path.read_bytes()
    assert FULL_TOKEN.encode() not in first.path.read_bytes()
    assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256


@pytest.mark.asyncio
async def test_runtime_uses_real_crm_and_enforces_disclosure(
    compiled_ir: dict[str, Any],
    crm_base_url: str,
) -> None:
    runtime = GenericRuntime(
        compiled_ir,
        provider=HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment=_environment(crm_base_url),
        ),
        granted_scopes=FULL_SCOPES,
        tenant_id="tenant-a",
    )

    result = await runtime.call("get_customer_context", {"customer_id": "cust-a-001"})

    assert isinstance(result, dict)
    customer = cast(dict[str, Any], result["customer"])
    contacts = cast(list[dict[str, Any]], result["contacts"])
    assert customer["name"] == "Acme Manufacturing"
    assert contacts[0]["email"] == "***"
    assert not _contains_key(result, "tenant_id")


@pytest.mark.asyncio
async def test_runtime_maps_real_crm_404_and_403(
    compiled_ir: dict[str, Any],
    crm_base_url: str,
) -> None:
    full_runtime = GenericRuntime(
        compiled_ir,
        provider=HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment=_environment(crm_base_url),
        ),
        granted_scopes=FULL_SCOPES,
        tenant_id="tenant-a",
    )
    limited_upstream = GenericRuntime(
        compiled_ir,
        provider=HttpProvider(
            base_url_ref="CRM_BASE_URL",
            environment=_environment(crm_base_url, CUSTOMER_ONLY_TOKEN),
        ),
        granted_scopes=FULL_SCOPES,
        tenant_id="tenant-a",
    )

    with pytest.raises(HttpNotFoundError) as missing:
        await full_runtime.call("get_customer_context", {"customer_id": "missing"})
    with pytest.raises(HttpForbiddenError) as forbidden:
        await limited_upstream.call("get_customer_context", {"customer_id": "cust-a-001"})

    assert (missing.value.code, missing.value.status) == ("ACC_RUNTIME_HTTP_NOT_FOUND", 404)
    assert (forbidden.value.code, forbidden.value.status) == ("ACC_RUNTIME_HTTP_FORBIDDEN", 403)
    assert FULL_TOKEN not in repr(missing.value)
    assert CUSTOMER_ONLY_TOKEN not in repr(forbidden.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response_kind", "error_type", "error_code"),
    [
        ("timeout", HttpTimeoutError, "ACC_RUNTIME_HTTP_TIMEOUT"),
        ("oversize", HttpResponseTooLargeError, "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"),
    ],
)
async def test_runtime_maps_timeout_and_oversize_stably(
    compiled_ir: dict[str, Any],
    response_kind: str,
    error_type: type[AccRuntimeError],
    error_code: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if response_kind == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(200, content=b"x" * 32769, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        runtime = GenericRuntime(
            compiled_ir,
            provider=HttpProvider(
                base_url_ref="CRM_BASE_URL",
                environment=_environment("http://crm.example.test"),
                client=client,
            ),
            granted_scopes={"customer.read"},
            tenant_id="tenant-a",
        )
        with pytest.raises(error_type) as caught:
            await runtime.call("search_customers", {"query": "acme"})

    assert caught.value.code == error_code
    assert FULL_TOKEN not in repr(caught.value)


@pytest.mark.asyncio
async def test_pack_serves_mcp_stdio_list_and_call_without_token_leak(
    tmp_path: Path,
    crm_base_url: str,
    compiled_ir: dict[str, Any],
) -> None:
    pack = build_pack(PROJECT, tmp_path / "crm.accpkg", compiled_ir=compiled_ir)
    environment = os.environ.copy()
    environment.update(
        {
            "CRM_BASE_URL": crm_base_url,
            "CRM_DEMO_TOKEN": FULL_TOKEN,
            "ACC_GRANTED_SCOPES": "customer.read contact.read followup.read todo.read",
            "ACC_TENANT_ID": "tenant-a",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "acc_core.cli.main", "run", str(pack.path)],
        env=environment,
        cwd=PROJECT,
    )
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with McpStdioTestClient(parameters, error_log=error_log) as client:
            listed = await client.list_tools()
            called = await client.call_tool(
                "get_customer_context",
                {"customer_id": "cust-a-001"},
            )
        error_log.seek(0)
        stderr = error_log.read()

    assert [tool.name for tool in listed.tools] == [
        "find_overdue_followups",
        "get_customer_context",
        "search_customers",
    ]
    assert called.isError is False
    assert called.structuredContent is not None
    result = called.structuredContent["result"]
    assert not _contains_key(result, "tenant_id")
    assert FULL_TOKEN not in stderr
