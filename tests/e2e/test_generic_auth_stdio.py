from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryFile
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from mcp import types
from mcp.client.stdio import StdioServerParameters

from acc_core.compiler import compile_project
from acc_core.packaging import build_pack
from acc_testkit import McpStdioTestClient

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACC_CORE_SRC = REPOSITORY_ROOT / "packages" / "acc-core" / "src"
IDENTITY_SECRET = "offline-user@example.test"
PASSWORD_SECRET = "offline-password-S3cr3t"
BEARER_SECRET = "offline-bearer-S3cr3t"
SOURCE_TOKENS = ("offline-source-token-one", "offline-source-token-two")


@dataclass
class _SourceState:
    auth_kind: str
    unauthorized_mode: str = "never"
    login_count: int = 0
    operation_count: int = 0
    queries: list[dict[str, list[str]]] = field(default_factory=list)
    authorization_values: list[str | None] = field(default_factory=list)
    login_bodies: list[dict[str, object]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


@contextmanager
def _fake_source(state: _SourceState) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/auth/login":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length))
            with state.lock:
                state.login_count += 1
                state.login_bodies.append(cast(dict[str, object], body))
                token = SOURCE_TOKENS[min(state.login_count - 1, 1)]
            response = json.dumps(
                {
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "permissions": ["source:item:read"],
                    "user": {"id": "upstream-principal"},
                }
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path != "/items/current":
                self.send_response(404)
                self.end_headers()
                return
            authorization = self.headers.get("authorization")
            with state.lock:
                state.operation_count += 1
                operation_number = state.operation_count
                state.authorization_values.append(authorization)
                state.queries.append(parse_qs(parsed.query))

            authorized = (
                (state.auth_kind == "none" and authorization is None)
                or (
                    state.auth_kind == "bearer_secret"
                    and authorization == f"Bearer {BEARER_SECRET}"
                )
                or (
                    state.auth_kind == "password_bearer"
                    and authorization in {f"Bearer {token}" for token in SOURCE_TOKENS}
                )
            )
            force_unauthorized = state.unauthorized_mode == "always" or (
                state.unauthorized_mode == "first" and operation_number == 1
            )
            if not authorized or force_unauthorized:
                self.send_response(401)
                self.end_headers()
                return
            response = b'{"ok":true}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast(tuple[str, int], server.server_address)
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _auth_config(kind: str, *, retry_on_unauthorized: bool) -> dict[str, object]:
    if kind == "none":
        return {"kind": "none"}
    if kind == "bearer_secret":
        return {"kind": "bearer_secret", "token_ref": "FAKE_SOURCE_TOKEN"}
    return {
        "kind": "password_bearer",
        "credentials": {
            "kind": "environment_secret",
            "identity_ref": "FAKE_SOURCE_IDENTITY",
            "password_ref": "FAKE_SOURCE_PASSWORD",
        },
        "login_path": "/auth/login",
        "identity_field": "identity",
        "password_field": "password",
        "token_pointer": "/access_token",
        "token_type_pointer": "/token_type",
        "expires_in_pointer": "/expires_in",
        "principal_pointer": "/user/id",
        "scopes_pointer": "/permissions",
        "scope_mapping": {"source:item:read": ["item.read"]},
        "retry_on_unauthorized": retry_on_unauthorized,
    }


def _make_project(
    root: Path,
    *,
    auth_kind: str,
    retry_on_unauthorized: bool = False,
) -> Path:
    source = root / "system"
    source.mkdir()
    (source / "routes.py").write_text("def current_item(): ...\n", encoding="utf-8")
    project = root / "acc-project"
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "1",
            "project": {"id": "generic-auth-offline", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "FAKE_SOURCE_BASE_URL",
                "auth": _auth_config(
                    auth_kind,
                    retry_on_unauthorized=retry_on_unauthorized,
                ),
                "context_binding_allowlist": ["tenant_context.tenant_id"],
            },
        },
    )
    _write_yaml(
        project / "operations" / "offline.current_item.yaml",
        {
            "schema_version": "1",
            "id": "offline.current_item",
            "title": "Current item",
            "kind": "http",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["actor_id", "tenant_id"],
                "properties": {
                    "actor_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                },
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["ok"],
                "properties": {"ok": {"type": "boolean"}},
            },
            "context_bindings": {
                "actor_id": "principal_id",
                "tenant_id": "tenant_context.tenant_id",
            },
            "http": {
                "method": "GET",
                "path": "/items/current",
                "path_parameters": {},
                "query_parameters": {"actor": "actor_id", "tenant": "tenant_id"},
                "scopes": ["item.read"],
                "timeout_seconds": 5,
                "max_response_bytes": 4096,
            },
            "safety": {"effect": "read"},
            "evidence": [
                {
                    "source_id": "offline-route",
                    "locator": "routes.py#L1-L1",
                    "digest": f"sha256:{'0' * 64}",
                }
            ],
        },
    )
    _write_yaml(
        project / "policies" / "offline-read.yaml",
        {
            "schema_version": "1",
            "id": "offline-read",
            "required_scopes": ["item.read"],
            "tenant_mode": "none",
            "readable_fields": ["ok"],
            "denied_fields": [],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "get_current_item.yaml",
        {
            "schema_version": "1",
            "id": "get_current_item",
            "title": "Get current item",
            "description": "Read one item through an offline fake source.",
            "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["ok"],
                "properties": {"ok": {"type": "boolean"}},
            },
            "workflow": [
                {"id": "item", "call": {"operation": "offline.current_item", "arguments": {}}},
                {"emit": {"value": "$.steps.item"}},
            ],
            "policy": "offline-read",
            "evals": ["offline-normal"],
        },
    )
    _write_yaml(
        project / "evals" / "offline-normal.yaml",
        {
            "schema_version": "1",
            "id": "offline-normal",
            "capability": "get_current_item",
            "input": {},
            "fixtures": {},
            "expected_calls": [],
            "expected_output_schema": {"type": "object"},
            "forbidden_fields": ["authorization"],
        },
    )
    return project


async def _exercise_stdio(
    project: Path,
    base_url: str,
    *,
    call_count: int,
) -> tuple[bytes, str, list[types.Tool], list[types.CallToolResult]]:
    report = compile_project(project)
    assert report.ok, report.diagnostics
    assert report.ir is not None
    pack = build_pack(project, project / "offline.accpkg", compiled_ir=report.ir)
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join([str(ACC_CORE_SRC), environment.get("PYTHONPATH", "")]),
            "FAKE_SOURCE_BASE_URL": base_url,
            "FAKE_SOURCE_TOKEN": BEARER_SECRET,
            "FAKE_SOURCE_IDENTITY": IDENTITY_SECRET,
            "FAKE_SOURCE_PASSWORD": PASSWORD_SECRET,
            "ACC_GRANTED_SCOPES": "item.read",
            "ACC_PRINCIPAL_ID": "stdio-principal-a",
            "ACC_TENANT_ID": "tenant-a",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "acc_core.cli.main", "run", str(pack.path)],
        env=environment,
        cwd=project,
    )
    listed: list[types.Tool] = []
    called: list[types.CallToolResult] = []
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with McpStdioTestClient(parameters, error_log=error_log) as client:
            listed.extend((await client.list_tools()).tools)
            for _ in range(call_count):
                called.append(await client.call_tool("get_current_item", {}))
        error_log.seek(0)
        stderr = error_log.read()
    return pack.path.read_bytes(), stderr, listed, called


def _assert_secrets_absent(value: object) -> None:
    serialized = value if isinstance(value, bytes) else repr(value).encode()
    for secret in (IDENTITY_SECRET, PASSWORD_SECRET, BEARER_SECRET, *SOURCE_TOKENS):
        assert secret.encode() not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_kind", ["none", "bearer_secret", "password_bearer"])
async def test_stdio_auth_kinds_use_fixed_principal_and_keep_secrets_private(
    tmp_path: Path,
    auth_kind: str,
) -> None:
    project = _make_project(tmp_path, auth_kind=auth_kind)
    state = _SourceState(auth_kind=auth_kind)
    with _fake_source(state) as base_url:
        pack_bytes, stderr, listed, called = await _exercise_stdio(
            project,
            base_url,
            call_count=2,
        )

    assert [tool.name for tool in listed] == ["get_current_item"]
    assert all(result.isError is False for result in called)
    assert b"stdio-principal-a" not in repr(listed).encode()
    assert state.operation_count == 2
    assert state.login_count == (1 if auth_kind == "password_bearer" else 0)
    assert state.queries == [
        {"actor": ["stdio-principal-a"], "tenant": ["tenant-a"]},
        {"actor": ["stdio-principal-a"], "tenant": ["tenant-a"]},
    ]
    if auth_kind == "password_bearer":
        assert state.login_bodies == [{"identity": IDENTITY_SECRET, "password": PASSWORD_SECRET}]
    _assert_secrets_absent(pack_bytes)
    _assert_secrets_absent(stderr)
    _assert_secrets_absent(listed)
    _assert_secrets_absent(called)


@pytest.mark.asyncio
async def test_stdio_password_auth_relogs_once_after_first_401_when_enabled(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path,
        auth_kind="password_bearer",
        retry_on_unauthorized=True,
    )
    state = _SourceState(auth_kind="password_bearer", unauthorized_mode="first")
    with _fake_source(state) as base_url:
        pack_bytes, stderr, listed, called = await _exercise_stdio(
            project,
            base_url,
            call_count=1,
        )

    assert state.login_count == 2
    assert state.operation_count == 2
    assert called[0].isError is False
    _assert_secrets_absent((pack_bytes, stderr, listed, called))


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_on_unauthorized", [False, True])
async def test_stdio_password_auth_401_is_stable_and_never_leaks_secrets(
    tmp_path: Path,
    retry_on_unauthorized: bool,
) -> None:
    project = _make_project(
        tmp_path,
        auth_kind="password_bearer",
        retry_on_unauthorized=retry_on_unauthorized,
    )
    state = _SourceState(auth_kind="password_bearer", unauthorized_mode="always")
    with _fake_source(state) as base_url:
        pack_bytes, stderr, listed, called = await _exercise_stdio(
            project,
            base_url,
            call_count=1,
        )

    assert state.login_count == (2 if retry_on_unauthorized else 1)
    assert state.operation_count == (2 if retry_on_unauthorized else 1)
    result = called[0]
    assert result.isError is True
    structured = cast(Mapping[str, Any], result.structuredContent)
    assert structured["error"]["code"] == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    _assert_secrets_absent((pack_bytes, stderr, listed, called))
