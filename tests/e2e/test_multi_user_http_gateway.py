from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml
from mcp import types
from pydantic import JsonValue

from acc_core.compiler import compile_project
from acc_core.packaging import build_pack
from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import (
    GatewayRuntimeComposition,
    GatewaySettings,
    MemoryAuditSink,
    create_gateway_runtime,
)
from acc_runtime.runtime import GenericRuntime
from acc_testkit import McpStreamableHttpTestClient

pytestmark = pytest.mark.e2e

PROJECT_ID = "offline-multi-user"
PASSWORDS = {
    "a@example.test": "A-password-private",
    "b@example.test": "B-password-private",
    "c@example.test": "C-password-private",
}
SOURCE_TOKENS = {
    "a@example.test": "source-jwt-a-private",
    "b@example.test": "source-jwt-b-private",
    "c@example.test": "source-jwt-c-private",
}
TENANTS = {
    "a@example.test": "tenant-a",
    "b@example.test": "tenant-b",
    "c@example.test": "tenant-c",
}
PRINCIPALS = {
    "a@example.test": "principal-a",
    "b@example.test": "principal-b",
    "c@example.test": "principal-c",
}


@dataclass
class _SourceState:
    force_unauthorized: set[str] = field(default_factory=set)
    login_count: dict[str, int] = field(default_factory=dict)
    calls: list[dict[str, str | None]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


@contextmanager
def _fake_source(state: _SourceState) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/api/login":
                self.send_response(404)
                self.end_headers()
                return
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            identity = body.get("email")
            password = body.get("password")
            if not isinstance(identity, str) or PASSWORDS.get(identity) != password:
                self.send_response(401)
                self.end_headers()
                return
            with state.lock:
                state.login_count[identity] = state.login_count.get(identity, 0) + 1
            payload = json.dumps(
                {
                    "access_token": SOURCE_TOKENS[identity],
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "user": {
                        "id": PRINCIPALS[identity],
                        "tenant": {"tenant_id": TENANTS[identity]},
                    },
                    "permissions": ["source:records:read"],
                }
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path != "/api/records/current":
                self.send_response(404)
                self.end_headers()
                return
            authorization = self.headers.get("authorization")
            identity = next(
                (
                    email
                    for email, token in SOURCE_TOKENS.items()
                    if authorization == f"Bearer {token}"
                ),
                None,
            )
            query = parse_qs(parsed.query)
            with state.lock:
                forced = identity is not None and identity in state.force_unauthorized
                if forced:
                    assert identity is not None
                    state.force_unauthorized.remove(identity)
                state.calls.append(
                    {
                        "identity": identity,
                        "actor": query.get("actor", [None])[0],
                        "tenant": query.get("tenant", [None])[0],
                    }
                )
            if identity is None or forced:
                self.send_response(401)
                self.end_headers()
                return
            if query.get("actor") != [PRINCIPALS[identity]] or query.get("tenant") != [
                TENANTS[identity]
            ]:
                self.send_response(403)
                self.end_headers()
                return
            payload = json.dumps(
                {
                    "owner": PRINCIPALS[identity],
                    "tenant_id": TENANTS[identity],
                    "record": f"visible-only-to-{PRINCIPALS[identity]}",
                }
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

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


def _make_gateway_project(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    (source / "routes.py").write_text("def current_record(): ...\n", encoding="utf-8")
    project = root / "project"
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "1",
            "project": {"id": PROJECT_ID, "version": "0.1.0"},
            "source_workspace": {"path": "../source", "mode": "read_only"},
            "runtime": {"transport": ["streamable_http"]},
            "provider": {
                "kind": "http",
                "base_url_ref": "OFFLINE_SOURCE_BASE_URL",
                "auth": {
                    "kind": "password_bearer",
                    "credentials": {"kind": "gateway_session"},
                    "login_path": "/api/login",
                    "identity_field": "email",
                    "password_field": "password",
                    "token_pointer": "/access_token",
                    "token_type_pointer": "/token_type",
                    "expires_in_pointer": "/expires_in",
                    "principal_pointer": "/user/id",
                    "scopes_pointer": "/permissions",
                    "tenant_pointer": "/user/tenant",
                    "scope_mapping": {"source:records:read": ["records.read"]},
                },
                "context_binding_allowlist": ["tenant_context.tenant_id"],
            },
        },
    )
    _write_yaml(
        project / "operations" / "records.current.yaml",
        {
            "schema_version": "1",
            "id": "records.current",
            "title": "Current record",
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
                "required": ["owner", "tenant_id", "record"],
                "properties": {
                    "owner": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "record": {"type": "string"},
                },
            },
            "context_bindings": {
                "actor_id": "principal_id",
                "tenant_id": "tenant_context.tenant_id",
            },
            "http": {
                "method": "GET",
                "path": "/api/records/current",
                "path_parameters": {},
                "query_parameters": {"actor": "actor_id", "tenant": "tenant_id"},
                "scopes": ["records.read"],
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
    output_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["owner", "tenant_id", "record"],
        "properties": {
            "owner": {"type": "string"},
            "tenant_id": {"type": "string"},
            "record": {"type": "string"},
        },
    }
    _write_yaml(
        project / "policies" / "records-read.yaml",
        {
            "schema_version": "1",
            "id": "records-read",
            "required_scopes": ["records.read"],
            "tenant_mode": "required",
            "tenant_field": "tenant_id",
            "readable_fields": ["owner", "tenant_id", "record"],
            "denied_fields": [],
            "redaction_rules": [],
        },
    )
    _write_yaml(
        project / "capabilities" / "records_current.yaml",
        {
            "schema_version": "1",
            "id": "records_current",
            "title": "Current record",
            "description": "Read only the current user's offline record.",
            "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
            "output_schema": output_schema,
            "workflow": [
                {"id": "record", "call": {"operation": "records.current", "arguments": {}}},
                {"emit": {"value": "$.steps.record"}},
            ],
            "policy": "records-read",
            "evals": ["offline-normal"],
        },
    )
    _write_yaml(
        project / "evals" / "offline-normal.yaml",
        {
            "schema_version": "1",
            "id": "offline-normal",
            "capability": "records_current",
            "input": {},
            "fixtures": {},
            "expected_calls": [],
            "expected_output_schema": {"type": "object"},
            "forbidden_fields": ["authorization", "cookie"],
        },
    )
    return project


@dataclass
class _Harness:
    transport: httpx.ASGITransport
    http: httpx.AsyncClient
    composition: GatewayRuntimeComposition
    audit: MemoryAuditSink


@asynccontextmanager
async def _gateway_harness(
    project: Path,
    source_url: str,
    *,
    ttl_seconds: int = 30,
) -> AsyncIterator[_Harness]:
    report = compile_project(project)
    assert report.ok, report.diagnostics
    assert report.ir is not None
    pack = build_pack(project, project / "offline.accpkg", compiled_ir=report.ir)
    audit = MemoryAuditSink()
    composition = create_gateway_runtime(
        pack_path=pack.path,
        settings=GatewaySettings(
            allowed_hosts=("gateway.test",),
            allowed_origins=("http://gateway.test",),
            session_ttl_seconds=ttl_seconds,
            max_sessions=8,
        ),
        environment={"OFFLINE_SOURCE_BASE_URL": source_url},
        deployment_scope_ceiling={"records.read"},
        mcp_session_idle_timeout_seconds=min(0.5, float(ttl_seconds)),
        audit_sink=audit,
        audit_deployment_salt=b"offline-audit-salt-private",
    )
    transport = httpx.ASGITransport(app=composition.app)
    async with (
        composition.app.router.lifespan_context(composition.app),
        httpx.AsyncClient(
            transport=transport,
            base_url="http://gateway.test",
            headers={"origin": "http://gateway.test"},
        ) as http,
    ):
        yield _Harness(transport, http, composition, audit)


async def _login(http: httpx.AsyncClient, identity: str) -> SecretValue:
    response = await http.post(
        "/runtime/sessions",
        json={"identity": identity, "password": PASSWORDS[identity]},
    )
    assert response.status_code == 201, response.text
    token = response.json()["token"]
    assert isinstance(token, str)
    return SecretValue(token)


def _tool_payload(result: types.CallToolResult) -> dict[str, JsonValue]:
    structured = result.structuredContent
    assert isinstance(structured, dict)
    payload = structured.get("result")
    assert isinstance(payload, dict)
    return cast(dict[str, JsonValue], payload)


def _secret_scan(value: object, gateway_tokens: list[SecretValue]) -> None:
    text = value if isinstance(value, bytes) else repr(value).encode()
    for secret in [*PASSWORDS.values(), *SOURCE_TOKENS.values()]:
        assert secret.encode() not in text
    for token in gateway_tokens:
        assert token.get_secret_value().encode() not in text
    lowered = text.lower()
    assert b"authorization: bearer" not in lowered
    assert b"cookie:" not in lowered


@pytest.mark.anyio
async def test_a_b_c_are_isolated_across_gateway_mcp_source_and_context(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    project = _make_gateway_project(tmp_path)
    state = _SourceState()
    caplog.set_level(logging.INFO)
    with _fake_source(state) as source_url:
        async with _gateway_harness(project, source_url) as harness:
            tokens = [await _login(harness.http, identity) for identity in PASSWORDS]
            clients = [
                McpStreamableHttpTestClient(
                    "http://gateway.test/mcp", token, transport=harness.transport
                )
                for token in tokens
            ]
            async with clients[0] as client_a, clients[1] as client_b, clients[2] as client_c:
                listed_tools = await client_a.list_tools()
                assert [tool.name for tool in listed_tools.tools] == ["records_current"]
                results = await asyncio.gather(
                    client_a.call_tool("records_current", {}),
                    client_b.call_tool("records_current", {}),
                    client_c.call_tool("records_current", {}),
                )
                assert [_tool_payload(result) for result in results] == [
                    {
                        "owner": f"principal-{letter}",
                        "tenant_id": f"tenant-{letter}",
                        "record": f"visible-only-to-principal-{letter}",
                    }
                    for letter in "abc"
                ]
                assert len({client.session_id for client in clients}) == 3

                for method in ("POST", "GET", "DELETE"):
                    for token_index, token in enumerate(tokens):
                        for session_index, client in enumerate(clients):
                            if token_index == session_index:
                                continue
                            response = await harness.http.request(
                                method,
                                "/mcp",
                                headers={
                                    "authorization": f"Bearer {token.get_secret_value()}",
                                    "mcp-session-id": cast(str, client.session_id),
                                    "content-type": "application/json",
                                    "accept": "application/json, text/event-stream",
                                },
                                json=(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": 70,
                                        "method": "tools/list",
                                    }
                                    if method == "POST"
                                    else None
                                ),
                            )
                            assert response.status_code == 404

                override = await client_a.call_tool(
                    "records_current", {"principalId": "principal-b"}
                )
                assert override.isError is True
                assert override.structuredContent is None
                assert isinstance(override.content[0], types.TextContent)
                assert "Additional properties are not allowed" in override.content[0].text
                assert "principal-b" not in override.content[0].text

                state.force_unauthorized.add("a@example.test")
                denied = await client_a.call_tool("records_current", {})
                assert denied.isError is True
                assert isinstance(denied.structuredContent, dict)
                denied_error = denied.structuredContent.get("error")
                assert isinstance(denied_error, dict)
                assert denied_error["code"] == "ACC_RUNTIME_AUTH_UNAUTHORIZED"
                assert _tool_payload(await client_b.call_tool("records_current", {}))["owner"] == (
                    "principal-b"
                )
                reauth = await harness.http.post(
                    "/mcp",
                    headers={
                        "authorization": f"Bearer {tokens[0].get_secret_value()}",
                        "mcp-session-id": cast(str, client_a.session_id),
                    },
                    json={"jsonrpc": "2.0", "id": 90, "method": "tools/list"},
                )
                assert reauth.status_code == 401

            logout = await harness.http.delete(
                "/runtime/sessions/current",
                headers={"authorization": f"Bearer {tokens[1].get_secret_value()}"},
            )
            assert logout.status_code == 204
            assert (
                await harness.http.post(
                    "/mcp",
                    headers={"authorization": f"Bearer {tokens[1].get_secret_value()}"},
                    json={},
                )
            ).status_code == 401

            report = compile_project(project)
            assert report.ir is not None
            pack = build_pack(project, project / "offline.accpkg", compiled_ir=report.ir)
            public_surfaces = {
                "tools": [tool.model_dump() for tool in listed_tools.tools],
                "business_results": [result.model_dump() for result in results],
                "errors": [denied.model_dump(), override.model_dump()],
                "audit": [event.to_dict() for event in harness.audit.events],
                "logs": [record.getMessage() for record in caplog.records],
                "repr": [repr(harness.composition), repr(harness.audit.events)],
                "coverage_fixture": {"offline_candidate": True, "covered_users": 3},
                "test_fixture": {"result": "isolated"},
                "handoff_fixture": {"status": "offline"},
                "artifact_manifest_fixture": {"pack": pack.path.name},
            }
            _secret_scan(public_surfaces, tokens)
            _secret_scan(pack.path.read_bytes(), tokens)

        async with _gateway_harness(project, source_url, ttl_seconds=1) as restarted:
            for token in tokens:
                response = await restarted.http.post(
                    "/mcp",
                    headers={"authorization": f"Bearer {token.get_secret_value()}"},
                    json={},
                )
                assert response.status_code == 401
            expiring = await _login(restarted.http, "c@example.test")
            await asyncio.sleep(1.05)
            expired = await restarted.http.post(
                "/mcp",
                headers={"authorization": f"Bearer {expiring.get_secret_value()}"},
                json={},
            )
            assert expired.status_code == 401
            _secret_scan(expired.text, [*tokens, expiring])


class _EchoProvider:
    async def call(
        self,
        operation: Mapping[str, object],
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        del operation, principal_context
        return {
            "owner": arguments["actor_id"],
            "tenant_id": arguments["tenant_id"],
            "record": f"visible-only-to-{arguments['actor_id']}",
        }


@pytest.mark.anyio
async def test_stdio_and_http_context_have_identical_business_and_policy_output(
    tmp_path: Path,
) -> None:
    report = compile_project(_make_gateway_project(tmp_path))
    assert report.ok and report.ir is not None
    http_context = PrincipalContext(
        principal_id="principal-a",
        gateway_session_id="gateway-a",
        target_system_id=PROJECT_ID,
        source_scopes={"source:records:read"},
        deployment_scope_ceiling={"records.read"},
        scope_mapping={"source:records:read": ["records.read"]},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="auth-a",
    )
    stdio_context = PrincipalContext(
        principal_id="principal-a",
        gateway_session_id=None,
        target_system_id=PROJECT_ID,
        source_scopes={"source:records:read"},
        deployment_scope_ceiling={"records.read"},
        scope_mapping={"source:records:read": ["records.read"]},
        tenant_context={"tenant_id": "tenant-a"},
        auth_state_handle="stdio:offline-multi-user",
    )
    runtime = GenericRuntime(report.ir, provider=_EchoProvider())
    assert await runtime.call_with_context("records_current", {}, http_context) == (
        await runtime.call_with_context("records_current", {}, stdio_context)
    )


@dataclass(frozen=True)
class _OfflineCandidate:
    name: str
    auth: Mapping[str, object]
    transport: Literal["stdio", "streamable_http"]
    offline_candidate: Literal[True] = True


@pytest.mark.parametrize(
    "candidate",
    [
        _OfflineCandidate(
            "crm-legacy-provider-bearer",
            {"kind": "bearer_secret", "token_ref": "CRM_LEGACY_TOKEN"},
            "stdio",
        ),
        _OfflineCandidate(
            "crm-new-provider-bearer",
            {"kind": "bearer_secret", "token_ref": "CRM_NEW_TOKEN"},
            "stdio",
        ),
        _OfflineCandidate("warehouse-none", {"kind": "none"}, "stdio"),
        _OfflineCandidate(
            "warehouse-bearer",
            {"kind": "bearer_secret", "token_ref": "WAREHOUSE_TOKEN"},
            "stdio",
        ),
        _OfflineCandidate(
            "baogao-jin-fake-email-password",
            {
                "kind": "password_bearer",
                "credentials": {"kind": "gateway_session"},
                "login_path": "/api/login",
                "identity_field": "email",
                "password_field": "password",
                "token_pointer": "/access_token",
                "scopes_pointer": "/permissions",
                "scope_mapping": {"source:records:read": ["records.read"]},
            },
            "streamable_http",
        ),
    ],
    ids=lambda candidate: candidate.name,
)
def test_representative_provider_fixtures_are_explicitly_offline_candidates(
    candidate: _OfflineCandidate,
) -> None:
    assert candidate.offline_candidate is True
    assert candidate.name.startswith(("crm-", "warehouse-", "baogao-jin-fake-"))
    if candidate.name.startswith("baogao-jin"):
        assert candidate.transport == "streamable_http"
        assert candidate.auth["credentials"] == {"kind": "gateway_session"}
        assert "baogao-jin" not in repr(PASSWORDS).casefold()
    else:
        assert candidate.transport == "stdio"
        assert candidate.auth["kind"] in {"none", "bearer_secret"}
