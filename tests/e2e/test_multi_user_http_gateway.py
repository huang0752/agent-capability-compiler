from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryFile
from typing import Literal, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml
from mcp import types
from mcp.client.stdio import StdioServerParameters
from pydantic import JsonValue

from acc_core.compiler import compile_project
from acc_core.coverage import analyze_coverage
from acc_core.packaging import build_pack, load_pack_manifest
from acc_core.scope import ScopeInventory
from acc_core.validation import validate_project
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import (
    GatewayRuntimeComposition,
    GatewaySettings,
    MemoryAuditSink,
    create_gateway_runtime,
)
from acc_runtime.runtime import GenericRuntime
from acc_testkit import McpStdioTestClient, McpStreamableHttpTestClient

pytestmark = pytest.mark.e2e

PROJECT_ID = "offline-multi-user"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACC_CORE_SRC = REPOSITORY_ROOT / "packages" / "acc-core" / "src"
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
SOURCE_SCOPES = {
    "a@example.test": "source:a:records:read",
    "b@example.test": "source:b:records:read",
    "c@example.test": "source:c:records:read",
}


@dataclass(frozen=True)
class _SourceFixtureMetadata:
    name: Literal["baogao-jin-auth-shape"] = "baogao-jin-auth-shape"
    verification_level: Literal["offline_candidate"] = "offline_candidate"
    generic_fake_auth_shape_only: Literal[True] = True
    source_connected: Literal[False] = False
    real_source_or_account_accessed: Literal[False] = False


BAOGAO_JIN_FAKE = _SourceFixtureMetadata()


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
                    "permissions": [SOURCE_SCOPES[identity]],
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


def _scope_inventory() -> ScopeInventory:
    return ScopeInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "pilot", "selected_domains": ["records"]},
            "domains": [{"id": "records", "status": "selected"}],
            "routes": [
                {
                    "id": "GET /api/records/current",
                    "domain": "records",
                    "method": "GET",
                    "kind": "read",
                    "effect": "read",
                    "path": "/api/records/current",
                    "evidence_sources": ["routes.py"],
                    "eligibility": "eligible",
                    "disposition": "composed",
                    "operation_id": "records.current",
                    "capability_ids": ["records_current"],
                }
            ],
            "summary": {
                "discovered_routes": 1,
                "eligible_routes": 1,
                "planned": 0,
                "composed": 1,
                "excluded": 0,
                "blocked_on_evidence": 0,
                "out_of_scope": 0,
                "unresolved": 0,
            },
        }
    )


def _make_gateway_project(root: Path) -> Path:
    source = root / "source"
    source.mkdir(parents=True)
    (source / "routes.py").write_text("def current_record(): ...\n", encoding="utf-8")
    project = root / "project"
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": PROJECT_ID, "version": "2.0.0"},
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
                    "scope_mapping": {
                        source_scope: ["records.read"] for source_scope in SOURCE_SCOPES.values()
                    },
                },
                "context_binding_allowlist": ["tenant_context.tenant_id"],
            },
            "quality": {"profile": "standard"},
        },
    )
    _write_yaml(
        project / "operations" / "records.current.yaml",
        {
            "schema_version": "2",
            "kind": "read",
            "id": "records.current",
            "title": "Current record",
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
                "request": None,
                "success": {"statuses": [200], "body": "json"},
                "scopes": ["records.read"],
                "timeout_seconds": 5,
                "max_response_bytes": 4096,
                "safety": {
                    "effect": "read",
                    "risk": "low",
                    "reversibility": "reversible",
                    "retry": {"mode": "idempotent_only"},
                    "idempotency": {"mode": "unsupported"},
                    "concurrency": {"mode": "not_supported"},
                },
            },
            "evidence": [
                {
                    "source_id": "offline-route",
                    "kind": "source_file",
                    "path": "routes.py",
                    "json_pointer": None,
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
            "schema_version": "2",
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
            "schema_version": "2",
            "kind": "read",
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
            "schema_version": "2",
            "id": "offline-normal",
            "capability": "records_current",
            "input": {},
            "fixtures": {},
            "expected_calls": [],
            "expected_output_schema": {"type": "object"},
            "expected_error": None,
            "forbidden_fields": ["authorization", "cookie"],
        },
    )
    operation_input = {
        "type": "object",
        "additionalProperties": False,
        "required": ["actor_id", "tenant_id"],
        "properties": {
            "actor_id": {"type": "string"},
            "tenant_id": {"type": "string"},
        },
    }
    _write_yaml(
        project / "source-contracts" / "records.current.yaml",
        {
            "schema_version": "2",
            "id": "records.current.contract",
            "operation_id": "records.current",
            "request_schema": operation_input,
            "response_schema": output_schema,
            "request_completeness": "complete",
            "response_completeness": "complete",
            "provenance": [],
        },
    )
    _write_yaml(
        project / "capability-quality" / "records_current.yaml",
        {
            "schema_version": "2",
            "capability_id": "records_current",
            "intent": {"action": "get", "resource_types": ["record"]},
            "inputs": {},
            "composition": {"failure_mode": "fail_fast"},
            "output_budget": {"max_bytes": 65536},
        },
    )
    return project


@dataclass
class _Harness:
    transport: httpx.ASGITransport
    http: httpx.AsyncClient
    composition: GatewayRuntimeComposition
    audit: MemoryAuditSink
    pack_sha256: str


@asynccontextmanager
async def _gateway_harness(
    project: Path,
    source_url: str,
    *,
    ttl_seconds: int = 30,
    deployment_scope_ceiling: frozenset[str] = frozenset({"records.read"}),
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
        deployment_scope_ceiling=deployment_scope_ceiling,
        # Keep the MCP transport alive long enough for concurrent source calls
        # on slower CI/Windows hosts. Session-token expiry is exercised below
        # through ``session_ttl_seconds`` and does not require a sub-second MCP
        # idle timeout.
        mcp_session_idle_timeout_seconds=float(ttl_seconds),
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
        yield _Harness(transport, http, composition, audit, pack.sha256)


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


def _secret_scan(
    value: object,
    gateway_tokens: list[SecretValue],
    *,
    extra_secrets: tuple[str, ...] = (),
) -> None:
    text = value if isinstance(value, bytes) else repr(value).encode()
    for secret in [*PASSWORDS.values(), *SOURCE_TOKENS.values(), *extra_secrets]:
        assert secret.encode() not in text
    for token in gateway_tokens:
        assert token.get_secret_value().encode() not in text
    lowered = text.lower()
    assert b"authorization: bearer" not in lowered
    assert b"cookie:" not in lowered


@pytest.mark.anyio
async def test_baogao_jin_auth_shape_offline_candidate_isolates_a_b_c(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    assert BAOGAO_JIN_FAKE.verification_level == "offline_candidate"
    assert BAOGAO_JIN_FAKE.generic_fake_auth_shape_only is True
    assert BAOGAO_JIN_FAKE.source_connected is False
    assert BAOGAO_JIN_FAKE.real_source_or_account_accessed is False
    project = _make_gateway_project(tmp_path)
    state = _SourceState()
    caplog.set_level(logging.INFO)
    with _fake_source(state) as source_url:
        async with _gateway_harness(project, source_url) as harness:
            tokens = [await _login(harness.http, identity) for identity in PASSWORDS]
            runtime_info = harness.composition.runtime_info()
            runtime_info_response = await harness.http.get(
                "/runtime/info",
                headers={"authorization": f"Bearer {tokens[0].get_secret_value()}"},
            )
            assert runtime_info_response.status_code == 200
            assert runtime_info_response.json() == runtime_info.model_dump(mode="json")
            assert runtime_info.pack_sha256 == harness.pack_sha256
            assert runtime_info.project_id == PROJECT_ID
            assert runtime_info.project_version == "2.0.0"
            assert runtime_info.transport == "streamable_http"
            assert set(runtime_info_response.json()) == {
                "pack_sha256",
                "project_id",
                "project_version",
                "interaction_sha256",
                "tool_schema_sha256",
                "transport",
            }
            _secret_scan(runtime_info_response.content, tokens)
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
            coverage = analyze_coverage(validate_project(project), _scope_inventory())
            manifest = load_pack_manifest(pack.path).to_dict()
            public_surfaces = {
                "fixture_metadata": BAOGAO_JIN_FAKE,
                "compiled_ir": report.ir,
                "pack_manifest": manifest,
                "coverage": coverage,
                "tools": [tool.model_dump() for tool in listed_tools.tools],
                "business_results": [result.model_dump() for result in results],
                "errors": [denied.model_dump(), override.model_dump()],
                "audit": [event.to_dict() for event in harness.audit.events],
                "logs": [record.getMessage() for record in caplog.records],
                "repr": [repr(harness.composition), repr(harness.audit.events)],
            }
            _secret_scan(public_surfaces, tokens)
            _secret_scan(pack.path.read_bytes(), tokens)
            for absent_delivery in (
                "HANDOFF.md",
                "artifact-manifest.json",
                "candidate.diff",
                "coverage-report.json",
                "risk-report.json",
                "scope-audit-report.json",
                "test-report.json",
            ):
                assert not (project / absent_delivery).exists()

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


def _make_stdio_project(root: Path) -> Path:
    project = _make_gateway_project(root)
    project_document = yaml.safe_load((project / "project.yaml").read_text(encoding="utf-8"))
    project_document["runtime"] = {"transport": ["stdio"]}
    project_document["provider"]["auth"]["credentials"] = {
        "kind": "environment_secret",
        "identity_ref": "OFFLINE_SOURCE_IDENTITY",
        "password_ref": "OFFLINE_SOURCE_PASSWORD",
    }
    _write_yaml(project / "project.yaml", project_document)
    return project


async def _exercise_stdio(
    project: Path,
    source_url: str,
    *,
    scopes: str,
) -> tuple[types.ListToolsResult, types.CallToolResult, str, bytes, object, object]:
    report = compile_project(project)
    assert report.ok, report.diagnostics
    assert report.ir is not None
    pack = build_pack(project, project / "offline-stdio.accpkg", compiled_ir=report.ir)
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join([str(ACC_CORE_SRC), environment.get("PYTHONPATH", "")]),
            "OFFLINE_SOURCE_BASE_URL": source_url,
            "OFFLINE_SOURCE_IDENTITY": "a@example.test",
            "OFFLINE_SOURCE_PASSWORD": PASSWORDS["a@example.test"],
            "ACC_GRANTED_SCOPES": scopes,
            "ACC_PRINCIPAL_ID": "principal-a",
            "ACC_TENANT_ID": "tenant-a",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "acc_core.cli.main", "run", str(pack.path)],
        env=environment,
        cwd=project,
    )
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with McpStdioTestClient(parameters, error_log=error_log) as client:
            listed = await client.list_tools()
            called = await client.call_tool("records_current", {})
        error_log.seek(0)
        stderr = error_log.read()
    return (
        listed,
        called,
        stderr,
        pack.path.read_bytes(),
        report.ir,
        load_pack_manifest(pack.path).to_dict(),
    )


@pytest.mark.anyio
async def test_stdio_and_http_context_have_identical_business_and_policy_output(
    tmp_path: Path,
) -> None:
    stdio_project = _make_stdio_project(tmp_path / "stdio")
    http_project = _make_gateway_project(tmp_path / "http")
    state = _SourceState()
    with _fake_source(state) as source_url:
        listed_stdio, stdio_success, stderr, pack_bytes, ir, manifest = await _exercise_stdio(
            stdio_project, source_url, scopes="records.read"
        )
        _, stdio_denied, denied_stderr, _, _, _ = await _exercise_stdio(
            stdio_project, source_url, scopes=""
        )

        async with _gateway_harness(http_project, source_url) as harness:
            token = await _login(harness.http, "a@example.test")
            async with McpStreamableHttpTestClient(
                "http://gateway.test/mcp", token, transport=harness.transport
            ) as client:
                listed_http = await client.list_tools()
                http_success = await client.call_tool("records_current", {})

        async with _gateway_harness(
            http_project,
            source_url,
            deployment_scope_ceiling=frozenset(),
        ) as denied_harness:
            denied_token = await _login(denied_harness.http, "a@example.test")
            async with McpStreamableHttpTestClient(
                "http://gateway.test/mcp",
                denied_token,
                transport=denied_harness.transport,
            ) as denied_client:
                http_denied = await denied_client.call_tool("records_current", {})

    assert [tool.name for tool in listed_stdio.tools] == [tool.name for tool in listed_http.tools]
    assert _tool_payload(stdio_success) == _tool_payload(http_success)
    assert stdio_denied.isError is True and http_denied.isError is True
    assert stdio_denied.structuredContent == http_denied.structuredContent
    _secret_scan(
        {
            "stdio_tools": listed_stdio.model_dump(),
            "stdio_success": stdio_success.model_dump(),
            "stdio_denied": stdio_denied.model_dump(),
            "stderr": stderr,
            "denied_stderr": denied_stderr,
            "ir": ir,
            "manifest": manifest,
        },
        [token, denied_token],
    )
    _secret_scan(pack_bytes, [token, denied_token])


@dataclass(frozen=True)
class _OfflineCandidate:
    name: str
    auth: Mapping[str, object] | None
    expected_authorization: str | None
    offline_candidate: Literal[True] = True


@pytest.mark.parametrize(
    "candidate",
    [
        _OfflineCandidate(
            "crm-new-provider-bearer",
            {"kind": "bearer_secret", "token_ref": "CRM_NEW_TOKEN"},
            "Bearer crm-new-private",
        ),
        _OfflineCandidate(
            "warehouse-none",
            {"kind": "none"},
            None,
        ),
        _OfflineCandidate(
            "warehouse-bearer",
            {"kind": "bearer_secret", "token_ref": "WAREHOUSE_TOKEN"},
            "Bearer warehouse-private",
        ),
    ],
    ids=lambda candidate: candidate.name,
)
@pytest.mark.anyio
async def test_representative_provider_fixtures_compile_pack_and_execute_offline(
    tmp_path: Path,
    candidate: _OfflineCandidate,
) -> None:
    project = _make_gateway_project(tmp_path / candidate.name)
    project_path = project / "project.yaml"
    project_document = yaml.safe_load(project_path.read_text(encoding="utf-8"))
    project_document["runtime"] = {"transport": ["stdio"]}
    project_document["provider"]["auth"] = candidate.auth
    _write_yaml(project_path, project_document)

    validation = validate_project(project)
    assert validation.ok, validation.diagnostics
    report = compile_project(project)
    assert report.ok, report.diagnostics
    assert report.ir is not None
    pack = build_pack(project, project / f"{candidate.name}.accpkg", compiled_ir=report.ir)

    observed_authorization: list[str | None] = []

    def handle(request: httpx.Request) -> httpx.Response:
        observed_authorization.append(request.headers.get("authorization"))
        return httpx.Response(
            200,
            json={
                "owner": "offline-principal",
                "tenant_id": "offline-tenant",
                "record": f"visible-only-to-{candidate.name}",
            },
            request=request,
        )

    environment = {
        "OFFLINE_SOURCE_BASE_URL": "https://offline-source.test",
        "CRM_NEW_TOKEN": "crm-new-private",
        "WAREHOUSE_TOKEN": "warehouse-private",
        "ACC_PRINCIPAL_ID": "offline-principal",
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        runtime = GenericRuntime.from_pack(
            pack.path,
            environment=environment,
            granted_scopes={"records.read"},
            tenant_id="offline-tenant",
            client=client,
        )
        result = await runtime.call("records_current", {})
        await runtime.aclose()

    assert result == {
        "owner": "offline-principal",
        "tenant_id": "offline-tenant",
        "record": f"visible-only-to-{candidate.name}",
    }
    assert observed_authorization == [candidate.expected_authorization]
    assert candidate.offline_candidate is True
    assert candidate.name.startswith(("crm-", "warehouse-"))
    _secret_scan(
        {
            "ir": report.ir,
            "manifest": load_pack_manifest(pack.path).to_dict(),
            "result": result,
        },
        [],
        extra_secrets=(
            "crm-new-private",
            "warehouse-private",
        ),
    )
    _secret_scan(
        pack.path.read_bytes(),
        [],
        extra_secrets=(
            "crm-new-private",
            "warehouse-private",
        ),
    )
