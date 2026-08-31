from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryFile
from typing import cast

import httpx
import pytest
from mcp import types
from mcp.client.stdio import StdioServerParameters
from pydantic import AnyUrl, JsonValue, SecretStr

from acc_runtime.context import PrincipalContext
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway.app import create_gateway_app
from acc_runtime.gateway.auth import GatewayPrincipalResolver, GatewayTokenVerifier
from acc_runtime.gateway.models import GatewayRuntimeInfo, GatewaySettings, SessionCreateResponse
from acc_runtime.gateway.sessions import InMemoryGatewaySessionStore
from acc_runtime.mcp import PrincipalCapabilityMcpServer
from acc_testkit import McpStdioTestClient, McpStreamableHttpTestClient

pytestmark = pytest.mark.e2e

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TOOL_NAME = "get_recursive_tree"
RUNTIME_INFO = GatewayRuntimeInfo(
    pack_sha256="a" * 64,
    project_id="schema-projection-test",
    project_version="1.0.0",
    interaction_sha256="c" * 64,
    tool_schema_sha256="b" * 64,
    transport="streamable_http",
)
TREE = {"root": {"value": "root", "next": {"value": "leaf", "next": None}}}
TREE_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "$defs": {
        "node": {
            "type": "object",
            "additionalProperties": False,
            "required": ["value", "next"],
            "properties": {
                "value": {"type": "string"},
                "next": {"anyOf": [{"$ref": "#/$defs/node"}, {"type": "null"}]},
            },
        }
    },
    "required": ["root"],
    "properties": {"root": {"$ref": "#/$defs/node"}},
}

STDIO_SERVER = """
from __future__ import annotations

from collections.abc import Mapping

import anyio
from pydantic import JsonValue

from acc_runtime.mcp import CapabilityMcpServer


class Runtime:
    def interaction_manifest(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "2",
            "digest": "c" * 64,
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }

    def tools(self) -> list[dict[str, object]]:
        return [{
            "name": "get_recursive_tree",
            "title": "Recursive tree",
            "description": "Return a recursive tree.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "output_schema": {
                "type": "object",
                "additionalProperties": False,
                "$defs": {
                    "node": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["value", "next"],
                        "properties": {
                            "value": {"type": "string"},
                            "next": {
                                "anyOf": [
                                    {"$ref": "#/$defs/node"},
                                    {"type": "null"},
                                ]
                            },
                        },
                    }
                },
                "required": ["root"],
                "properties": {"root": {"$ref": "#/$defs/node"}},
            },
        }]

    async def call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue:
        assert capability_id == "get_recursive_tree"
        assert arguments == {}
        return {
            "root": {
                "value": "root",
                "next": {"value": "leaf", "next": None},
            }
        }


anyio.run(CapabilityMcpServer(Runtime()).run_stdio)
"""


class _ContextRuntime:
    def interaction_manifest(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "2",
            "digest": "c" * 64,
            "inventory": {"status": "not_declared"},
            "contracts": {},
            "dependencies": [],
        }

    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": TOOL_NAME,
                "title": "Recursive tree",
                "description": "Return a recursive tree.",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
                "output_schema": TREE_OUTPUT_SCHEMA,
            }
        ]

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue:
        assert capability_id == TOOL_NAME
        assert arguments == {}
        assert principal_context.target_system_id == "schema-projection-test"
        return cast(JsonValue, TREE)


class _SessionService:
    def __init__(self, store: InMemoryGatewaySessionStore) -> None:
        self.store = store

    async def startup(self) -> None:
        return

    async def create_session(self, *, identity: str, password: str) -> SessionCreateResponse:
        assert identity == "schema-user"
        assert password == "schema-password"
        context = PrincipalContext(
            principal_id="schema-principal",
            gateway_session_id="schema-gateway-session",
            target_system_id="schema-projection-test",
            source_scopes=set(),
            deployment_scope_ceiling=set(),
            tenant_context=None,
            auth_state_handle="schema-auth-state",
        )
        creation = await self.store.create(
            session_id="schema-gateway-session",
            principal_context=context,
        )
        return SessionCreateResponse(
            gateway_token=SecretStr(creation.token.get_secret_value()),
            expires_in_seconds=60,
        )

    async def delete_current(self, token: str) -> None:
        await self.store.revoke_token(SecretValue(token))

    async def aclose(self) -> None:
        await self.store.close()


async def _exercise_stdio(
    tmp_path: Path,
) -> tuple[types.Tool, types.CallToolResult, types.ReadResourceResult, str]:
    server_path = tmp_path / "recursive_stdio_server.py"
    server_path.write_text(STDIO_SERVER, encoding="utf-8")
    environment = os.environ.copy()
    python_paths = [
        REPOSITORY_ROOT / "packages" / "acc-core" / "src",
        REPOSITORY_ROOT / "packages" / "acc-runtime" / "src",
    ]
    environment["PYTHONPATH"] = os.pathsep.join(
        [*(str(path) for path in python_paths), environment.get("PYTHONPATH", "")]
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
        env=environment,
        cwd=tmp_path,
    )
    with TemporaryFile(mode="w+", encoding="utf-8") as error_log:
        async with McpStdioTestClient(parameters, error_log=error_log) as client:
            listed = await client.list_tools()
            called = await client.call_tool(TOOL_NAME, {})
            resources = await client._active_session().list_resources()
            assert str(resources.resources[0].uri) == "acc://interactions/v2/manifest"
            manifest = await client._active_session().read_resource(
                AnyUrl("acc://interactions/v2/manifest")
            )
        error_log.seek(0)
        stderr = error_log.read()
    return listed.tools[0], called, manifest, stderr


async def _exercise_streamable_http() -> tuple[
    types.Tool, types.CallToolResult, types.ReadResourceResult
]:
    store = InMemoryGatewaySessionStore(max_sessions=2, ttl_seconds=60)
    service = _SessionService(store)
    settings = GatewaySettings(
        allowed_hosts=("gateway.test",),
        allowed_origins=("http://gateway.test",),
        session_ttl_seconds=60,
        max_sessions=2,
    )
    resolver = GatewayPrincipalResolver(store=store, project_id="schema-projection-test")
    app = create_gateway_app(
        settings=settings,
        service=service,
        token_verifier=GatewayTokenVerifier(
            store=store,
            project_id="schema-projection-test",
        ),
        mcp_server=PrincipalCapabilityMcpServer(_ContextRuntime(), resolver=resolver),
        runtime_info=RUNTIME_INFO,
    )
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport,
            base_url="http://gateway.test",
            headers={"origin": "http://gateway.test"},
        ) as http,
    ):
        login = await http.post(
            "/runtime/sessions",
            json={"identity": "schema-user", "password": "schema-password"},
        )
        assert login.status_code == 201
        token = SecretValue(login.json()["token"])
        async with McpStreamableHttpTestClient(
            "http://gateway.test/mcp",
            token,
            transport=transport,
        ) as client:
            listed = await client.list_tools()
            called = await client.call_tool(TOOL_NAME, {})
            resources = await client._active_session().list_resources()
            assert str(resources.resources[0].uri) == "acc://interactions/v2/manifest"
            manifest = await client._active_session().read_resource(
                AnyUrl("acc://interactions/v2/manifest")
            )
    return listed.tools[0], called, manifest


@pytest.mark.anyio
async def test_official_sdk_validates_recursive_schema_resources_over_both_transports(
    tmp_path: Path,
) -> None:
    stdio_tool, stdio_result, stdio_manifest, stderr = await _exercise_stdio(tmp_path)
    http_tool, http_result, http_manifest = await _exercise_streamable_http()

    assert stderr == ""
    assert stdio_tool.outputSchema == http_tool.outputSchema
    assert isinstance(stdio_tool.outputSchema, dict)
    properties = stdio_tool.outputSchema.get("properties")
    assert isinstance(properties, dict)
    result_schema = properties.get("result")
    assert isinstance(result_schema, dict)
    assert result_schema["$id"].startswith("urn:acc:mcp-output:")
    assert stdio_result.isError is False and http_result.isError is False
    assert stdio_result.structuredContent == http_result.structuredContent == {"result": TREE}
    stdio_text = stdio_manifest.contents[0]
    http_text = http_manifest.contents[0]
    assert isinstance(stdio_text, types.TextResourceContents)
    assert isinstance(http_text, types.TextResourceContents)
    assert json.loads(stdio_text.text) == json.loads(http_text.text)
