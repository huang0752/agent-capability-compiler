"""MCP-native read-only overlay for verified Agent Usage packages."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from mcp import types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl, BaseModel

from acc_core.usage import (
    UsagePackageError,
    UsagePackageTrustStore,
    VerifiedUsagePackage,
    verify_usage_package,
)
from acc_runtime.mcp import PrincipalCapabilityMcpServer, listed_tools_sha256

_MANIFEST_URI = "acc://usage/v2/manifest"
_DOMAIN_URI_PREFIX = "acc://usage/v2/domains/"
_PROMPT_PREFIX = "acc_usage."
_MAX_RESOURCE_BYTES = 256 * 1024
_MAX_PROMPT_BYTES = 32 * 1024


class UsageOverlayError(Exception):
    """Stable, data-free Usage overlay failure."""


class UsageOverlayDigestMismatchError(UsageOverlayError):
    """The Usage package does not describe the delegated Tool surface."""


class UsageOverlayTrustError(UsageOverlayError):
    """The Usage package has no deployment-trusted release receipt."""


class _BaseMcpServer(Protocol):
    def list_tools(self) -> list[types.Tool]: ...

    def list_resources(self) -> list[types.Resource]: ...

    def read_resource(self, uri: str | AnyUrl) -> list[ReadResourceContents]: ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, object] | None
    ) -> types.CallToolResult: ...


def _canonical_json(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _resource_contents(payload: object) -> list[ReadResourceContents]:
    text = _canonical_json(payload)
    if len(text.encode()) > _MAX_RESOURCE_BYTES:
        raise UsageOverlayError("released Usage resource exceeds the public size limit")
    return [ReadResourceContents(content=text, mime_type="application/json")]


def _released_contract_payload(package: VerifiedUsagePackage, domain_id: str) -> dict[str, object]:
    contract = package.contracts[domain_id]
    release = package.releases[domain_id]
    route_ids = set(release.route_ids)
    goal_ids = set(release.business_goal_ids)
    routes = [route for route in contract.tool_routes if route.id in route_ids]
    step_ids = {step.id for route in routes for step in route.steps}
    error_ids = {item for route in routes for item in route.error_branch_ids}
    lifecycle_ids = {
        route.action_lifecycle_id for route in routes if route.action_lifecycle_id is not None
    }

    def dumped(values: Sequence[BaseModel]) -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in values]

    payload: dict[str, object] = {
        "business_goals": dumped([goal for goal in contract.business_goals if goal.id in goal_ids]),
        "conditions": dumped(
            [
                item
                for item in contract.conditions
                if item.route_id in route_ids and (item.step_id is None or item.step_id in step_ids)
            ]
        ),
        "defaults": dumped([item for item in contract.defaults if item.step_id in step_ids]),
        "domain_id": domain_id,
        "error_handling": dumped(
            [item for item in contract.error_handling if item.id in error_ids]
        ),
        "input_bindings": dumped(
            [
                item
                for item in contract.input_bindings
                if item.consumer_step_id in step_ids
                and (item.source_step_id is None or item.source_step_id in step_ids)
            ]
        ),
        "known_limitations": list(release.known_limitations),
        "mcp_release_id": release.mcp_release_id,
        "option_sources": dumped(
            [
                item
                for item in contract.option_sources
                if item.consumer_step_id in step_ids
                and (item.producer_step_id is None or item.producer_step_id in step_ids)
            ]
        ),
        "package_sha256": "sha256:" + package.sha256,
        "prohibited_behaviors": list(contract.prohibited_behaviors),
        "related_data": dumped(
            [
                item
                for item in contract.related_data
                if item.consumer_step_id in step_ids and item.producer_step_id in step_ids
            ]
        ),
        "result_consumption": dumped(
            [item for item in contract.result_consumption if item.step_id in step_ids]
        ),
        "schema_version": "2",
        "tool_routes": dumped(routes),
        "usage_release_id": release.usage_release_id,
        "verification": release.verification.model_dump(mode="json"),
        "action_lifecycles": dumped(
            [item for item in contract.action_lifecycles if item.id in lifecycle_ids]
        ),
    }
    return cast(dict[str, object], _strip_evidence_bindings(payload))


def _strip_evidence_bindings(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_evidence_bindings(item)
            for key, item in value.items()
            if key not in {"evidence_claim_ids", "evidence_claims", "evidence_refs"}
        }
    if isinstance(value, list):
        return [_strip_evidence_bindings(item) for item in value]
    return value


class AgentUsageOverlayMcpServer:
    """Append released Usage Resources and Prompts without changing base Tools."""

    def __init__(
        self,
        base_server: _BaseMcpServer,
        usage_package: str | Path,
        *,
        trust_store: UsagePackageTrustStore | None = None,
    ) -> None:
        if trust_store is None:
            raise UsageOverlayTrustError(
                "Agent Usage overlay requires an explicit deployment trust store"
            )
        try:
            package = verify_usage_package(usage_package, trust_store=trust_store)
        except UsagePackageError as exc:
            raise UsageOverlayTrustError(
                "Agent Usage package receipt is missing, invalid, or untrusted"
            ) from exc
        if not package.trusted or not package.manifest.released_domain_ids:
            raise UsageOverlayTrustError(
                "Agent Usage overlay requires at least one trusted released domain"
            )
        tools = base_server.list_tools()
        if package.manifest.tool_schema_digest != "sha256:" + listed_tools_sha256(tools):
            raise UsageOverlayDigestMismatchError(
                "Agent Usage package Tool digest does not match the delegated MCP server"
            )
        base_uris = {str(item.uri) for item in base_server.list_resources()}
        usage_uris = {
            _MANIFEST_URI,
            *(_DOMAIN_URI_PREFIX + domain_id for domain_id in package.manifest.released_domain_ids),
        }
        if base_uris & usage_uris:
            raise UsageOverlayError("base MCP resource collides with the Usage namespace")

        self._base_server = base_server
        self._package = package
        self._expected_tool_schema_digest = package.manifest.tool_schema_digest
        self._domain_payloads = {
            domain_id: _released_contract_payload(package, domain_id)
            for domain_id in package.manifest.released_domain_ids
        }
        for payload in self._domain_payloads.values():
            _resource_contents(payload)

    def list_tools(self) -> list[types.Tool]:
        """Return the delegated Tool definitions unchanged."""

        return self._assert_integrity()

    def _assert_package_trusted(self) -> None:
        if not self._package.trusted:
            raise UsageOverlayTrustError("Agent Usage package is no longer live and trusted")

    def _assert_integrity(self, tools: list[types.Tool] | None = None) -> list[types.Tool]:
        self._assert_package_trusted()
        current_tools = self._base_server.list_tools() if tools is None else tools
        if self._expected_tool_schema_digest != "sha256:" + listed_tools_sha256(current_tools):
            raise UsageOverlayDigestMismatchError(
                "Agent Usage package Tool digest does not match the delegated MCP server"
            )
        return current_tools

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
        *,
        access_token: AccessToken | None = None,
    ) -> types.CallToolResult:
        """Delegate Tool execution without interpreting Usage guidance."""

        self._assert_integrity()
        if isinstance(self._base_server, PrincipalCapabilityMcpServer):
            return await self._base_server.call_tool(name, arguments, access_token=access_token)
        return await self._base_server.call_tool(name, arguments)

    def list_resources(self) -> list[types.Resource]:
        self._assert_integrity()
        resources = list(self._base_server.list_resources())
        resources.append(
            types.Resource(
                name="acc-agent-usage-manifest-v2",
                title="ACC Agent Usage Manifest",
                uri=AnyUrl(_MANIFEST_URI),
                description="Verified released Agent Usage domains.",
                mimeType="application/json",
            )
        )
        resources.extend(
            types.Resource(
                name=f"acc-agent-usage-{domain_id}-v2",
                title=f"ACC Agent Usage: {domain_id}",
                uri=AnyUrl(_DOMAIN_URI_PREFIX + domain_id),
                description="Platform-neutral released Agent Usage guidance.",
                mimeType="application/json",
            )
            for domain_id in self._package.manifest.released_domain_ids
        )
        return resources

    def read_resource(self, uri: str | AnyUrl) -> list[ReadResourceContents]:
        self._assert_integrity()
        text_uri = str(uri)
        if text_uri == _MANIFEST_URI:
            return _resource_contents(
                {
                    "domain_ids": list(self._package.manifest.released_domain_ids),
                    "format": self._package.manifest.format,
                    "format_version": self._package.manifest.format_version,
                    "mcp_release_id": self._package.manifest.mcp_release_id,
                    "package_sha256": "sha256:" + self._package.sha256,
                    "schema_version": "2",
                    "tool_schema_digest": self._package.manifest.tool_schema_digest,
                }
            )
        if text_uri.startswith(_DOMAIN_URI_PREFIX):
            domain_id = text_uri.removeprefix(_DOMAIN_URI_PREFIX)
            payload = self._domain_payloads.get(domain_id)
            if payload is None:
                raise ValueError("unknown Usage resource")
            return _resource_contents(payload)
        return self._base_server.read_resource(uri)

    def list_prompts(self) -> list[types.Prompt]:
        self._assert_integrity()
        return [
            types.Prompt(
                name=_PROMPT_PREFIX + domain_id,
                title=f"Use released {domain_id} capabilities",
                description="Follow one verified platform-neutral Usage goal.",
                arguments=[
                    types.PromptArgument(
                        name="goal_id",
                        description="Exact released business goal identifier.",
                        required=True,
                    )
                ],
            )
            for domain_id in self._package.manifest.released_domain_ids
        ]

    def get_prompt(self, name: str, arguments: Mapping[str, str] | None) -> types.GetPromptResult:
        self._assert_integrity()
        if (
            not name.startswith(_PROMPT_PREFIX)
            or arguments is None
            or set(arguments) != {"goal_id"}
        ):
            raise ValueError("unknown or invalid prompt request")
        domain_id = name.removeprefix(_PROMPT_PREFIX)
        payload = self._domain_payloads.get(domain_id)
        goal_id = arguments.get("goal_id")
        if payload is None or not isinstance(goal_id, str):
            raise ValueError("unknown or invalid prompt request")
        goals = payload["business_goals"]
        if not isinstance(goals, list) or goal_id not in {
            item.get("id") for item in goals if isinstance(item, dict)
        }:
            raise ValueError("unknown or invalid prompt request")
        raw_routes = payload["tool_routes"]
        if not isinstance(raw_routes, list):
            raise UsageOverlayError("released Usage routes are invalid")
        routes = [
            route
            for route in raw_routes
            if isinstance(route, dict) and route.get("business_goal_id") == goal_id
        ]
        prompt_payload = {
            "business_goal": next(
                item for item in goals if isinstance(item, dict) and item.get("id") == goal_id
            ),
            "domain_id": domain_id,
            "instruction": (
                "Use only the declared tool routes. Preserve preconditions and error branches, "
                "and never infer authorization or bypass Action lifecycle steps."
            ),
            "known_limitations": payload["known_limitations"],
            "prohibited_behaviors": payload["prohibited_behaviors"],
            "tool_routes": routes,
            "usage_release_id": payload["usage_release_id"],
        }
        text = _canonical_json(prompt_payload)
        if len(text.encode()) > _MAX_PROMPT_BYTES:
            raise UsageOverlayError("released Usage prompt exceeds the public size limit")
        return types.GetPromptResult(
            description="Verified Agent Usage guidance.",
            messages=[
                types.PromptMessage(role="user", content=types.TextContent(type="text", text=text))
            ],
        )

    def create_server(self) -> Server[object]:
        server: Server[object] = Server("acc-runtime", version="0.1.0")

        @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_tools() -> list[types.Tool]:
            return self.list_tools()

        @server.call_tool(validate_input=True)  # type: ignore[untyped-decorator]
        async def call_tool(name: str, arguments: dict[str, object] | None) -> types.CallToolResult:
            return await self.call_tool(name, arguments, access_token=get_access_token())

        @server.list_resources()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_resources() -> list[types.Resource]:
            return self.list_resources()

        @server.read_resource()  # type: ignore[no-untyped-call,untyped-decorator]
        async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
            return self.read_resource(uri)

        @server.list_prompts()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_prompts() -> list[types.Prompt]:
            return self.list_prompts()

        @server.get_prompt()  # type: ignore[no-untyped-call,untyped-decorator]
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
            return self.get_prompt(name, arguments)

        return server

    async def run_stdio(self) -> None:
        server = self.create_server()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions(), {}),
            )


__all__ = [
    "AgentUsageOverlayMcpServer",
    "UsageOverlayDigestMismatchError",
    "UsageOverlayError",
    "UsageOverlayTrustError",
]
