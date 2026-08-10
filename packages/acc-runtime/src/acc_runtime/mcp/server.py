"""Model Context Protocol adapter for the generic ACC runtime."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Never, Protocol, cast

from mcp import types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl, JsonValue

from acc_runtime.actions.coordinator import ActionCoordinator, ActionInputInvalidError
from acc_runtime.context import (
    PrincipalContext,
    normalize_security_name,
    sensitive_auth_name_marker,
)
from acc_runtime.credentials import SecretValue
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.mcp.schema_projection import project_mcp_output_schema


class McpRuntime(Protocol):
    """Minimal runtime surface consumed by the protocol adapter."""

    def tools(self) -> list[dict[str, object]]: ...

    def interaction_manifest(self) -> dict[str, JsonValue]: ...

    async def call(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
    ) -> JsonValue: ...


class ContextualMcpRuntime(Protocol):
    """Runtime surface for transports that resolve a Principal per request."""

    def tools(self) -> list[dict[str, object]]: ...

    def interaction_manifest(self) -> dict[str, JsonValue]: ...

    async def call_with_context(
        self,
        capability_id: str,
        arguments: Mapping[str, JsonValue],
        principal_context: PrincipalContext,
    ) -> JsonValue: ...


class PrincipalResolver(Protocol):
    async def resolve(self, access_token: AccessToken | None = None) -> PrincipalContext: ...


@dataclass(frozen=True, slots=True)
class _McpCancelled:
    pass


_MCP_CANCELLED = _McpCancelled()
type _McpCallOutcome = types.CallToolResult | _McpCancelled


class _ActionToolUnavailableError(AccRuntimeError):
    code = "ACC_RUNTIME_ACTION_TOOL_UNAVAILABLE"
    status = 404


_GATEWAY_RESERVED_ARGUMENTS = frozenset(
    {
        "access_token",
        "auth_state_handle",
        "authorization",
        "bearer",
        "cookie",
        "cookies",
        "credential",
        "credential_ref",
        "credentials",
        "effective_scopes",
        "gateway_session_id",
        "id_token",
        "jwt",
        "password",
        "principal",
        "principal_id",
        "refresh_token",
        "scope",
        "scopes",
        "source_scopes",
        "tenant_context",
        "token",
    }
)
_GATEWAY_RESERVED_COMPACT_ARGUMENTS = {
    name.replace("_", ""): name for name in _GATEWAY_RESERVED_ARGUMENTS
}
_INTERACTION_MANIFEST_URI = "acc://interactions/v2/manifest"
_ACTION_MANIFEST_URI = "acc://actions/v2/manifest"
_ACTION_TOOL_NAMES = frozenset(
    {
        "acc_action_approve",
        "acc_action_commit",
        "acc_action_status",
    }
)


class CapabilityMcpServer:
    """Expose ACC capabilities as MCP tools over the official low-level SDK."""

    def __init__(self, runtime: McpRuntime) -> None:
        self.runtime = runtime

    def list_tools(self) -> list[types.Tool]:
        """Translate stable runtime tool metadata to MCP tool definitions."""

        return _translate_tools(self.runtime.tools())

    def list_resources(self) -> list[types.Resource]:
        """Expose the compiler-attested interaction manifest as one read-only resource."""

        return _interaction_resources()

    def read_resource(self, uri: str | AnyUrl) -> list[ReadResourceContents]:
        """Read only the fixed public interaction manifest URI."""

        return _read_interaction_resource(uri, self.runtime.interaction_manifest())

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
    ) -> types.CallToolResult:
        """Execute one tool and return only public, JSON-safe result structures."""

        try:
            result = await self.runtime.call(
                name,
                cast(Mapping[str, JsonValue], dict(arguments or {})),
            )
            payload: dict[str, Any] = {"result": result}
            return self._result(payload, is_error=False)
        except AccRuntimeError as exc:
            return self._result({"error": exc.to_dict()}, is_error=True)
        except Exception:
            return self._result(
                {
                    "error": {
                        "code": "ACC_RUNTIME_INTERNAL",
                        "status": 500,
                        "details": {},
                    }
                },
                is_error=True,
            )

    @staticmethod
    def _result(payload: dict[str, Any], *, is_error: bool) -> types.CallToolResult:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            structuredContent=payload,
            isError=is_error,
        )

    def create_server(self) -> Server[object]:
        """Create the SDK server without touching process standard streams."""

        server: Server[object] = Server("acc-runtime", version="0.1.0")

        @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_tools() -> list[types.Tool]:
            return self.list_tools()

        @server.call_tool(validate_input=True)  # type: ignore[untyped-decorator]
        async def call_tool(
            name: str,
            arguments: dict[str, object] | None,
        ) -> types.CallToolResult:
            return await self.call_tool(name, arguments)

        @server.list_resources()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_resources() -> list[types.Resource]:
            return self.list_resources()

        @server.read_resource()  # type: ignore[no-untyped-call,untyped-decorator]
        async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
            return self.read_resource(uri)

        return server

    async def run_stdio(self) -> None:
        """Serve MCP on stdin/stdout without writing non-protocol output."""

        server = self.create_server()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions(), {}),
            )


class PrincipalCapabilityMcpServer:
    """Expose capabilities using the Principal authenticated by the current request."""

    __slots__ = ("action_coordinator", "resolver", "runtime")

    def __init__(
        self,
        runtime: ContextualMcpRuntime,
        *,
        resolver: PrincipalResolver,
        action_coordinator: ActionCoordinator | None = None,
    ) -> None:
        if action_coordinator is not None and not isinstance(action_coordinator, ActionCoordinator):
            raise TypeError("action_coordinator must be ActionCoordinator")
        self.runtime = runtime
        self.resolver = resolver
        self.action_coordinator = action_coordinator

    def list_tools(self) -> list[types.Tool]:
        """Reuse the stable public tool projection without adding identity inputs."""

        tools = _translate_tools(self.runtime.tools(), reject_reserved_arguments=True)
        if self.action_coordinator is not None:
            action_tools = _action_lifecycle_tools(self.action_coordinator)
            collisions = sorted(
                {tool.name for tool in tools} & {tool.name for tool in action_tools}
            )
            if collisions:
                raise TypeError("Action lifecycle tool name collision")
            tools.extend(action_tools)
        return tools

    def list_resources(self) -> list[types.Resource]:
        """Expose the same deployment manifest without resolving a Principal."""

        resources = _interaction_resources()
        if self.action_coordinator is not None:
            resources.extend(_action_resources())
        return resources

    def read_resource(self, uri: str | AnyUrl) -> list[ReadResourceContents]:
        """Read the public deployment manifest without touching session identity."""

        if str(uri) == _ACTION_MANIFEST_URI and self.action_coordinator is not None:
            return _read_json_resource(self.action_coordinator.public_manifest())
        return _read_interaction_resource(uri, self.runtime.interaction_manifest())

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
        *,
        access_token: AccessToken | None = None,
    ) -> types.CallToolResult:
        """Resolve the current Principal and invoke only the contextual runtime API."""

        adapter = self
        outcome = await adapter._call_tool_outcome(name, arguments, access_token)
        access_token = None
        arguments = None
        name = ""
        del adapter
        del self
        if isinstance(outcome, _McpCancelled):
            _raise_mcp_cancelled()
        return outcome

    async def _call_tool_outcome(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
        access_token: AccessToken | None,
    ) -> _McpCallOutcome:
        try:
            reserved_arguments = _reserved_argument_names(arguments)
            if reserved_arguments:
                return CapabilityMcpServer._result(
                    {
                        "error": {
                            "code": "ACC_GATEWAY_RESERVED_ARGUMENT",
                            "status": 400,
                            "details": {"argument_names": reserved_arguments},
                        }
                    },
                    is_error=True,
                )
            principal = await self.resolver.resolve(access_token)
            prepare_capability_id = _prepare_capability_id(self.action_coordinator, name)
            if name in _ACTION_TOOL_NAMES or prepare_capability_id is not None:
                if self.action_coordinator is None:
                    raise _ActionToolUnavailableError("Action lifecycle tool is unavailable")
                result = await _call_action_lifecycle(
                    self.action_coordinator,
                    name,
                    cast(Mapping[str, JsonValue], dict(arguments or {})),
                    principal,
                    prepare_capability_id=prepare_capability_id,
                )
            else:
                result = await self.runtime.call_with_context(
                    name,
                    cast(Mapping[str, JsonValue], dict(arguments or {})),
                    principal,
                )
            return CapabilityMcpServer._result({"result": result}, is_error=False)
        except asyncio.CancelledError:
            return _MCP_CANCELLED
        except AccRuntimeError as exc:
            return CapabilityMcpServer._result({"error": exc.to_dict()}, is_error=True)
        except Exception:
            return CapabilityMcpServer._result(
                {
                    "error": {
                        "code": "ACC_RUNTIME_INTERNAL",
                        "status": 500,
                        "details": {},
                    }
                },
                is_error=True,
            )

    def create_server(self) -> Server[object]:
        """Create a public SDK server; owner binding remains SDK-managed."""

        server: Server[object] = Server("acc-runtime", version="0.1.0")

        @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_tools() -> list[types.Tool]:
            return self.list_tools()

        @server.call_tool(validate_input=True)  # type: ignore[untyped-decorator]
        async def call_tool(
            name: str,
            arguments: dict[str, object] | None,
        ) -> types.CallToolResult:
            return await self.call_tool(name, arguments, access_token=get_access_token())

        @server.list_resources()  # type: ignore[no-untyped-call,untyped-decorator]
        async def list_resources() -> list[types.Resource]:
            return self.list_resources()

        @server.read_resource()  # type: ignore[no-untyped-call,untyped-decorator]
        async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
            return self.read_resource(uri)

        return server


def _interaction_resources() -> list[types.Resource]:
    return [
        types.Resource(
            name="acc-interaction-manifest-v2",
            title="ACC Interaction Manifest",
            uri=AnyUrl(_INTERACTION_MANIFEST_URI),
            description="Compiler-attested public interaction semantics.",
            mimeType="application/json",
        )
    ]


def _action_resources() -> list[types.Resource]:
    return [
        types.Resource(
            name="acc-action-manifest-v2",
            title="ACC Action Manifest",
            uri=AnyUrl(_ACTION_MANIFEST_URI),
            description="Pack-bound compiler-attested Action lifecycle metadata.",
            mimeType="application/json",
        )
    ]


def _read_json_resource(manifest: Mapping[str, JsonValue]) -> list[ReadResourceContents]:
    text = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return [ReadResourceContents(content=text, mime_type="application/json")]


def _read_interaction_resource(
    uri: str | AnyUrl,
    manifest: Mapping[str, JsonValue],
) -> list[ReadResourceContents]:
    if str(uri) != _INTERACTION_MANIFEST_URI:
        raise ValueError("interaction resource is not available")
    return _read_json_resource(manifest)


def _object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


def _status_schema() -> dict[str, Any]:
    return {
        "type": "string",
        "enum": [
            "approved",
            "committing",
            "expired",
            "failed",
            "outcome_unknown",
            "prepared",
            "succeeded",
        ],
    }


def _closed_result(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return _object_schema(properties, required)


def _action_lifecycle_tools(coordinator: ActionCoordinator) -> list[types.Tool]:
    handle = {"type": "string", "minLength": 43}
    prepare_result = _closed_result(
        {
            "action_handle": handle,
            "approval_required": {"type": "boolean"},
            "capability_id": {"type": "string"},
            "expires_at": {"type": "number"},
            "preview": {},
            "status": _status_schema(),
        },
        [
            "action_handle",
            "approval_required",
            "capability_id",
            "expires_at",
            "preview",
            "status",
        ],
    )
    status_result = _closed_result(
        {
            "capability_id": {"type": "string"},
            "status": _status_schema(),
            "result": {},
        },
        ["capability_id", "result", "status"],
    )
    commit_result = _closed_result(
        {
            "capability_id": {"type": "string"},
            "replayed": {"type": "boolean"},
            "result": {},
            "status": _status_schema(),
        },
        ["capability_id", "replayed", "result", "status"],
    )
    tools: list[tuple[str, str, dict[str, Any], dict[str, Any], types.ToolAnnotations]] = []
    manifest = coordinator.public_manifest()
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list):
        raise TypeError("Action manifest is invalid")
    for item in capabilities:
        if not isinstance(item, dict):
            raise TypeError("Action manifest is invalid")
        capability_id = item.get("capability_id")
        input_schema = item.get("input_schema")
        title = item.get("title")
        if not isinstance(capability_id, str) or not isinstance(input_schema, dict):
            raise TypeError("Action manifest is invalid")
        if _reserved_schema_property_names(input_schema):
            raise TypeError("runtime tool schema exposes a reserved Gateway argument")
        tools.append(
            (
                f"{capability_id}.prepare",
                f"Prepare {title}" if isinstance(title, str) else "Prepare Action",
                cast(dict[str, Any], input_schema),
                prepare_result,
                types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
            )
        )
    tools.extend(
        [
            (
                "acc_action_approve",
                "Approve Action",
                _object_schema(
                    {"action_handle": handle, "approval_handle": handle},
                    ["action_handle", "approval_handle"],
                ),
                status_result,
                types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
            ),
            (
                "acc_action_commit",
                "Commit Action",
                _object_schema({"action_handle": handle}, ["action_handle"]),
                commit_result,
                types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
            ),
            (
                "acc_action_status",
                "Action Status",
                _object_schema({"action_handle": handle}, ["action_handle"]),
                status_result,
                types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
            ),
        ]
    )
    return [
        types.Tool(
            name=name,
            title=title,
            description="Use the trusted ACC prepare, approve, commit and status lifecycle.",
            inputSchema=input_schema,
            outputSchema=project_mcp_output_schema(name, output_schema),
            annotations=annotations,
        )
        for name, title, input_schema, output_schema, annotations in tools
    ]


def _prepare_capability_id(coordinator: ActionCoordinator | None, name: str) -> str | None:
    if coordinator is None or not name.endswith(".prepare"):
        return None
    candidate = name.removesuffix(".prepare")
    capabilities = coordinator.public_manifest().get("capabilities")
    if isinstance(capabilities, list) and any(
        isinstance(item, dict) and item.get("capability_id") == candidate for item in capabilities
    ):
        return candidate
    return None


def _required_string(arguments: Mapping[str, JsonValue], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise ActionInputInvalidError("Action lifecycle arguments are invalid")
    return value


async def _call_action_lifecycle(
    coordinator: ActionCoordinator,
    name: str,
    arguments: Mapping[str, JsonValue],
    principal: PrincipalContext,
    *,
    prepare_capability_id: str | None,
) -> JsonValue:
    if prepare_capability_id is not None:
        prepared = await coordinator.prepare(prepare_capability_id, arguments, principal)
        return {
            "action_handle": prepared.action_handle.get_secret_value(),
            "capability_id": prepared.capability_id,
            "status": prepared.status.value,
            "preview": prepared.preview,
            "approval_required": prepared.approval_required,
            "expires_at": prepared.expires_at,
        }
    action_handle = _required_string(arguments, "action_handle")
    if name == "acc_action_approve":
        if set(arguments) != {"action_handle", "approval_handle"}:
            raise ActionInputInvalidError("Action lifecycle arguments are invalid")
        result = await coordinator.approve(
            action_handle,
            SecretValue(_required_string(arguments, "approval_handle")),
            principal,
        )
        return {
            "capability_id": result.capability_id,
            "status": result.status.value,
            "result": result.result,
        }
    if set(arguments) != {"action_handle"}:
        raise ActionInputInvalidError("Action lifecycle arguments are invalid")
    if name == "acc_action_commit":
        committed = await coordinator.commit(action_handle, principal)
        return {
            "capability_id": committed.capability_id,
            "status": committed.status.value,
            "result": committed.result,
            "replayed": committed.replayed,
        }
    status = await coordinator.status(action_handle, principal)
    return {
        "capability_id": status.capability_id,
        "status": status.status.value,
        "result": status.result,
    }


def _translate_tools(
    definitions: list[dict[str, object]],
    *,
    reject_reserved_arguments: bool = False,
) -> list[types.Tool]:
    tools: list[types.Tool] = []
    for definition in definitions:
        name = definition.get("name")
        input_schema = definition.get("input_schema")
        output_schema = definition.get("output_schema")
        if (
            not isinstance(name, str)
            or not isinstance(input_schema, dict)
            or not isinstance(output_schema, dict)
        ):
            raise TypeError("runtime tool metadata is invalid")
        if reject_reserved_arguments and _reserved_schema_property_names(input_schema):
            raise TypeError("runtime tool schema exposes a reserved Gateway argument")
        title = definition.get("title")
        description = definition.get("description")
        tools.append(
            types.Tool(
                name=name,
                title=title if isinstance(title, str) else None,
                description=description if isinstance(description, str) else None,
                inputSchema=cast(dict[str, Any], input_schema),
                outputSchema=project_mcp_output_schema(name, output_schema),
            )
        )
    return tools


def _reserved_argument_names(arguments: Mapping[str, object] | None) -> list[str]:
    """Find reserved identity/auth names recursively without retaining their values."""

    found: set[str] = set()
    pending: list[object] = [arguments]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, Mapping):
            for key, value in current.items():
                if isinstance(key, str):
                    reserved = _reserved_argument_name(key)
                    if reserved is not None:
                        found.add(reserved)
                pending.append(value)
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return sorted(found)


def _reserved_schema_property_names(schema: Mapping[str, object]) -> frozenset[str]:
    found: set[str] = set()
    pending: list[object] = [schema]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, Mapping):
            properties = current.get("properties")
            if isinstance(properties, Mapping):
                for key in properties:
                    if isinstance(key, str):
                        reserved = _reserved_argument_name(key)
                        if reserved is not None:
                            found.add(reserved)
            if "required" in current:
                required = _schema_string_sequence(current.get("required"))
                if required is None:
                    found.add("invalid_dynamic_name_contract")
                else:
                    for key in required:
                        reserved = _reserved_argument_name(key)
                        if reserved is not None:
                            found.add(reserved)
            if "patternProperties" in current:
                pattern_properties = current.get("patternProperties")
                if not isinstance(pattern_properties, Mapping):
                    found.add("invalid_dynamic_name_contract")
                else:
                    for pattern in pattern_properties:
                        if not isinstance(pattern, str) or not _pattern_is_provably_safe(pattern):
                            found.add("dynamic_reserved_name")
            if "propertyNames" in current:
                property_names = current.get("propertyNames")
                if not isinstance(property_names, Mapping):
                    found.add("invalid_dynamic_name_contract")
                else:
                    if "const" in property_names:
                        const = property_names.get("const")
                        if not isinstance(const, str):
                            found.add("invalid_dynamic_name_contract")
                        else:
                            reserved = _reserved_argument_name(const)
                            if reserved is not None:
                                found.add(reserved)
                    if "enum" in property_names:
                        enum = _schema_string_sequence(property_names.get("enum"))
                        if enum is None:
                            found.add("invalid_dynamic_name_contract")
                        else:
                            for key in enum:
                                reserved = _reserved_argument_name(key)
                                if reserved is not None:
                                    found.add(reserved)
                    if "pattern" in property_names:
                        pattern = property_names.get("pattern")
                        if not isinstance(pattern, str) or not _pattern_is_provably_safe(pattern):
                            found.add("dynamic_reserved_name")
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return frozenset(found)


def _reserved_argument_name(value: str) -> str | None:
    normalized = normalize_security_name(value)
    if normalized in _GATEWAY_RESERVED_ARGUMENTS:
        return normalized
    gateway_reserved = _GATEWAY_RESERVED_COMPACT_ARGUMENTS.get(normalized.replace("_", ""))
    if gateway_reserved is not None:
        return gateway_reserved
    return sensitive_auth_name_marker(value)


def _schema_string_sequence(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return None
    if any(not isinstance(item, str) for item in value):
        return None
    return tuple(value)


_SAFE_EXACT_PROPERTY_PATTERN = re.compile(r"\^([A-Za-z][A-Za-z0-9_-]*)\$")


def _pattern_is_provably_safe(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    exact = _SAFE_EXACT_PROPERTY_PATTERN.fullmatch(pattern)
    return exact is not None and _reserved_argument_name(exact.group(1)) is None


def _raise_mcp_cancelled() -> Never:
    raise asyncio.CancelledError() from None


__all__ = [
    "CapabilityMcpServer",
    "ContextualMcpRuntime",
    "McpRuntime",
    "PrincipalCapabilityMcpServer",
    "PrincipalResolver",
]
