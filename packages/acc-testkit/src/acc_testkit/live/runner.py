"""Generic live Gateway orchestration built on the official MCP client adapter."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from mcp import types

from acc_core.quality.output_size import canonical_json_bytes
from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import GatewayRuntimeInfo
from acc_testkit.live.models import (
    LiveGatewayAccount,
    LiveGatewayAttestation,
    LiveGatewayCase,
    LiveGatewayProfile,
    LiveGatewayReport,
    LiveStepResult,
    LiveStepStatus,
    SecretRef,
)
from acc_testkit.mcp_client import (
    GatewayLogoutProbe,
    GatewayRawMcpSessionOwnerProbe,
    GatewaySessionClient,
    McpStreamableHttpTestClient,
)


class _McpClient(Protocol):
    @property
    def initialized(self) -> object: ...
    @property
    def session_id(self) -> str | None: ...
    async def __aenter__(self) -> _McpClient: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    async def list_tools(self) -> types.ListToolsResult: ...
    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> types.CallToolResult: ...


class _SessionClient(Protocol):
    async def __aenter__(self) -> _SessionClient: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    async def login(self, *, identity: SecretValue, password: SecretValue) -> SecretValue: ...
    async def runtime_info(self) -> GatewayRuntimeInfo: ...
    def mcp_client(self) -> McpStreamableHttpTestClient: ...
    async def probe_raw_mcp_session_owner_rejection(
        self, foreign_session_id: str
    ) -> GatewayRawMcpSessionOwnerProbe: ...
    async def logout(self) -> GatewayLogoutProbe: ...


type SessionClientFactory = Callable[..., Any]
type McpClientFactory = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class OperatorApprovalConfig:
    """Runtime-only SecretRef for the fixed loopback Operator endpoint."""

    endpoint_url: str
    secret_ref: SecretRef

    def __post_init__(self) -> None:
        if type(self.secret_ref) is not SecretRef:
            raise TypeError("operator approval secret_ref must be a SecretRef")
        parsed = urlsplit(self.endpoint_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/operator/actions/approve"
            or parsed.query
            or parsed.fragment
            or not _loopback_host(parsed.hostname)
        ):
            raise ValueError("Operator approval endpoint must be the fixed loopback HTTP URL")


class LiveGatewayRunner:
    """Run protocol-generic probes and keep source-specific behavior in profile cases."""

    def __init__(
        self,
        profile: LiveGatewayProfile,
        *,
        environment: Mapping[str, str],
        transport: httpx.AsyncBaseTransport | None = None,
        session_client_factory: SessionClientFactory | None = None,
        mcp_client_factory: McpClientFactory | None = None,
        operator_approval: OperatorApprovalConfig | None = None,
    ) -> None:
        self.profile = profile
        self.transport = transport
        self._credentials = _resolve_credentials(profile.accounts, environment)
        self._session_factory = session_client_factory or self._default_session_factory
        self._mcp_factory = mcp_client_factory or self._default_mcp_factory
        self._operator_approval = operator_approval
        self._operator_secret = _resolve_operator_secret(operator_approval, environment)
        if any(case.kind == "operator_approve" for case in profile.cases):
            if operator_approval is None or self._operator_secret is None:
                raise ValueError("operator approval cases require a provisioned runtime hook")
            if _origin(operator_approval.endpoint_url) != _origin(profile.gateway_url):
                raise ValueError("Operator approval endpoint must use the exact Gateway origin")

    def __repr__(self) -> str:
        return f"LiveGatewayRunner(gateway_url={self.profile.gateway_url!r})"

    def _default_session_factory(self, url: str, **_: object) -> GatewaySessionClient:
        return GatewaySessionClient(url, transport=self.transport)

    @staticmethod
    def _default_mcp_factory(session: _SessionClient, account_alias: str) -> _McpClient:
        del account_alias
        return session.mcp_client()

    async def run(self) -> LiveGatewayReport:
        steps: list[LiveStepResult] = []
        sessions: dict[str, _SessionClient] = {}
        mcps: dict[str, _McpClient] = {}
        listed_tools: dict[str, frozenset[str]] = {}
        action_handles: dict[str, SecretValue] = {}
        pack_sha256: str | None = None
        session_stack = AsyncExitStack()
        mcp_stacks: dict[str, AsyncExitStack] = {}
        try:
            for account in self.profile.accounts:
                credentials = self._credentials[account.alias]
                if credentials is None:
                    steps.append(_skipped(f"account.{account.alias}.login", required=True))
                    continue
                try:
                    session = self._session_factory(
                        self.profile.gateway_url,
                        account_alias=account.alias,
                        transport=self.transport,
                    )
                    session = await session_stack.enter_async_context(session)
                    await session.login(identity=credentials[0], password=credentials[1])
                    sessions[account.alias] = session
                    steps.append(_passed(f"account.{account.alias}.login", required=True))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(f"account.{account.alias}.login", required=True))

            attestation_session = next(iter(sessions.values()), None)
            if attestation_session is None:
                steps.append(_skipped("runtime.attestation", required=True))
            else:
                try:
                    info = await attestation_session.runtime_info()
                    pack_sha256 = info.pack_sha256
                    if not _attestation_matches(info, self.profile.attestation):
                        steps.append(_failed("runtime.attestation", required=True))
                    else:
                        steps.append(_passed("runtime.attestation", required=True))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed("runtime.attestation", required=True))

            for account in self.profile.accounts:
                active_session = sessions.get(account.alias)
                if active_session is None:
                    steps.append(_skipped(f"account.{account.alias}.initialize", required=True))
                    steps.append(_skipped(f"account.{account.alias}.list_tools", required=True))
                    continue
                try:
                    mcp = self._mcp_factory(active_session, account.alias)
                    account_mcp_stack = AsyncExitStack()
                    mcp = await account_mcp_stack.enter_async_context(mcp)
                    _ = mcp.initialized
                    mcps[account.alias] = mcp
                    mcp_stacks[account.alias] = account_mcp_stack
                    steps.append(_passed(f"account.{account.alias}.initialize", required=True))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(f"account.{account.alias}.initialize", required=True))
                    steps.append(_skipped(f"account.{account.alias}.list_tools", required=True))
                    continue
                try:
                    listed = await mcp.list_tools()
                    names = frozenset(tool.name for tool in listed.tools)
                    listed_tools[account.alias] = names
                    required_names = _required_tools(self.profile, account.alias)
                    if required_names <= names:
                        steps.append(_passed(f"account.{account.alias}.list_tools", required=True))
                    else:
                        steps.append(_failed(f"account.{account.alias}.list_tools", required=True))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(f"account.{account.alias}.list_tools", required=True))

            for case in self.profile.cases:
                step_id = f"case.{case.id}"
                if case.kind == "operator_approve":
                    handle = action_handles.get(case.prepare_case_id or "")
                    if handle is None:
                        steps.append(_skipped(step_id, required=case.required))
                        continue
                    try:
                        evidence = await self._operator_approve(case, handle)
                        steps.append(_passed(step_id, required=case.required, evidence=evidence))
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        steps.append(_failed(step_id, required=case.required))
                    continue
                case_mcp = mcps.get(case.account)
                assert case.tool is not None
                if case_mcp is None or case.tool not in listed_tools.get(case.account, frozenset()):
                    steps.append(_skipped(step_id, required=case.required))
                    continue
                try:
                    arguments = dict(case.arguments)
                    if case.action_handle_from_case is not None:
                        handle = action_handles.get(case.action_handle_from_case)
                        if handle is None:
                            steps.append(_skipped(step_id, required=case.required))
                            continue
                        arguments["action_handle"] = handle.get_secret_value()
                    result = await case_mcp.call_tool(case.tool, arguments)
                    if _case_matches(result, case):
                        evidence = (
                            {}
                            if case.expect_error
                            else {
                                "response_bytes": len(
                                    canonical_json_bytes(result.structuredContent)
                                )
                            }
                        )
                        if case.action_phase == "prepare":
                            handle = _prepared_action_handle(result)
                            if handle is None:
                                steps.append(_failed(step_id, required=case.required))
                                continue
                            action_handles[case.id] = handle
                        steps.append(_passed(step_id, required=case.required, evidence=evidence))
                    else:
                        steps.append(_failed(step_id, required=case.required))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(step_id, required=case.required))

            isolation = self.profile.isolation
            isolation_mcps = [mcps.get(alias) for alias in isolation.accounts]
            if any(mcp is None for mcp in isolation_mcps):
                steps.append(
                    _skipped("profile.source_result_isolation", required=isolation.required)
                )
            else:
                try:
                    results = []
                    for alias, isolation_mcp in zip(
                        isolation.accounts, isolation_mcps, strict=True
                    ):
                        assert isolation_mcp is not None
                        result = await isolation_mcp.call_tool(isolation.tool, isolation.arguments)
                        results.append(
                            not result.isError
                            and result.structuredContent
                            == isolation.expected_structured_content[alias]
                        )
                    if all(results):
                        steps.append(
                            _passed(
                                "profile.source_result_isolation",
                                required=isolation.required,
                            )
                        )
                    else:
                        steps.append(
                            _failed(
                                "profile.source_result_isolation",
                                required=isolation.required,
                            )
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(
                        _failed(
                            "profile.source_result_isolation",
                            required=isolation.required,
                        )
                    )

            foreign_alias, probing_alias = isolation.accounts
            foreign_mcp = mcps.get(foreign_alias)
            probing_session = sessions.get(probing_alias)
            foreign_session_id = foreign_mcp.session_id if foreign_mcp is not None else None
            owner_step_id = "protocol.raw_mcp_session_owner_cross_rejection"
            if probing_session is None or foreign_session_id is None:
                steps.append(_skipped(owner_step_id, required=True))
            else:
                try:
                    owner_probe = await probing_session.probe_raw_mcp_session_owner_rejection(
                        foreign_session_id
                    )
                    owner_step = _passed if owner_probe.rejected else _failed
                    steps.append(
                        owner_step(
                            owner_step_id,
                            required=True,
                            evidence=owner_probe.evidence(),
                        )
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(owner_step_id, required=True))

            primary_alias, peer_alias = isolation.accounts
            primary_stack = mcp_stacks.pop(primary_alias, None)
            if primary_stack is not None:
                await primary_stack.aclose()
            mcps.pop(primary_alias, None)
            primary_session = sessions.get(primary_alias)
            primary_logout_verified = False
            if primary_session is None:
                steps.append(_skipped(f"account.{primary_alias}.logout", required=True))
                steps.append(_skipped("security.logout_old_token_rejected", required=True))
            else:
                try:
                    logout_probe = await primary_session.logout()
                    logout_evidence = {
                        "logout_status": logout_probe.logout_status,
                        "old_token_status": logout_probe.old_token_status,
                    }
                    logout_step = _passed if logout_probe.session_revoked else _failed
                    steps.append(
                        logout_step(
                            f"account.{primary_alias}.logout",
                            required=True,
                            evidence=logout_evidence,
                        )
                    )
                    old_token_step = _passed if logout_probe.old_token_rejected else _failed
                    steps.append(
                        old_token_step(
                            "security.logout_old_token_rejected",
                            required=True,
                            evidence={"status": logout_probe.old_token_status},
                        )
                    )
                    primary_logout_verified = (
                        logout_probe.session_revoked and logout_probe.old_token_rejected
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(f"account.{primary_alias}.logout", required=True))
                    steps.append(_skipped("security.logout_old_token_rejected", required=True))

            peer_mcp = mcps.get(peer_alias)
            if (
                not primary_logout_verified
                or peer_mcp is None
                or isolation.tool not in listed_tools.get(peer_alias, frozenset())
            ):
                steps.append(_skipped("security.peer_session_active_after_logout", required=True))
            else:
                try:
                    peer_result = await peer_mcp.call_tool(isolation.tool, isolation.arguments)
                    if (
                        not peer_result.isError
                        and peer_result.structuredContent
                        == isolation.expected_structured_content[peer_alias]
                    ):
                        steps.append(
                            _passed("security.peer_session_active_after_logout", required=True)
                        )
                    else:
                        steps.append(
                            _failed("security.peer_session_active_after_logout", required=True)
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(
                        _failed("security.peer_session_active_after_logout", required=True)
                    )

            for account in self.profile.accounts:
                if account.alias == primary_alias:
                    continue
                account_stack = mcp_stacks.pop(account.alias, None)
                if account_stack is not None:
                    await account_stack.aclose()
                mcps.pop(account.alias, None)
                active_session = sessions.get(account.alias)
                if active_session is None:
                    steps.append(_skipped(f"account.{account.alias}.logout", required=True))
                    continue
                try:
                    logout_probe = await active_session.logout()
                    logout_step = _passed if logout_probe.session_revoked else _failed
                    steps.append(
                        logout_step(
                            f"account.{account.alias}.logout",
                            required=True,
                            evidence={"logout_status": logout_probe.logout_status},
                        )
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    steps.append(_failed(f"account.{account.alias}.logout", required=True))
        finally:
            for account_stack in mcp_stacks.values():
                await account_stack.aclose()
            await session_stack.aclose()
        return LiveGatewayReport.from_steps(steps, pack_sha256=pack_sha256)

    async def _operator_approve(
        self, case: LiveGatewayCase, action_handle: SecretValue
    ) -> dict[str, Any]:
        config = self._operator_approval
        secret = self._operator_secret
        if config is None or secret is None or case.capability_id is None:
            raise ValueError("operator approval hook is not provisioned")
        async with httpx.AsyncClient(
            transport=self.transport,
            follow_redirects=False,
            timeout=5.0,
        ) as client:
            response = await client.post(
                config.endpoint_url,
                headers={"X-ACC-Operator-Authorization": (f"Bearer {secret.get_secret_value()}")},
                json={"action_handle": action_handle.get_secret_value()},
            )
        if response.status_code != 200:
            raise ValueError("operator approval failed")
        payload = response.json()
        if payload != {"capability_id": case.capability_id, "status": "approved"}:
            raise ValueError("operator approval returned an invalid minimized response")
        prepare_id = case.prepare_case_id or ""
        related = [
            item
            for item in self.profile.cases
            if item.action_handle_from_case == prepare_id
            and item.account == case.account
            and item.capability_id == case.capability_id
        ]
        commit = next((item.id for item in related if item.action_phase == "commit"), None)
        status = next((item.id for item in related if item.action_phase == "status"), None)
        if commit is None or status is None:
            raise ValueError("operator approval requires declared commit and status cases")
        parsed = urlsplit(config.endpoint_url)
        return {
            "approval_mechanism": "loopback_operator_http_v1",
            "gateway_origin_sha256": hashlib.sha256(
                _origin(config.endpoint_url).encode()
            ).hexdigest(),
            "endpoint_path_sha256": hashlib.sha256(parsed.path.encode()).hexdigest(),
            "prepare_case_id": prepare_id,
            "operator_case_id": case.id,
            "commit_case_id": commit,
            "status_case_id": status,
            "capability_id": case.capability_id,
            "account": case.account,
            "approve_tool_invoked": False,
            "operator_invoked": True,
        }


def _resolve_credentials(
    accounts: tuple[LiveGatewayAccount, ...], environment: Mapping[str, str]
) -> dict[str, tuple[SecretValue, SecretValue] | None]:
    resolved: dict[str, tuple[SecretValue, SecretValue] | None] = {}
    for account in accounts:
        identity = environment.get(account.identity.env)
        password = environment.get(account.password.env)
        resolved[account.alias] = (
            (SecretValue(identity), SecretValue(password)) if identity and password else None
        )
        identity = None
        password = None
    return resolved


def _resolve_operator_secret(
    config: OperatorApprovalConfig | None, environment: Mapping[str, str]
) -> SecretValue | None:
    if config is None:
        return None
    value = environment.get(config.secret_ref.env)
    if value is None or len(value.encode()) < 32:
        return None
    return SecretValue(value)


def _loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname
    if host is None:
        raise ValueError("URL has no host")
    rendered_host = f"[{host.lower()}]" if ":" in host else host.lower()
    default_port = 80 if parsed.scheme == "http" else 443
    port = parsed.port or default_port
    return f"{parsed.scheme.lower()}://{rendered_host}:{port}"


def _prepared_action_handle(result: types.CallToolResult) -> SecretValue | None:
    payload = result.structuredContent
    if isinstance(payload, Mapping) and set(payload) == {"result"}:
        payload = payload["result"]
    if not isinstance(payload, Mapping):
        return None
    value = payload.get("action_handle")
    return SecretValue(value) if isinstance(value, str) and value else None


def _attestation_matches(actual: GatewayRuntimeInfo, expected: LiveGatewayAttestation) -> bool:
    return (
        actual.pack_sha256 == expected.pack_sha256
        and actual.project_id == expected.project_id
        and actual.project_version == expected.project_version
        and actual.interaction_sha256 == expected.interaction_sha256
        and actual.tool_schema_sha256 == expected.tool_schema_sha256
        and actual.transport == "streamable_http"
    )


def _required_tools(profile: LiveGatewayProfile, alias: str) -> frozenset[str]:
    names = {
        case.tool
        for case in profile.cases
        if case.account == alias and case.kind == "tool_call" and case.tool is not None
    }
    if alias in profile.isolation.accounts:
        names.add(profile.isolation.tool)
    return frozenset(names)


def _case_matches(result: types.CallToolResult, case: LiveGatewayCase) -> bool:
    if result.isError is not case.expect_error:
        return False
    if case.expected_structured_content is not None:
        return result.structuredContent == case.expected_structured_content
    if case.expected_error_code is not None:
        structured = result.structuredContent
        if not isinstance(structured, Mapping):
            return False
        error = structured.get("error")
        return isinstance(error, Mapping) and error.get("code") == case.expected_error_code
    return True


def _passed(
    step_id: str,
    *,
    required: bool,
    evidence: dict[str, Any] | None = None,
) -> LiveStepResult:
    return LiveStepResult(
        id=step_id,
        required=required,
        status=LiveStepStatus.PASSED,
        evidence={} if evidence is None else evidence,
    )


def _failed(
    step_id: str,
    *,
    required: bool,
    evidence: dict[str, Any] | None = None,
) -> LiveStepResult:
    return LiveStepResult(
        id=step_id,
        required=required,
        status=LiveStepStatus.FAILED,
        evidence={} if evidence is None else evidence,
    )


def _skipped(step_id: str, *, required: bool) -> LiveStepResult:
    return LiveStepResult(id=step_id, required=required, status=LiveStepStatus.SKIPPED)


__all__ = [
    "LiveGatewayRunner",
    "McpClientFactory",
    "OperatorApprovalConfig",
    "SessionClientFactory",
]
