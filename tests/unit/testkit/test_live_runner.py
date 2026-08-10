from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest
from mcp import types
from pydantic import ValidationError

from acc_runtime.credentials import SecretValue
from acc_runtime.gateway import GatewayRuntimeInfo
from acc_testkit import GatewayLogoutProbe, GatewayRawMcpSessionOwnerProbe
from acc_testkit.live import (
    LiveGatewayAccount,
    LiveGatewayAttestation,
    LiveGatewayCase,
    LiveGatewayIsolationCase,
    LiveGatewayProfile,
    LiveGatewayRunner,
    LiveStepStatus,
    SecretRef,
)


def _profile() -> LiveGatewayProfile:
    return LiveGatewayProfile(
        gateway_url="https://gateway.test",
        attestation=LiveGatewayAttestation(
            pack_sha256="a" * 64,
            project_id="project-a",
            project_version="1.0.0",
            interaction_sha256="c" * 64,
            tool_schema_sha256="b" * 64,
        ),
        accounts=(
            LiveGatewayAccount(
                alias="a",
                identity=SecretRef(env="ACC_TEST_A_IDENTITY"),
                password=SecretRef(env="ACC_TEST_A_PASSWORD"),
            ),
            LiveGatewayAccount(
                alias="b",
                identity=SecretRef(env="ACC_TEST_B_IDENTITY"),
                password=SecretRef(env="ACC_TEST_B_PASSWORD"),
            ),
        ),
        cases=(
            LiveGatewayCase(
                id="read-a",
                account="a",
                tool="records.current",
                arguments={},
                expected_structured_content={"result": {"owner": "a"}},
            ),
            LiveGatewayCase(
                id="source-denied-b",
                account="b",
                tool="records.denied",
                arguments={},
                expect_error=True,
                expected_error_code="SOURCE_DENIED",
                required=False,
            ),
        ),
        isolation=LiveGatewayIsolationCase(
            accounts=("a", "b"),
            tool="records.current",
            arguments={},
            expected_structured_content={
                "a": {"result": {"owner": "a"}},
                "b": {"result": {"owner": "b"}},
            },
        ),
    )


def _environment() -> dict[str, str]:
    return {
        "ACC_TEST_A_IDENTITY": "identity-a-private",
        "ACC_TEST_A_PASSWORD": "password-a-private",
        "ACC_TEST_B_IDENTITY": "identity-b-private",
        "ACC_TEST_B_PASSWORD": "password-b-private",
    }


class _SessionClient:
    def __init__(
        self,
        gateway_url: str,
        *,
        account_alias: str,
        events: list[str],
        **_: object,
    ) -> None:
        assert gateway_url == "https://gateway.test"
        self.account_alias = account_alias
        self.token = SecretValue(f"token-{account_alias}-private")
        self.logged_out = False
        self.events = events

    async def __aenter__(self) -> _SessionClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def login(self, *, identity: SecretValue, password: SecretValue) -> SecretValue:
        assert identity.get_secret_value() == f"identity-{self.account_alias}-private"
        assert password.get_secret_value() == f"password-{self.account_alias}-private"
        return self.token

    async def runtime_info(self) -> GatewayRuntimeInfo:
        return GatewayRuntimeInfo(
            pack_sha256="a" * 64,
            project_id="project-a",
            project_version="1.0.0",
            interaction_sha256="c" * 64,
            tool_schema_sha256="b" * 64,
            transport="streamable_http",
        )

    async def probe_raw_mcp_session_owner_rejection(
        self, foreign_session_id: str
    ) -> GatewayRawMcpSessionOwnerProbe:
        assert self.account_alias == "b"
        assert foreign_session_id == "mcp-session-a"
        self.events.append("owner-probe:b-over-a")
        return GatewayRawMcpSessionOwnerProbe(
            post_status=404,
            get_status=404,
            delete_status=404,
        )

    async def logout(self) -> GatewayLogoutProbe:
        self.logged_out = True
        self.events.append(f"logout:{self.account_alias}")
        return GatewayLogoutProbe(logout_status=204, old_token_status=401)


class _McpClient:
    def __init__(self, account_alias: str, *, events: list[str]) -> None:
        self.account_alias = account_alias
        self.session_id = f"mcp-session-{account_alias}"
        self.events = events
        self.initialized = SimpleNamespace(serverInfo=SimpleNamespace(name="acc-runtime"))

    async def __aenter__(self) -> _McpClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(name="records.current", inputSchema={"type": "object"}),
                types.Tool(name="records.denied", inputSchema={"type": "object"}),
            ]
        )

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> types.CallToolResult:
        assert arguments == {}
        self.events.append(f"call:{self.account_alias}:{name}")
        if name == "records.denied":
            return types.CallToolResult(
                content=[],
                isError=True,
                structuredContent={"error": {"code": "SOURCE_DENIED"}},
            )
        return types.CallToolResult(
            content=[],
            isError=False,
            structuredContent={"result": {"owner": self.account_alias}},
        )


def _runner(
    profile: LiveGatewayProfile,
    environment: Mapping[str, str],
    *,
    events: list[str] | None = None,
) -> LiveGatewayRunner:
    recorded_events = [] if events is None else events

    def session_factory(url: str, **kwargs: object) -> _SessionClient:
        account_alias = kwargs.get("account_alias")
        assert isinstance(account_alias, str)
        return _SessionClient(url, account_alias=account_alias, events=recorded_events)

    def mcp_factory(_session: _SessionClient, account_alias: str) -> _McpClient:
        return _McpClient(account_alias, events=recorded_events)

    return LiveGatewayRunner(
        profile,
        environment=environment,
        session_client_factory=session_factory,
        mcp_client_factory=mcp_factory,
    )


def test_live_profile_accepts_only_environment_secret_references() -> None:
    profile = _profile()

    assert profile.accounts[0].identity.env == "ACC_TEST_A_IDENTITY"
    assert "identity-a-private" not in repr(profile)
    with pytest.raises(ValidationError):
        LiveGatewayAccount.model_validate(
            {
                "alias": "raw",
                "identity": {"env": "ACC_TEST_IDENTITY"},
                "password": {"env": "ACC_TEST_PASSWORD"},
                "raw_password": "forbidden",
            }
        )
    with pytest.raises(ValidationError, match="Gateway base URL"):
        LiveGatewayProfile.model_validate(
            {
                **_profile().model_dump(mode="python"),
                "gateway_url": "https://user:secret@gateway.test",
            }
        )


@pytest.mark.asyncio
async def test_live_runner_reports_attestation_login_list_call_isolation_and_logout() -> None:
    events: list[str] = []
    report = await _runner(_profile(), _environment(), events=events).run()

    assert report.verified is True
    assert report.validation_level == "source_connected_verified"
    assert report.transport == "streamable_http"
    assert report.pack_sha256 == "a" * 64
    assert report.planned == 15
    assert report.executed == 15
    assert report.passed == 15
    assert report.failed == 0
    assert report.skipped == 0
    assert all(step.status is LiveStepStatus.PASSED for step in report.steps)
    assert "session.isolation" not in {step.id for step in report.steps}
    assert {
        "profile.source_result_isolation",
        "protocol.raw_mcp_session_owner_cross_rejection",
        "security.logout_old_token_rejected",
        "security.peer_session_active_after_logout",
    } <= {step.id for step in report.steps}
    owner = next(
        step for step in report.steps if step.id == "protocol.raw_mcp_session_owner_cross_rejection"
    )
    assert owner.evidence == {"POST": 404, "GET": 404, "DELETE": 404}
    assert events.index("logout:a") < len(events) - 1
    assert events[-1] == "logout:b"
    assert "call:b:records.current" in events[events.index("logout:a") + 1 :]
    rendered = report.model_dump_json()
    for secret in _environment().values():
        assert secret not in rendered
    assert "token-a-private" not in rendered


@pytest.mark.asyncio
async def test_required_skips_cannot_produce_a_verified_report() -> None:
    environment = _environment()
    environment.pop("ACC_TEST_B_PASSWORD")

    report = await _runner(_profile(), environment).run()

    assert report.skipped > 0
    assert report.planned == 15
    assert report.executed == report.passed + report.failed
    assert report.planned == report.executed + report.skipped
    assert any(step.required and step.status is LiveStepStatus.SKIPPED for step in report.steps)
    assert report.verified is False
    assert report.validation_level == "unverified"


@pytest.mark.asyncio
async def test_peer_liveness_is_skipped_when_primary_logout_was_not_proven() -> None:
    environment = _environment()
    environment.pop("ACC_TEST_A_PASSWORD")

    report = await _runner(_profile(), environment).run()

    peer = next(
        step for step in report.steps if step.id == "security.peer_session_active_after_logout"
    )
    assert peer.status is LiveStepStatus.SKIPPED


@pytest.mark.asyncio
async def test_attestation_mismatch_is_a_failed_required_step() -> None:
    profile = _profile().model_copy(
        update={
            "attestation": LiveGatewayAttestation(
                pack_sha256="c" * 64,
                project_id="project-a",
                project_version="1.0.0",
                interaction_sha256="d" * 64,
                tool_schema_sha256="b" * 64,
            )
        }
    )

    report = await _runner(profile, _environment()).run()

    attestation = next(step for step in report.steps if step.id == "runtime.attestation")
    assert attestation.status is LiveStepStatus.FAILED
    assert report.verified is False
