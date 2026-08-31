from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import httpx
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
    OperatorApprovalConfig,
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
        assert gateway_url in {"https://gateway.test", "http://127.0.0.1:8765"}
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
                types.Tool(name="records.prepare", inputSchema={"type": "object"}),
                types.Tool(name="acc_action_commit", inputSchema={"type": "object"}),
                types.Tool(name="acc_action_status", inputSchema={"type": "object"}),
            ]
        )

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> types.CallToolResult:
        arguments = dict(arguments or {})
        self.events.append(f"call:{self.account_alias}:{name}")
        if name == "records.prepare":
            assert arguments == {"record_id": "r-1"}
            return types.CallToolResult(
                content=[],
                isError=False,
                structuredContent={"result": {"action_handle": "h" * 43, "status": "prepared"}},
            )
        if name in {"acc_action_commit", "acc_action_status"}:
            assert arguments == {"action_handle": "h" * 43}
            return types.CallToolResult(
                content=[], isError=False, structuredContent={"result": {"status": "succeeded"}}
            )
        assert arguments == {}
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
    transport: httpx.AsyncBaseTransport | None = None,
    operator_approval: OperatorApprovalConfig | None = None,
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
        transport=transport,
        session_client_factory=session_factory,
        mcp_client_factory=mcp_factory,
        operator_approval=operator_approval,
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


def _operator_profile() -> LiveGatewayProfile:
    base = _profile()
    return base.model_copy(
        update={
            "gateway_url": "http://127.0.0.1:8765",
            "cases": (
                LiveGatewayCase(
                    id="prepare",
                    account="a",
                    capability_id="records.update",
                    action_phase="prepare",
                    tool="records.prepare",
                    arguments={"record_id": "r-1"},
                ),
                LiveGatewayCase(
                    id="operator",
                    kind="operator_approve",
                    account="a",
                    capability_id="records.update",
                    prepare_case_id="prepare",
                ),
                LiveGatewayCase(
                    id="commit",
                    account="a",
                    capability_id="records.update",
                    action_phase="commit",
                    action_handle_from_case="prepare",
                    tool="acc_action_commit",
                    expected_structured_content={"result": {"status": "succeeded"}},
                ),
                LiveGatewayCase(
                    id="status",
                    account="a",
                    capability_id="records.update",
                    action_phase="status",
                    action_handle_from_case="prepare",
                    tool="acc_action_status",
                    expected_structured_content={"result": {"status": "succeeded"}},
                ),
            ),
        }
    )


def test_action_cases_require_an_earlier_matching_prepare() -> None:
    payload = _operator_profile().model_dump(mode="python")
    payload["cases"][1]["prepare_case_id"] = "missing"
    with pytest.raises(ValidationError, match="earlier prepare"):
        LiveGatewayProfile.model_validate(payload)

    payload = _operator_profile().model_dump(mode="python")
    payload["cases"][2]["arguments"] = {"action_handle": "static-forbidden"}
    with pytest.raises(ValidationError, match="cannot be serialized"):
        LiveGatewayProfile.model_validate(payload)


@pytest.mark.asyncio
async def test_live_runner_uses_loopback_operator_without_reporting_handle_or_secret() -> None:
    secret = "operator-secret-" + "x" * 40

    async def operator(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://127.0.0.1:8765/operator/actions/approve"
        assert request.headers["X-ACC-Operator-Authorization"] == f"Bearer {secret}"
        assert request.content == ('{"action_handle":"' + "h" * 43 + '"}').encode()
        return httpx.Response(
            200,
            json={"capability_id": "records.update", "status": "approved"},
        )

    environment = {**_environment(), "ACC_OPERATOR_SECRET": secret}
    runner = _runner(
        _operator_profile(),
        environment,
        transport=httpx.MockTransport(operator),
        operator_approval=OperatorApprovalConfig(
            endpoint_url="http://127.0.0.1:8765/operator/actions/approve",
            secret_ref=SecretRef(env="ACC_OPERATOR_SECRET"),
        ),
    )

    report = await runner.run()

    assert report.verified
    operator_step = next(step for step in report.steps if step.id == "case.operator")
    assert operator_step.evidence == {
        "approval_mechanism": "loopback_operator_http_v1",
        "gateway_origin_sha256": "72b0e86b156f08eb458acaa497126a06506565a00cbc375b40c2c304f4266442",
        "endpoint_path_sha256": "3f0e3365031af3be7e657cb53322b1a819f885340f6c99eae884b5007911a6a2",
        "prepare_case_id": "prepare",
        "operator_case_id": "operator",
        "commit_case_id": "commit",
        "status_case_id": "status",
        "capability_id": "records.update",
        "account": "a",
        "approve_tool_invoked": False,
        "operator_invoked": True,
    }
    rendered = report.model_dump_json()
    assert "h" * 43 not in rendered
    assert secret not in rendered


def test_operator_config_rejects_cross_origin_non_loopback_and_missing_secret() -> None:
    with pytest.raises(ValueError, match="fixed loopback"):
        OperatorApprovalConfig(
            endpoint_url="https://gateway.example/operator/actions/approve",
            secret_ref=SecretRef(env="ACC_OPERATOR_SECRET"),
        )
    with pytest.raises(ValueError, match="provisioned"):
        LiveGatewayRunner(
            _operator_profile(),
            environment=_environment(),
            operator_approval=OperatorApprovalConfig(
                endpoint_url="http://127.0.0.1:8765/operator/actions/approve",
                secret_ref=SecretRef(env="ACC_OPERATOR_SECRET"),
            ),
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
    successful_case = next(step for step in report.steps if step.id == "case.read-a")
    assert successful_case.evidence == {"response_bytes": len(b'{"result":{"owner":"a"}}')}
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
