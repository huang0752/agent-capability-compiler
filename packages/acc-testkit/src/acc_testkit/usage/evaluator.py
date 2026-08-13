"""Deterministic headless, real-MCP, and live release verification for Agent Usage."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import httpx
from pydantic import JsonValue

from acc_core.usage import (
    DomainUsageContract,
    UsageActionLifecycle,
    UsageDomainDecision,
    UsageErrorBranch,
    UsageScenario,
    UsageStepBinding,
    UsageToolRoute,
    UsageToolStep,
    VerifiedUsageReleaseBundle,
    finalize_verified_usage_release,
    ingest_source_usage_evidence,
    ingest_usage_contract_analysis,
    ingest_user_acceptance,
)
from acc_core.usage.acceptance import (
    McpReleaseAcceptanceVerification,
    listed_tool_snapshot_sha256,
)
from acc_core.usage.analyze import analyze_usage_contract
from acc_core.usage.project import UsageProjectReport
from acc_core.usage.verification import (
    UsageAxisReport,
    UsageVerificationTraceEntry,
)
from acc_runtime.credentials import SecretValue
from acc_testkit.interactions import evaluate_condition
from acc_testkit.mcp_client.stdio import McpStdioTestClient
from acc_testkit.mcp_client.stdio import _inspect_live_transport as _stdio_live
from acc_testkit.mcp_client.streamable_http import (
    McpStreamableHttpTestClient,
)
from acc_testkit.mcp_client.streamable_http import (
    _inspect_live_transport as _http_live,
)
from acc_testkit.usage.models import (
    RealMcpUsageScenarioResult,
    UsageAttestation,
    UsageOutcomeKind,
    UsageScenarioResult,
    UsageToolOutcome,
    UsageTraceEntry,
    usage_contract_digest,
    usage_scenario_digest,
)

_MISSING = object()


class UsageEvaluationError(ValueError):
    """Stable failure for a malformed headless evaluation request."""


class UsageCallerError(RuntimeError):
    """Data-free stable error classification emitted by a fake Tool caller."""

    _KINDS = frozenset(
        {
            "unauthorized",
            "forbidden",
            "not_found",
            "timeout",
            "conflict",
            "outcome_unknown",
            "source_error",
        }
    )

    def __init__(self, kind: str) -> None:
        if kind not in self._KINDS:
            raise ValueError("unsupported Usage caller error classification")
        self.kind = cast(UsageOutcomeKind, kind)
        super().__init__(kind)

    @classmethod
    def from_http_status(cls, status: int) -> UsageCallerError:
        classifications = {401: "unauthorized", 403: "forbidden", 404: "not_found"}
        if status not in classifications:
            raise ValueError("only stable 401, 403, and 404 classifications are supported")
        return cls(classifications[status])


class UsageToolCaller(Protocol):
    """Fake-only caller boundary; production mutation transports are out of scope."""

    async def call(
        self, tool_name: str, arguments: Mapping[str, JsonValue]
    ) -> UsageToolOutcome: ...


class TrustedOperatorApproval:
    """Non-serializable success token returned only by an injected operator hook."""

    __slots__ = ("approval_mechanism", "capability_id", "endpoint_path_sha256", "origin_sha256")

    def __init__(
        self,
        *,
        capability_id: str,
        approval_mechanism: str,
        origin_sha256: str,
        endpoint_path_sha256: str,
    ) -> None:
        if approval_mechanism != "loopback_operator_http_v1":
            raise ValueError("unsupported operator approval mechanism")
        self.capability_id = capability_id
        self.approval_mechanism = approval_mechanism
        self.origin_sha256 = origin_sha256
        self.endpoint_path_sha256 = endpoint_path_sha256

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("trusted operator approval tokens are not serializable")


class TrustedOperatorApprovalHook(Protocol):
    async def approve(
        self, *, capability_id: str, action_handle: SecretValue
    ) -> TrustedOperatorApproval: ...


class LoopbackOperatorApprovalHook:
    """Built-in fixed-path HTTP hook; credentials remain runtime-only."""

    __slots__ = ("_endpoint_url", "_secret", "_transport")

    def __init__(
        self,
        *,
        gateway_url: str,
        endpoint_url: str,
        secret: SecretValue,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        gateway_origin = _operator_origin(gateway_url)
        endpoint = urlsplit(endpoint_url)
        if (
            endpoint.path != "/operator/actions/approve"
            or endpoint.query
            or endpoint.fragment
            or endpoint.username is not None
            or endpoint.password is not None
            or not _operator_loopback(endpoint.hostname)
            or _operator_origin(endpoint_url) != gateway_origin
        ):
            raise ValueError("operator hook requires the fixed same-origin loopback endpoint")
        if len(secret.get_secret_value().encode()) < 32:
            raise ValueError("operator hook secret must contain at least 32 bytes")
        self._endpoint_url = endpoint_url
        self._secret = secret
        self._transport = transport

    async def approve(
        self, *, capability_id: str, action_handle: SecretValue
    ) -> TrustedOperatorApproval:
        async with httpx.AsyncClient(
            transport=self._transport, follow_redirects=False, timeout=5.0
        ) as client:
            response = await client.post(
                self._endpoint_url,
                headers={
                    "X-ACC-Operator-Authorization": (f"Bearer {self._secret.get_secret_value()}")
                },
                json={"action_handle": action_handle.get_secret_value()},
            )
        if response.status_code != 200:
            raise UsageEvaluationError("operator approval failed")
        payload = response.json()
        if payload != {"capability_id": capability_id, "status": "approved"}:
            raise UsageEvaluationError("operator approval returned an invalid minimized response")
        endpoint = urlsplit(self._endpoint_url)
        return TrustedOperatorApproval(
            capability_id=capability_id,
            approval_mechanism="loopback_operator_http_v1",
            origin_sha256=hashlib.sha256(_operator_origin(self._endpoint_url).encode()).hexdigest(),
            endpoint_path_sha256=hashlib.sha256(endpoint.path.encode()).hexdigest(),
        )


class RealMcpUsageClient(UsageToolCaller, Protocol):
    async def list_tools(self) -> list[dict[str, object]]: ...


class RealMcpUsageRunner:
    async def run(
        self,
        *,
        contract: DomainUsageContract,
        scenario: UsageScenario,
        client: RealMcpUsageClient | McpStdioTestClient | McpStreamableHttpTestClient,
        attestation: UsageAttestation,
        public_inputs: Mapping[str, JsonValue] | None = None,
        trusted_context: Mapping[str, JsonValue] | None = None,
        operator_approval_hook: TrustedOperatorApprovalHook | None = None,
    ) -> RealMcpUsageScenarioResult:
        if attestation.execution_mode != "real_mcp":
            raise ValueError("real MCP runner requires a real_mcp attestation")
        transport_identity = _live_transport_identity(client)
        tools: list[dict[str, object]]
        if type(client) in {McpStdioTestClient, McpStreamableHttpTestClient}:
            official_client = cast(_OfficialMcpClient, client)
            listed = await official_client.list_tools()
            tools = [
                {
                    "name": tool.name,
                    "inputSchema": dict(tool.inputSchema),
                    "outputSchema": dict(tool.outputSchema or {}),
                }
                for tool in listed.tools
            ]
            caller: UsageToolCaller = _OfficialMcpCaller(official_client)
        else:
            tools = await cast(RealMcpUsageClient, client).list_tools()
            caller = cast(RealMcpUsageClient, client)
        runtime_digest = "sha256:" + listed_tool_snapshot_sha256({"tools": tools})
        if runtime_digest != contract.tool_schema_digest:
            raise ValueError("runtime Tool digest does not match the exact contract")
        result = await HeadlessUsageEvaluator().run(
            contract=contract,
            scenario=scenario,
            caller=caller,
            attestation=attestation,
            public_inputs=public_inputs,
            trusted_context=trusted_context,
            operator_approval_hook=operator_approval_hook,
        )
        observed = RealMcpUsageScenarioResult(
            result=result, runtime_tool_schema_digest=runtime_digest
        )
        if (
            transport_identity is not None
            and _live_transport_identity(client) == transport_identity
        ):
            object.__setattr__(observed, "_runner_derived", True)
            object.__setattr__(
                observed, "_verification_fingerprint", observed._public_fingerprint()
            )
            object.__setattr__(observed, "_origin_identity", id(observed))
        return observed


type _OfficialMcpClient = McpStdioTestClient | McpStreamableHttpTestClient


class _OfficialMcpCaller:
    def __init__(self, client: _OfficialMcpClient) -> None:
        self._client = client

    async def call(self, tool_name: str, arguments: Mapping[str, JsonValue]) -> UsageToolOutcome:
        called = await self._client.call_tool(tool_name, arguments)
        if called.isError:
            return UsageToolOutcome(outcome="outcome_unknown")
        payload: object = called.structuredContent
        if isinstance(payload, Mapping) and set(payload) == {"result"}:
            payload = payload["result"]
        return UsageToolOutcome.success(cast(JsonValue, payload))


def _live_transport_identity(client: object) -> tuple[int, int, int, str] | None:
    if type(client) is McpStdioTestClient:
        return _stdio_live(client)
    if type(client) is McpStreamableHttpTestClient:
        return _http_live(client)
    return None


@dataclass(frozen=True, slots=True)
class UsageScenarioVerification:
    """Transient callers and inputs for one exact declared scenario."""

    headless_caller: UsageToolCaller
    real_mcp_client: RealMcpUsageClient | _OfficialMcpClient
    public_inputs: Mapping[str, JsonValue] = field(default_factory=dict)
    trusted_context: Mapping[str, JsonValue] = field(default_factory=dict)
    real_mcp_operator_hook: TrustedOperatorApprovalHook | None = None


class AgentUsageReleaseVerifier:
    """Run every required Usage release gate in one live process."""

    async def verify(
        self,
        *,
        project: UsageProjectReport,
        accepted_mcp_release: McpReleaseAcceptanceVerification,
        domain_id: str,
        executions: Mapping[str, UsageScenarioVerification],
    ) -> VerifiedUsageReleaseBundle:
        if not project.ok or not accepted_mcp_release.ok or not accepted_mcp_release.trusted:
            raise UsageEvaluationError("Usage release verification requires valid typed inputs")
        if domain_id not in accepted_mcp_release.accepted_domain_ids:
            raise UsageEvaluationError("Usage domain is not in the accepted MCP release")
        contract = project.domain_contracts.get(domain_id)
        if contract is None:
            raise UsageEvaluationError("Usage domain contract is missing")
        required_ids = tuple(contract.required_scenario_ids)
        if tuple(sorted(executions)) != required_ids:
            raise UsageEvaluationError("scenario executions must match the exact denominator")
        scenarios = tuple(project.scenarios[item] for item in required_ids)
        decisions = [
            item
            for item in project.decisions.values()
            if item.domain_id == domain_id and item.disposition == "accepted"
        ]
        if not decisions:
            raise UsageEvaluationError("an accepted Usage domain decision is required")
        decision = max(decisions, key=lambda item: item.revision)
        analysis = analyze_usage_contract(project, accepted_mcp_release, domain_id=domain_id)
        if not analysis.ok:
            codes = ",".join(sorted({item.code for item in analysis.diagnostics}))
            raise UsageEvaluationError(f"Usage contract analysis did not pass: {codes}")

        headless_results: list[UsageScenarioResult] = []
        real_results: list[RealMcpUsageScenarioResult] = []
        headless_attestations: dict[str, UsageAttestation] = {}
        real_attestations: dict[str, UsageAttestation] = {}
        for scenario in scenarios:
            execution = executions[scenario.scenario_id]
            route = _select_route(contract, scenario)
            lifecycle = _lifecycle(contract, route)
            if (
                lifecycle is not None
                and lifecycle.approval != "never"
                and execution.real_mcp_operator_hook is None
            ):
                raise UsageEvaluationError(
                    "real MCP Action approval requires an explicit trusted operator hook"
                )
            common = {
                "pack_digest": contract.pack_digest,
                "ir_digest": contract.ir_digest,
                "tool_schema_digest": contract.tool_schema_digest,
                "test_report_digest": contract.test_report_digest,
                "source_snapshot_digest": contract.source_snapshot_digest,
                "contract_digest": usage_contract_digest(contract),
                "scenario_digest": usage_scenario_digest(scenario),
            }
            headless_attestation = UsageAttestation(**common, execution_mode="fake")
            real_attestation = UsageAttestation(**common, execution_mode="real_mcp")
            headless_result = await HeadlessUsageEvaluator().run(
                contract=contract,
                scenario=scenario,
                caller=execution.headless_caller,
                attestation=headless_attestation,
                public_inputs=execution.public_inputs,
                trusted_context=execution.trusted_context,
            )
            if headless_result.status != "passed":
                raise UsageEvaluationError("a required headless Usage scenario did not pass")
            real_result = await RealMcpUsageRunner().run(
                contract=contract,
                scenario=scenario,
                client=execution.real_mcp_client,
                attestation=real_attestation,
                public_inputs=execution.public_inputs,
                trusted_context=execution.trusted_context,
                operator_approval_hook=execution.real_mcp_operator_hook,
            )
            if real_result.result.status != "passed":
                raise UsageEvaluationError("a required real MCP Usage scenario did not pass")
            headless_results.append(headless_result)
            real_results.append(real_result)
            headless_attestations[scenario.scenario_id] = headless_attestation
            real_attestations[scenario.scenario_id] = real_attestation

        reports = (
            ingest_source_usage_evidence(
                project=project,
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ),
            ingest_usage_contract_analysis(
                analysis=analysis,
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ),
            ingest_user_acceptance(
                contract=contract,
                scenarios=scenarios,
                decision=decision,
            ),
        )
        return finalize_verified_usage_release(
            project=project,
            accepted_mcp_release=accepted_mcp_release,
            analysis=analysis,
            domain_id=domain_id,
            contract=contract,
            scenarios=scenarios,
            decision=decision,
            reports=reports,
            headless_results=headless_results,
            real_mcp_results=real_results,
            headless_attestations=headless_attestations,
            real_mcp_attestations=real_attestations,
        )


class HeadlessUsageEvaluator:
    """Execute one declared route with no identity data or real mutation transport."""

    async def run(
        self,
        *,
        contract: DomainUsageContract,
        scenario: UsageScenario,
        caller: UsageToolCaller,
        attestation: UsageAttestation,
        public_inputs: Mapping[str, JsonValue] | None = None,
        trusted_context: Mapping[str, JsonValue] | None = None,
        requested_behavior: str | None = None,
        operator_approval_hook: TrustedOperatorApprovalHook | None = None,
    ) -> UsageScenarioResult:
        if not _attestation_matches(contract, scenario, attestation):
            return _result(
                contract,
                scenario,
                scenario.route_id,
                status="stale",
                outcome="stale",
            )
        route = _select_route(contract, scenario)
        if requested_behavior is not None and requested_behavior in contract.prohibited_behaviors:
            return _result(contract, scenario, route, status="prohibited", outcome="prohibited")
        if scenario.kind == "prohibited_behavior":
            return _result(contract, scenario, route, status="prohibited", outcome="prohibited")

        inputs = copy.deepcopy(dict(public_inputs or {}))
        trusted = copy.deepcopy(dict(trusted_context or {}))
        lifecycle = _lifecycle(contract, route)
        trusted_bindings_allowed = _trusted_bindings_are_allowed(contract)
        approval_provisioned = (
            operator_approval_hook is not None
            or _trusted_approval_is_provisioned(contract, lifecycle, inputs, trusted)
        )
        if not trusted_bindings_allowed or not approval_provisioned:
            return _result(
                contract,
                scenario,
                route,
                status="failed",
                outcome="not_provisioned",
            )
        undeclared = sorted(set(inputs) - set(scenario.public_input_ids))
        if undeclared:
            raise UsageEvaluationError("public inputs contain undeclared identifiers")
        state: dict[str, JsonValue] = copy.deepcopy(inputs)
        step_results: dict[str, JsonValue] = {}
        trace: list[UsageTraceEntry] = []
        final_outcome: UsageOutcomeKind = "success"
        status_outcome: UsageOutcomeKind | None = None

        for step in _ordered_steps(route, route.result_step_id):
            if not _should_execute_step(step, lifecycle, state):
                continue
            if (
                step.action_phase == "approve"
                and lifecycle is not None
                and operator_approval_hook is None
                and not _approval_handle_is_available(contract, lifecycle, trusted)
            ):
                return _result(
                    contract,
                    scenario,
                    route,
                    status="failed",
                    outcome="not_provisioned",
                    trace=trace,
                )
            arguments = _arguments(contract, step, inputs, trusted, step_results)
            outcome = await _call_step(
                caller=caller,
                contract=contract,
                scenario=scenario,
                route=route,
                step=step,
                arguments=arguments,
                trace=trace,
                operator_approval_hook=operator_approval_hook,
                action_handle=(
                    _action_handle_from_prepare(step_results, lifecycle)
                    if step.action_phase == "approve" and lifecycle is not None
                    else None
                ),
            )
            if outcome.outcome == "success":
                step_results[step.id] = copy.deepcopy(outcome.result)
                state[step.id] = copy.deepcopy(outcome.result)
                if step.action_phase == "status":
                    status_outcome = "success"
                if step.id == route.result_step_id:
                    break
                continue
            if outcome.outcome == "empty":
                final_outcome = "empty"
                break
            if step.action_phase == "status":
                status_outcome = outcome.outcome
                if final_outcome == "success":
                    final_outcome = outcome.outcome
                break
            if (
                outcome.outcome == "outcome_unknown"
                and lifecycle is not None
                and step.action_phase == "commit"
            ):
                final_outcome = "outcome_unknown"
                status_step = next(
                    (item for item in route.steps if item.id == lifecycle.status_step_id),
                    None,
                )
                if status_step is None:
                    raise UsageEvaluationError("action status step is not declared")
                status_arguments = _arguments(
                    contract,
                    status_step,
                    inputs,
                    trusted,
                    step_results,
                )
                status_result = await _call_step(
                    caller=caller,
                    contract=contract,
                    scenario=scenario,
                    route=route,
                    step=status_step,
                    arguments=status_arguments,
                    trace=trace,
                )
                status_outcome = status_result.outcome
                break
            final_outcome = outcome.outcome
            break

        if final_outcome == "outcome_unknown":
            status = "outcome_unknown"
        else:
            status = "passed" if final_outcome in scenario.expected_outcomes else "failed"
        return _result(
            contract,
            scenario,
            route,
            status=status,
            outcome=final_outcome,
            status_outcome=status_outcome,
            trace=trace,
        )


async def _call_step(
    *,
    caller: UsageToolCaller,
    contract: DomainUsageContract,
    scenario: UsageScenario,
    route: UsageToolRoute,
    step: UsageToolStep,
    arguments: dict[str, JsonValue],
    trace: list[UsageTraceEntry],
    operator_approval_hook: TrustedOperatorApprovalHook | None = None,
    action_handle: SecretValue | None = None,
) -> UsageToolOutcome:
    for attempt in (1, 2):
        trace_arguments: JsonValue | Mapping[str, JsonValue] = _secret_free_trace_arguments(
            step, arguments
        )
        trace_tool_name = step.tool_name
        try:
            if step.action_phase == "approve" and operator_approval_hook is not None:
                if action_handle is None:
                    raise UsageEvaluationError(
                        "operator approval requires a prepared action handle"
                    )
                approved = await operator_approval_hook.approve(
                    capability_id=step.capability_id,
                    action_handle=action_handle,
                )
                if (
                    type(approved) is not TrustedOperatorApproval
                    or approved.capability_id != step.capability_id
                ):
                    raise UsageEvaluationError("operator hook returned an invalid trusted result")
                outcome = UsageToolOutcome.success(
                    {"capability_id": approved.capability_id, "status": "approved"}
                )
                trace_arguments = {
                    "approval_mechanism": approved.approval_mechanism,
                    "capability_id": approved.capability_id,
                    "endpoint_path_sha256": approved.endpoint_path_sha256,
                    "origin_sha256": approved.origin_sha256,
                }
                trace_tool_name = "operator:loopback_operator_http_v1"
            else:
                outcome = await caller.call(step.tool_name, copy.deepcopy(arguments))
                trace_arguments = _secret_free_trace_arguments(step, arguments)
        except asyncio.CancelledError:
            raise
        except UsageCallerError as exc:
            outcome = UsageToolOutcome(outcome=exc.kind)
        except Exception:
            outcome = UsageToolOutcome(outcome="source_error")
        trace.append(
            UsageTraceEntry(
                scenario_id=scenario.scenario_id,
                route_id=route.id,
                step_id=step.id,
                tool_name=trace_tool_name,
                phase=step.action_phase,
                attempt=attempt,
                outcome=outcome.outcome,
                arguments_sha256=_json_digest(trace_arguments),
                result_sha256=(
                    _json_digest(outcome.result)
                    if outcome.outcome == "success" and step.action_phase != "prepare"
                    else None
                ),
            )
        )
        if attempt == 1 and _retry_allowed(contract, route, step, outcome.outcome):
            continue
        return outcome
    raise AssertionError("bounded retry loop must return")


def _action_handle_from_prepare(
    step_results: Mapping[str, JsonValue], lifecycle: UsageActionLifecycle
) -> SecretValue | None:
    prepared = step_results.get(lifecycle.prepare_step_id)
    value = _read_pointer(prepared, "/action_handle") if prepared is not None else _MISSING
    return SecretValue(value) if isinstance(value, str) and value else None


def _secret_free_trace_arguments(
    step: UsageToolStep, arguments: Mapping[str, JsonValue]
) -> Mapping[str, JsonValue]:
    if step.action_phase not in {"approve", "commit", "status"}:
        return arguments
    redacted = copy.deepcopy(dict(arguments))
    for name in ("action_handle", "approval_handle"):
        if name in redacted:
            redacted[name] = "<runtime-handle>"
    return redacted


def _operator_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _operator_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("operator hook URL must be absolute HTTP(S)")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    return f"{parsed.scheme.lower()}://{rendered_host}:{port}"


def _retry_allowed(
    contract: DomainUsageContract,
    route: UsageToolRoute,
    step: UsageToolStep,
    outcome: UsageOutcomeKind,
) -> bool:
    if step.retry != "safe" or step.action_phase is not None:
        return False
    branches = {branch.id: branch for branch in contract.error_handling}
    return any(
        _branch_allows_retry(branches[branch_id], step, outcome)
        for branch_id in route.error_branch_ids
    )


def _branch_allows_retry(
    branch: UsageErrorBranch, step: UsageToolStep, outcome: UsageOutcomeKind
) -> bool:
    return (
        branch.behavior == "retry"
        and branch.retry_policy in {"safe_read", "idempotent"}
        and step.id in branch.step_ids
        and outcome in branch.outcomes
    )


def _arguments(
    contract: DomainUsageContract,
    step: UsageToolStep,
    public_inputs: Mapping[str, JsonValue],
    trusted_context: Mapping[str, JsonValue],
    step_results: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    binding_by_id = {binding.id: binding for binding in contract.input_bindings}
    for binding_id in step.binding_ids:
        binding = binding_by_id.get(binding_id)
        if binding is None:
            raise UsageEvaluationError("step references an unknown input binding")
        value = _binding_value(binding, public_inputs, trusted_context, step_results)
        if value is _MISSING:
            continue
        mapped = _apply_mapping(binding, cast(JsonValue, value))
        _write_pointer(result, binding.target_pointer, mapped)
    for default in contract.defaults:
        existing = _read_pointer(result, default.target_pointer)
        if default.step_id != step.id or existing is not _MISSING:
            continue
        if default.source == "literal":
            _write_pointer(result, default.target_pointer, copy.deepcopy(default.value))
    return result


def _binding_value(
    binding: UsageStepBinding,
    public_inputs: Mapping[str, JsonValue],
    trusted_context: Mapping[str, JsonValue],
    step_results: Mapping[str, JsonValue],
) -> object:
    if binding.source_kind == "prior_step_output":
        source_step_id = binding.source_step_id
        if source_step_id is None or source_step_id not in step_results:
            return _MISSING
        source: object = step_results[source_step_id]
    elif binding.source_kind == "trusted_context":
        if binding.value_kind != "approval_handle":
            raise UsageEvaluationError("trusted context is restricted to approval handles")
        source = trusted_context
    else:
        source = public_inputs
    return _read_pointer(source, binding.source_pointer)


def _apply_mapping(binding: UsageStepBinding, value: JsonValue) -> JsonValue:
    if binding.mapping is None or binding.mapping.kind == "identity":
        return copy.deepcopy(value)
    mapping = binding.mapping.mapping
    key = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return copy.deepcopy(mapping.get(key, value))


def _trusted_approval_is_provisioned(
    contract: DomainUsageContract,
    lifecycle: UsageActionLifecycle | None,
    public_inputs: Mapping[str, JsonValue],
    trusted_context: Mapping[str, JsonValue],
) -> bool:
    if lifecycle is None or lifecycle.approval == "never":
        return True
    if lifecycle.approval == "conditional":
        condition = lifecycle.approval_condition
        if condition is None:
            raise UsageEvaluationError("conditional approval has no condition")
        if not evaluate_condition(condition.model_dump(mode="json"), public_inputs):
            return True
    return _approval_handle_is_available(contract, lifecycle, trusted_context)


def _approval_handle_is_available(
    contract: DomainUsageContract,
    lifecycle: UsageActionLifecycle,
    trusted_context: Mapping[str, JsonValue],
) -> bool:
    binding_id = lifecycle.approval_handle_binding_id
    binding = next((item for item in contract.input_bindings if item.id == binding_id), None)
    if (
        binding is None
        or binding.source_kind != "trusted_context"
        or binding.value_kind != "approval_handle"
        or binding.consumer_step_id != lifecycle.approve_step_id
    ):
        return False
    return _read_pointer(trusted_context, binding.source_pointer) is not _MISSING


def _trusted_bindings_are_allowed(contract: DomainUsageContract) -> bool:
    return all(
        binding.source_kind != "trusted_context" or binding.value_kind == "approval_handle"
        for binding in contract.input_bindings
    )


def _should_execute_step(
    step: UsageToolStep,
    lifecycle: UsageActionLifecycle | None,
    state: Mapping[str, JsonValue],
) -> bool:
    if step.condition is not None and not evaluate_condition(
        step.condition.model_dump(mode="json"), state
    ):
        return False
    if step.action_phase != "approve" or lifecycle is None:
        return True
    if lifecycle.approval == "never":
        return False
    if lifecycle.approval == "always":
        return True
    if lifecycle.approval_condition is None:
        raise UsageEvaluationError("conditional approval has no condition")
    return evaluate_condition(lifecycle.approval_condition.model_dump(mode="json"), state)


def _ordered_steps(route: UsageToolRoute, result_step_id: str) -> tuple[UsageToolStep, ...]:
    by_id = {step.id: step for step in route.steps}
    if result_step_id not in by_id:
        raise UsageEvaluationError("route result step is not declared")
    required = {result_step_id}
    pending = [result_step_id]
    while pending:
        step_id = pending.pop()
        for dependency_id in by_id[step_id].depends_on_step_ids:
            if dependency_id not in by_id:
                raise UsageEvaluationError("route dependency is unresolved")
            if dependency_id not in required:
                required.add(dependency_id)
                pending.append(dependency_id)
    remaining = set(required)
    completed: set[str] = set()
    ordered: list[UsageToolStep] = []
    while remaining:
        ready = [
            by_id[step_id]
            for step_id in remaining
            if set(by_id[step_id].depends_on_step_ids) <= completed
        ]
        if not ready:
            raise UsageEvaluationError("route dependencies are cyclic or unresolved")
        ready.sort(key=lambda step: step.id)
        chosen = ready[0]
        ordered.append(chosen)
        completed.add(chosen.id)
        remaining.remove(chosen.id)
    return tuple(ordered)


def _select_route(contract: DomainUsageContract, scenario: UsageScenario) -> UsageToolRoute:
    if scenario.domain_id != contract.domain_id:
        raise UsageEvaluationError("scenario domain does not match contract")
    if scenario.scenario_id not in contract.required_scenario_ids:
        raise UsageEvaluationError("scenario is not in the contract denominator")
    route = next((item for item in contract.tool_routes if item.id == scenario.route_id), None)
    if route is None:
        raise UsageEvaluationError("scenario route is not declared")
    return route


def _lifecycle(contract: DomainUsageContract, route: UsageToolRoute) -> UsageActionLifecycle | None:
    if route.action_lifecycle_id is None:
        return None
    lifecycle = next(
        (item for item in contract.action_lifecycles if item.id == route.action_lifecycle_id), None
    )
    if lifecycle is None:
        raise UsageEvaluationError("route action lifecycle is not declared")
    return lifecycle


def _attestation_matches(
    contract: DomainUsageContract,
    scenario: UsageScenario,
    attestation: UsageAttestation,
) -> bool:
    return (
        attestation.contract_digest == usage_contract_digest(contract)
        and attestation.scenario_digest == usage_scenario_digest(scenario)
        and all(
            getattr(attestation, field_name) == getattr(contract, field_name)
            for field_name in (
                "pack_digest",
                "ir_digest",
                "tool_schema_digest",
                "test_report_digest",
                "source_snapshot_digest",
            )
        )
    )


def _result(
    contract: DomainUsageContract,
    scenario: UsageScenario,
    route: UsageToolRoute | str,
    *,
    status: str,
    outcome: str,
    status_outcome: UsageOutcomeKind | None = None,
    trace: Sequence[UsageTraceEntry] = (),
) -> UsageScenarioResult:
    result = UsageScenarioResult.model_validate(
        {
            "scenario_id": scenario.scenario_id,
            "domain_id": contract.domain_id,
            "route_id": route.id if isinstance(route, UsageToolRoute) else route,
            "status": status,
            "outcome": outcome,
            "status_outcome": status_outcome,
            "trace": tuple(trace),
        }
    )
    object.__setattr__(result, "_evaluator_derived", True)
    object.__setattr__(result, "_verification_fingerprint", result._public_fingerprint())
    object.__setattr__(result, "_origin_identity", id(result))
    return result


def ingest_headless_agent_results(
    *,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
    results: Sequence[UsageScenarioResult],
    attestations: Mapping[str, UsageAttestation],
) -> UsageAxisReport:
    """Ingest only live evaluator-derived results with exact frozen attestations."""

    scenario_by_id = {item.scenario_id: item for item in scenarios}
    result_by_id = {item.scenario_id: item for item in results}
    required = tuple(contract.required_scenario_ids)
    if (
        tuple(sorted(scenario_by_id)) != required
        or tuple(sorted(result_by_id)) != required
        or tuple(sorted(attestations)) != required
    ):
        raise ValueError("headless results must match the exact scenario denominator")
    if any(not item.evaluator_derived for item in results):
        raise ValueError("headless axis requires live evaluator-derived results")
    scenario_digests: dict[str, str] = {}
    trace: list[UsageVerificationTraceEntry] = []
    evidence: list[str] = []
    for sequence, scenario_id in enumerate(required, 1):
        scenario = scenario_by_id[scenario_id]
        result = result_by_id[scenario_id]
        attestation = attestations[scenario_id]
        scenario_digest = usage_scenario_digest(scenario)
        if (
            result.domain_id != contract.domain_id
            or result.route_id != scenario.route_id
            or attestation.contract_digest != usage_contract_digest(contract)
            or attestation.scenario_digest != scenario_digest
            or any(
                getattr(attestation, field_name) != getattr(contract, field_name)
                for field_name in (
                    "pack_digest",
                    "ir_digest",
                    "tool_schema_digest",
                    "test_report_digest",
                    "source_snapshot_digest",
                )
            )
        ):
            raise ValueError("headless result attestation does not match exact artifacts")
        if not result.trace:
            raise ValueError("verified headless scenarios require an observed Tool call")
        artifact_digest = "sha256:" + hashlib.sha256(result.model_dump_json().encode()).hexdigest()
        terminal = result.trace[-1]
        trace.append(
            UsageVerificationTraceEntry(
                axis="headless_agent_verified",
                sequence=sequence,
                scenario_id=scenario_id,
                route_id=result.route_id,
                tool_name=terminal.tool_name,
                phase=terminal.phase,
                call_number=1,
                status="passed" if result.status == "passed" else "failed",
                artifact_digest=artifact_digest,
            )
        )
        scenario_digests[scenario_id] = scenario_digest
        evidence.append(artifact_digest)
    contract_digest = usage_contract_digest(contract)
    if (
        decision.domain_id != contract.domain_id
        or decision.disposition != "accepted"
        or decision.contract_digest != contract_digest
    ):
        raise ValueError("headless axis decision does not bind the exact contract")
    return UsageAxisReport.from_trace(
        axis="headless_agent_verified",
        domain_id=contract.domain_id,
        required_scenario_ids=required,
        trace=trace,
        evidence_references=tuple(sorted(evidence)),
        contract_digest=contract_digest,
        scenario_digests=scenario_digests,
        package_digest=contract.pack_digest,
        decision_digest=decision.decision_digest,
    )


def ingest_real_mcp_results(
    *,
    contract: DomainUsageContract,
    scenarios: Sequence[UsageScenario],
    decision: UsageDomainDecision,
    results: Sequence[RealMcpUsageScenarioResult],
    attestations: Mapping[str, UsageAttestation],
) -> UsageAxisReport:
    if any(not item.runner_derived for item in results):
        raise ValueError("real MCP axis requires live runner-derived results")
    scenario_results = tuple(item.result for item in results)
    headless = ingest_headless_agent_results(
        contract=contract,
        scenarios=scenarios,
        decision=decision,
        results=scenario_results,
        attestations=attestations,
    )
    if any(item.runtime_tool_schema_digest != contract.tool_schema_digest for item in results):
        raise ValueError("real MCP runtime Tool digest does not match")
    trace = tuple(
        entry.model_copy(update={"axis": "real_mcp_verified"}) for entry in headless.trace
    )
    return UsageAxisReport.from_trace(
        axis="real_mcp_verified",
        domain_id=contract.domain_id,
        required_scenario_ids=headless.required_scenario_ids,
        trace=trace,
        evidence_references=headless.evidence_references,
        contract_digest=headless.contract_digest,
        scenario_digests=headless.scenario_digests,
        package_digest=headless.package_digest,
        decision_digest=headless.decision_digest,
    )


def _json_digest(value: JsonValue | Mapping[str, JsonValue]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _pointer_tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise UsageEvaluationError("binding pointer must be absolute")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def _read_pointer(document: object, pointer: str) -> object:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdecimal() and int(token) < len(current):
            current = current[int(token)]
        else:
            return _MISSING
    return current


def _write_pointer(document: dict[str, JsonValue], pointer: str, value: JsonValue) -> None:
    tokens = _pointer_tokens(pointer)
    if not tokens:
        if not isinstance(value, Mapping):
            raise UsageEvaluationError("root binding value must be an object")
        document.clear()
        document.update(cast(Mapping[str, JsonValue], copy.deepcopy(value)))
        return
    current = document
    for token in tokens[:-1]:
        existing = current.get(token)
        if existing is None:
            child: dict[str, JsonValue] = {}
            current[token] = child
            current = child
        elif isinstance(existing, dict):
            current = existing
        else:
            raise UsageEvaluationError("binding target traverses a scalar")
    current[tokens[-1]] = copy.deepcopy(value)


__all__ = [
    "AgentUsageReleaseVerifier",
    "HeadlessUsageEvaluator",
    "LoopbackOperatorApprovalHook",
    "RealMcpUsageClient",
    "RealMcpUsageRunner",
    "TrustedOperatorApproval",
    "TrustedOperatorApprovalHook",
    "UsageCallerError",
    "UsageEvaluationError",
    "UsageScenarioVerification",
    "UsageToolCaller",
    "ingest_headless_agent_results",
    "ingest_real_mcp_results",
]
