from __future__ import annotations

import asyncio
import hashlib
import pickle
import zipfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import httpx
import pytest
import yaml
from mcp.client.stdio import StdioServerParameters
from pydantic import JsonValue

import acc_testkit.usage as usage_module
from acc_core.interactions import ComparisonExpression, LiteralOperand, ReferenceOperand
from acc_core.packaging import build_pack
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage import (
    DomainUsageContract,
    UsageActionLifecycle,
    UsageDomainDecision,
    UsageErrorBranch,
    UsageScenario,
    UsageStepBinding,
    UsageToolRoute,
    UsageToolStep,
    build_agent_usage_release,
    ingest_source_usage_evidence,
    ingest_usage_contract_analysis,
    ingest_user_acceptance,
    usage_domain_decision_digest,
)
from acc_core.usage.acceptance import (
    McpReleaseAcceptanceVerification,
    listed_tool_snapshot_sha256,
    verify_mcp_release_acceptance,
)
from acc_core.usage.analyze import UsageAnalysisReport, analyze_usage_contract
from acc_core.usage.models import McpReleaseAcceptance
from acc_core.usage.project import UsageProjectReport, validate_usage_project
from acc_runtime.credentials import SecretValue
from acc_testkit.mcp_client import McpStdioTestClient
from acc_testkit.usage import (
    AgentUsageReleaseVerifier,
    HeadlessUsageEvaluator,
    LoopbackOperatorApprovalHook,
    RealMcpUsageRunner,
    TrustedOperatorApproval,
    UsageAttestation,
    UsageCallerError,
    UsageEvaluationError,
    UsageScenarioVerification,
    UsageToolOutcome,
    ingest_headless_agent_results,
    ingest_real_mcp_results,
    usage_contract_digest,
    usage_scenario_digest,
)
from acc_testkit.usage.evaluator import _live_transport_identity

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64
_DIGEST_D = "sha256:" + "d" * 64
_DIGEST_E = "sha256:" + "e" * 64


def test_public_release_verifier_is_available() -> None:
    assert hasattr(usage_module, "AgentUsageReleaseVerifier")


def test_exact_stdio_client_cannot_self_report_live_transport_provenance() -> None:
    client = McpStdioTestClient(StdioServerParameters(command="unused", args=[]))
    assert not hasattr(client, "_live_owner_identity")
    assert not hasattr(client, "_live_session_fingerprint")
    session = object()
    stack = object()
    object.__setattr__(client, "_session", session)
    object.__setattr__(client, "_stack", stack)
    object.__setattr__(client, "_live_owner_identity", id(client))
    object.__setattr__(client, "_live_session_fingerprint", (id(session), id(stack)))

    assert _live_transport_identity(client) is None


def _finance_verifier_inputs(
    tmp_path: Path,
) -> tuple[UsageProjectReport, McpReleaseAcceptanceVerification, list[dict[str, object]]]:
    project = validate_usage_project(Path(__file__).parents[2] / "fixtures" / "usage" / "finance")
    input_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
        "required": [],
    }
    output_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"items": {"type": "array", "items": {}}},
        "required": ["items"],
    }
    tools: list[dict[str, object]] = [
        {
            "name": "finance.invoice.list",
            "inputSchema": input_schema,
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"result": output_schema},
                "required": ["result"],
            },
        }
    ]
    interaction = {
        "schema_version": "2",
        "inventory": {"status": "declared"},
        "contracts": {"finance.invoice.list": {}},
        "dependencies": [],
    }
    interaction_digest = hashlib.sha256(canonical_json_bytes(interaction)).hexdigest()
    compiled_ir = {
        "ir_version": "2",
        "project": {
            "schema_version": "2",
            "project": {"id": "finance-usage", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "FINANCE_BASE_URL"},
            "quality": {"profile": "standard"},
        },
        "interaction_sha256": interaction_digest,
        "interactions": {**interaction, "digest": interaction_digest},
        "capabilities": {
            "finance.invoice.list": {
                "definition": {
                    "kind": "read",
                    "input_schema": input_schema,
                    "output_schema": output_schema,
                }
            }
        },
        "operations": {},
        "policies": {},
        "evals": {},
    }
    pack_project = tmp_path / "acc-project"
    pack_project.mkdir()
    (pack_project / "project.yaml").write_text(
        yaml.safe_dump(compiled_ir["project"], sort_keys=False), encoding="utf-8"
    )
    (pack_project / "domain-map.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "2",
                "domains": [
                    {
                        "id": "finance",
                        "title": "Finance",
                        "status": "in_progress",
                        "candidate_ids": [],
                        "route_ids": [],
                        "interaction_ids": [],
                        "dependency_domain_ids": [],
                        "evidence_refs": [],
                        "active_decision_ref": None,
                    }
                ],
                "unclassified_candidate_ids": [],
                "preferred_order": ["finance"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    pack_path = tmp_path / "finance.accpkg"
    build_pack(pack_project, pack_path, compiled_ir=compiled_ir)
    with zipfile.ZipFile(pack_path) as archive:
        ir_bytes = archive.read("compiled/ir.json")
    report_path = tmp_path / "test-report.json"
    report_path.write_text('{"passed":true}\n', encoding="utf-8")
    pack_digest = "sha256:" + hashlib.sha256(pack_path.read_bytes()).hexdigest()
    ir_digest = "sha256:" + hashlib.sha256(ir_bytes).hexdigest()
    tool_digest = "sha256:" + listed_tool_snapshot_sha256({"tools": tools})
    test_digest = "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
    acceptance = McpReleaseAcceptance.model_validate(
        {
            "schema_version": "2",
            "release_id": "finance-mcp-1",
            "pack_digest": pack_digest,
            "ir_digest": ir_digest,
            "tool_schema_digest": tool_digest,
            "accepted_domain_ids": ["finance"],
            "test_report_digest": test_digest,
            "known_limitations": [],
            "accepted_by": "reviewer-ref",
            "accepted_at": "2026-08-11T00:00:00Z",
        }
    )
    accepted = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack_path,
        tool_snapshot={"tools": tools},
        test_report_path=report_path,
    )
    assert accepted.ok and accepted.trusted
    source_contract = project.domain_contracts["finance"]
    error_branch = UsageErrorBranch.model_construct(
        id="http-errors",
        outcomes=["forbidden", "not_found", "timeout", "unauthorized"],
        behavior="stop",
        description="Stop on source HTTP failures.",
        step_ids=["list"],
        retry_policy="never",
        evidence_claim_ids=["claim-result"],
    )
    route = source_contract.tool_routes[0].model_copy(
        update={
            "steps": [
                source_contract.tool_routes[0]
                .steps[0]
                .model_copy(update={"tool_name": "finance.invoice.list"})
            ],
            "error_branch_ids": ["http-errors"],
        }
    )
    contract = source_contract.model_copy(
        update={
            "pack_digest": pack_digest,
            "ir_digest": ir_digest,
            "tool_schema_digest": tool_digest,
            "test_report_digest": test_digest,
            "tool_routes": [route],
            "error_handling": [error_branch],
        }
    )
    contract_digest = usage_contract_digest(contract)
    original_decision = project.decisions[("finance", 1)]
    decision_data = original_decision.model_dump(mode="json")
    decision_data["contract_digest"] = contract_digest
    decision_data["decision_digest"] = usage_domain_decision_digest(decision_data)
    confirmation = dict(decision_data["user_confirmation"])
    confirmation["confirmed_decision_digest"] = decision_data["decision_digest"]
    decision_data["user_confirmation"] = confirmation
    decision = UsageDomainDecision.model_validate(decision_data)
    release = project.releases["finance-usage-1"].model_copy(
        update={
            "tool_schema_digest": tool_digest,
            "pack_digest": pack_digest,
            "ir_digest": ir_digest,
            "test_report_digest": test_digest,
            "contract_digest": contract_digest,
            "decision_digest": decision.decision_digest,
            "host_adapters": [],
        }
    )
    project = replace(
        project,
        acceptance=acceptance,
        domain_contracts=MappingProxyType({"finance": contract}),
        decisions=MappingProxyType({("finance", 1): decision}),
        releases=MappingProxyType({"finance-usage-1": release}),
    )
    return project, accepted, tools


@pytest.mark.asyncio
async def test_public_release_verifier_rejects_fake_real_mcp_and_failed_headless_scenario(
    tmp_path: Path,
) -> None:
    project, accepted, tools = _finance_verifier_inputs(tmp_path)

    def execution(headless_outcome: UsageToolOutcome) -> UsageScenarioVerification:
        real_client = FakeRealMcpClient(
            {"finance.invoice.list": [UsageToolOutcome.success({"items": []})]}
        )
        real_client.tools = tools
        return UsageScenarioVerification(
            headless_caller=FakeUsageCaller({"finance.invoice.list": [headless_outcome]}),
            real_mcp_client=real_client,
        )

    with pytest.raises(ValueError, match="not live runner output"):
        await AgentUsageReleaseVerifier().verify(
            project=project,
            accepted_mcp_release=accepted,
            domain_id="finance",
            executions={"finance-list-happy": execution(UsageToolOutcome.success({"items": []}))},
        )

    with pytest.raises(UsageEvaluationError, match="headless Usage scenario"):
        await AgentUsageReleaseVerifier().verify(
            project=project,
            accepted_mcp_release=accepted,
            domain_id="finance",
            executions={"finance-list-happy": execution(UsageToolOutcome(outcome="forbidden"))},
        )


@pytest.mark.asyncio
async def test_public_release_verifier_rejects_a_copied_live_acceptance(tmp_path: Path) -> None:
    project, accepted, tools = _finance_verifier_inputs(tmp_path)
    copied = replace(accepted)
    assert not copied.trusted
    analysis = analyze_usage_contract(project, copied, domain_id="finance")
    assert analysis.ok
    assert not analysis.trusted
    real_client = FakeRealMcpClient(
        {"finance.invoice.list": [UsageToolOutcome.success({"items": []})]}
    )
    real_client.tools = tools

    with pytest.raises(UsageEvaluationError, match="valid typed inputs"):
        await AgentUsageReleaseVerifier().verify(
            project=project,
            accepted_mcp_release=copied,
            domain_id="finance",
            executions={
                "finance-list-happy": UsageScenarioVerification(
                    headless_caller=FakeUsageCaller(
                        {"finance.invoice.list": [UsageToolOutcome.success({"items": []})]}
                    ),
                    real_mcp_client=real_client,
                )
            },
        )


@pytest.mark.asyncio
async def test_public_release_verifier_rejects_same_named_execution_lookalikes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, accepted, _tools = _finance_verifier_inputs(tmp_path)
    contract = project.domain_contracts["finance"]
    scenario = project.scenarios["finance-list-happy"]

    class Trace:
        tool_name = "finance.invoice.list"
        phase = None

    def dump_json() -> str:
        return '{"status":"passed"}'

    fake_scenario_type = type(
        "UsageScenarioResult",
        (),
        {
            "__module__": "acc_testkit.usage.models",
            "scenario_id": scenario.scenario_id,
            "domain_id": contract.domain_id,
            "route_id": scenario.route_id,
            "status": "passed",
            "trace": (Trace(),),
            "evaluator_derived": True,
            "model_dump_json": staticmethod(dump_json),
        },
    )
    fake_scenario = fake_scenario_type()
    fake_real_type = type(
        "RealMcpUsageScenarioResult",
        (),
        {
            "__module__": "acc_testkit.usage.models",
            "result": fake_scenario,
            "runtime_tool_schema_digest": contract.tool_schema_digest,
            "runner_derived": True,
        },
    )

    async def fake_headless_run(*_args: object, **_kwargs: object) -> object:
        return fake_scenario

    async def fake_real_run(*_args: object, **_kwargs: object) -> object:
        return fake_real_type()

    monkeypatch.setattr(HeadlessUsageEvaluator, "run", fake_headless_run)
    monkeypatch.setattr(RealMcpUsageRunner, "run", fake_real_run)

    with pytest.raises(ValueError, match="unsupported concrete type"):
        await AgentUsageReleaseVerifier().verify(
            project=project,
            accepted_mcp_release=accepted,
            domain_id="finance",
            executions={
                scenario.scenario_id: UsageScenarioVerification(
                    headless_caller=FakeUsageCaller({}),
                    real_mcp_client=FakeRealMcpClient({}),
                )
            },
        )


class FakeUsageCaller:
    def __init__(self, outcomes: Mapping[str, list[UsageToolOutcome | BaseException]]) -> None:
        self._outcomes = {name: list(values) for name, values in outcomes.items()}
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []

    async def call(self, tool_name: str, arguments: Mapping[str, JsonValue]) -> UsageToolOutcome:
        self.calls.append((tool_name, dict(arguments)))
        outcome = self._outcomes[tool_name].pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeRealMcpClient(FakeUsageCaller):
    def __init__(self, outcomes: Mapping[str, list[UsageToolOutcome | BaseException]]) -> None:
        super().__init__(outcomes)
        self.tools: list[dict[str, object]] = [
            {"name": name, "inputSchema": {}, "outputSchema": {}} for name in sorted(outcomes)
        ]

    async def list_tools(self) -> list[dict[str, object]]:
        return self.tools


def _step(
    step_id: str,
    tool_name: str,
    *,
    depends: list[str] | None = None,
    bindings: list[str] | None = None,
    retry: str = "never",
    phase: str | None = None,
) -> UsageToolStep:
    return UsageToolStep.model_construct(
        id=step_id,
        capability_id=f"cap.{step_id}",
        tool_name=tool_name,
        depends_on_step_ids=depends or [],
        binding_ids=bindings or [],
        retry=retry,
        action_phase=phase,
        condition=None,
    )


def _contract(
    *,
    steps: list[UsageToolStep] | None = None,
    bindings: list[UsageStepBinding] | None = None,
    errors: list[UsageErrorBranch] | None = None,
    lifecycle: UsageActionLifecycle | None = None,
) -> DomainUsageContract:
    route_steps = steps or [
        _step("find", "records.find", bindings=["query"]),
        _step("read", "records.read", depends=["find"], bindings=["record-id"]),
    ]
    route = UsageToolRoute.model_construct(
        id="route.main",
        business_goal_id="goal.main",
        preconditions=[],
        steps=route_steps,
        error_branch_ids=[branch.id for branch in errors or []],
        result_step_id=route_steps[-1].id,
        result_pointer="",
        action_lifecycle_id=lifecycle.id if lifecycle else None,
    )
    default_bindings = [
        UsageStepBinding.model_construct(
            id="query",
            source_kind="public_input",
            source_step_id=None,
            consumer_step_id="find",
            source_pointer="/query",
            target_pointer="/filter/q",
            mapping=None,
            value_kind="public_value",
        ),
        UsageStepBinding.model_construct(
            id="record-id",
            source_kind="prior_step_output",
            source_step_id="find",
            consumer_step_id="read",
            source_pointer="/items/0/id",
            target_pointer="/record_id",
            mapping=None,
            value_kind="public_value",
        ),
    ]
    return DomainUsageContract.model_construct(
        schema_version="2",
        domain_id="records",
        pack_digest=_DIGEST_A,
        ir_digest=_DIGEST_B,
        tool_schema_digest=_DIGEST_C,
        test_report_digest=_DIGEST_D,
        source_snapshot_digest=_DIGEST_E,
        business_goals=[],
        tool_routes=[route],
        input_bindings=bindings if bindings is not None else default_bindings,
        defaults=[],
        conditions=[],
        option_sources=[],
        related_data=[],
        result_consumption=[],
        error_handling=errors or [],
        action_lifecycles=[lifecycle] if lifecycle else [],
        prohibited_behaviors=["delete_without_confirmation"],
        required_scenario_ids=["scenario.main"],
        evidence_claims=[],
    )


def _scenario(*, kind: str = "happy_path", expected: list[str] | None = None) -> UsageScenario:
    return UsageScenario.model_construct(
        schema_version="2",
        scenario_id="scenario.main",
        domain_id="records",
        route_id="route.main",
        title="main",
        kind=kind,
        public_input_ids=["query"],
        expected_outcomes=expected or ["success"],
        prohibited_behaviors=["delete_without_confirmation"],
    )


def _action_scenario(
    *, kind: str = "action_lifecycle", expected: list[str] | None = None
) -> UsageScenario:
    return _scenario(kind=kind, expected=expected).model_copy(
        update={"public_input_ids": ["approval_required"]}
    )


def _attestation(
    contract: DomainUsageContract | None = None,
    scenario: UsageScenario | None = None,
    **updates: object,
) -> UsageAttestation:
    accepted_contract = contract or _contract()
    accepted_scenario = scenario or _scenario()
    values: dict[str, object] = {
        "pack_digest": _DIGEST_A,
        "ir_digest": _DIGEST_B,
        "tool_schema_digest": _DIGEST_C,
        "test_report_digest": _DIGEST_D,
        "source_snapshot_digest": _DIGEST_E,
        "contract_digest": usage_contract_digest(accepted_contract),
        "scenario_digest": usage_scenario_digest(accepted_scenario),
        "execution_mode": "fake",
    }
    values.update(updates)
    return UsageAttestation.model_validate(values)


@pytest.mark.asyncio
async def test_runs_declared_route_once_in_dependency_order_with_pointer_bindings() -> None:
    caller = FakeUsageCaller(
        {
            "records.find": [UsageToolOutcome.success({"items": [{"id": "r-1"}]})],
            "records.read": [UsageToolOutcome.success({"id": "r-1"})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=_contract(),
        scenario=_scenario(),
        caller=caller,
        attestation=_attestation(),
        public_inputs={"query": "cement"},
    )

    assert report.status == "passed"
    assert report.evaluator_derived
    assert not hasattr(type(report), "_mark_evaluator_derived")
    assert not report.model_copy().evaluator_derived
    assert not type(report).model_validate_json(report.model_dump_json()).evaluator_derived
    assert caller.calls == [
        ("records.find", {"filter": {"q": "cement"}}),
        ("records.read", {"record_id": "r-1"}),
    ]
    assert [entry.step_id for entry in report.trace] == ["find", "read"]
    assert report.trace[0].arguments_sha256 is not None
    assert report.trace[0].result_sha256 is not None
    assert "cement" not in report.model_dump_json()
    assert "r-1" not in report.model_dump_json()

    contract = _contract()
    scenario = _scenario()
    decision = UsageDomainDecision.model_construct(
        domain_id="records",
        disposition="accepted",
        contract_digest=usage_contract_digest(contract),
        included_route_ids=["route.main"],
        decision_digest="sha256:" + "9" * 64,
    )
    axis = ingest_headless_agent_results(
        contract=contract,
        scenarios=(scenario,),
        decision=decision,
        results=(report,),
        attestations={"scenario.main": _attestation(contract, scenario)},
    )
    assert not axis.verified
    serialized = type(report).model_validate_json(report.model_dump_json())
    with pytest.raises(ValueError, match="evaluator-derived"):
        ingest_headless_agent_results(
            contract=contract,
            scenarios=(scenario,),
            decision=decision,
            results=(serialized,),
            attestations={"scenario.main": _attestation(contract, scenario)},
        )


@pytest.mark.asyncio
async def test_real_mcp_runner_binds_tools_and_rejects_serialized_result() -> None:
    client = FakeRealMcpClient(
        {
            "records.find": [UsageToolOutcome.success({"items": [{"id": "r-1"}]})],
            "records.read": [UsageToolOutcome.success({"id": "r-1"})],
        }
    )
    tool_digest = "sha256:" + listed_tool_snapshot_sha256({"tools": client.tools})
    contract = _contract().model_copy(update={"tool_schema_digest": tool_digest})
    scenario = _scenario()
    attestation = _attestation(contract, scenario).model_copy(
        update={"tool_schema_digest": tool_digest, "execution_mode": "real_mcp"}
    )
    observed = await RealMcpUsageRunner().run(
        contract=contract,
        scenario=scenario,
        client=client,
        attestation=attestation,
        public_inputs={"query": "cement"},
    )
    assert not observed.runner_derived
    assert not hasattr(type(observed), "_mark_runner_derived")
    assert not observed.model_copy().runner_derived
    decision = UsageDomainDecision.model_construct(
        domain_id="records",
        disposition="accepted",
        contract_digest=usage_contract_digest(contract),
        included_route_ids=["route.main"],
        decision_digest="sha256:" + "9" * 64,
    )
    with pytest.raises(ValueError, match="runner-derived"):
        ingest_real_mcp_results(
            contract=contract,
            scenarios=(scenario,),
            decision=decision,
            results=(observed,),
            attestations={"scenario.main": attestation},
        )
    forged = type(observed).model_validate_json(observed.model_dump_json())
    with pytest.raises(ValueError, match="runner-derived"):
        ingest_real_mcp_results(
            contract=contract,
            scenarios=(scenario,),
            decision=decision,
            results=(forged,),
            attestations={"scenario.main": attestation},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["unauthorized", "forbidden", "outcome_unknown"])
async def test_real_mcp_runner_preserves_stable_failure_classifications(kind: str) -> None:
    client = FakeRealMcpClient({"records.find": [UsageCallerError(kind)]})
    tool_digest = "sha256:" + listed_tool_snapshot_sha256({"tools": client.tools})
    contract = _contract().model_copy(update={"tool_schema_digest": tool_digest})
    scenario = _scenario()
    attestation = _attestation(contract, scenario).model_copy(
        update={"tool_schema_digest": tool_digest, "execution_mode": "real_mcp"}
    )
    observed = await RealMcpUsageRunner().run(
        contract=contract,
        scenario=scenario,
        client=client,
        attestation=attestation,
        public_inputs={"query": "cement"},
    )
    assert observed.result.outcome == kind
    assert observed.result.status == ("outcome_unknown" if kind == "outcome_unknown" else "failed")


@pytest.mark.asyncio
async def test_release_builder_returns_live_limited_bundle_not_a_bare_release() -> None:
    project = validate_usage_project(Path(__file__).parents[2] / "fixtures" / "usage" / "finance")
    contract = project.domain_contracts["finance"]
    scenario = project.scenarios["finance-list-happy"]
    decision = project.decisions[("finance", 1)]
    attestation = UsageAttestation(
        pack_digest=contract.pack_digest,
        ir_digest=contract.ir_digest,
        tool_schema_digest=contract.tool_schema_digest,
        test_report_digest=contract.test_report_digest,
        source_snapshot_digest=contract.source_snapshot_digest,
        contract_digest=usage_contract_digest(contract),
        scenario_digest=usage_scenario_digest(scenario),
        execution_mode="fake",
    )
    result = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=FakeUsageCaller({"finance_invoice_list": [UsageToolOutcome.success({"items": []})]}),
        attestation=attestation,
    )
    headless = ingest_headless_agent_results(
        contract=contract,
        scenarios=(scenario,),
        decision=decision,
        results=(result,),
        attestations={scenario.scenario_id: attestation},
    )
    reports = (
        ingest_source_usage_evidence(
            project=project, contract=contract, scenarios=(scenario,), decision=decision
        ),
        ingest_usage_contract_analysis(
            analysis=UsageAnalysisReport(domain_id="finance", diagnostics=()),
            contract=contract,
            scenarios=(scenario,),
            decision=decision,
        ),
        headless,
        ingest_user_acceptance(contract=contract, scenarios=(scenario,), decision=decision),
    )
    document = project.releases["finance-usage-1"].model_dump(mode="json", exclude={"verification"})
    document.update(
        {
            "release_status": "limited",
            "known_limitations": ["Real MCP verification remains pending."],
            "host_adapters": [],
        }
    )
    with pytest.raises(ValueError, match="verified reports"):
        build_agent_usage_release(
            release_document=document,
            reports=reports,
            scenario_digests={scenario.scenario_id: usage_scenario_digest(scenario)},
        )


@pytest.mark.asyncio
async def test_empty_outcome_stops_route() -> None:
    caller = FakeUsageCaller({"records.find": [UsageToolOutcome.empty()]})
    contract = _contract()
    scenario = _scenario(kind="empty_result", expected=["empty"])

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"query": "none"},
    )

    assert report.status == "passed"
    assert report.outcome == "empty"
    assert len(caller.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "outcome"),
    [
        (UsageCallerError.from_http_status(401), "unauthorized"),
        (UsageCallerError.from_http_status(403), "forbidden"),
        (UsageCallerError.from_http_status(404), "not_found"),
        (UsageCallerError("timeout"), "timeout"),
    ],
)
async def test_stably_classifies_caller_failures_without_exception_text(
    error: UsageCallerError, outcome: str
) -> None:
    error.args = ("sensitive upstream detail",)
    caller = FakeUsageCaller({"records.find": [error]})
    contract = _contract()
    scenario = _scenario(expected=[outcome])

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"query": "x"},
    )

    assert report.status == "passed"
    assert report.outcome == outcome
    assert "sensitive upstream detail" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_retries_timeout_only_when_both_step_and_branch_allow_it() -> None:
    branch = UsageErrorBranch.model_construct(
        id="retry-timeout",
        outcomes=["timeout"],
        behavior="retry",
        description="retry safe read",
        step_ids=["find"],
        retry_policy="safe_read",
        evidence_claim_ids=["claim"],
    )
    contract = _contract(
        steps=[_step("find", "records.find", bindings=["query"], retry="safe")],
        bindings=[
            UsageStepBinding.model_construct(
                id="query",
                source_kind="public_input",
                source_step_id=None,
                consumer_step_id="find",
                source_pointer="/query",
                target_pointer="/q",
                mapping=None,
                value_kind="public_value",
            )
        ],
        errors=[branch],
    )
    caller = FakeUsageCaller(
        {
            "records.find": [
                UsageCallerError("timeout"),
                UsageToolOutcome.success({"items": []}),
            ]
        }
    )
    scenario = _scenario()

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"query": "x"},
    )

    assert report.status == "passed"
    assert len(caller.calls) == 2
    assert [entry.outcome for entry in report.trace] == ["timeout", "success"]


@pytest.mark.asyncio
async def test_stale_attestation_and_prohibited_request_make_zero_calls() -> None:
    caller = FakeUsageCaller({"records.find": [UsageToolOutcome.success({})]})
    evaluator = HeadlessUsageEvaluator()

    stale = await evaluator.run(
        contract=_contract(),
        scenario=_scenario(),
        caller=caller,
        attestation=_attestation(tool_schema_digest="sha256:" + "f" * 64),
        public_inputs={"query": "x"},
    )
    prohibited_contract = _contract()
    prohibited_scenario = _scenario(kind="prohibited_behavior", expected=["prohibited"])
    prohibited = await evaluator.run(
        contract=prohibited_contract,
        scenario=prohibited_scenario,
        caller=caller,
        attestation=_attestation(prohibited_contract, prohibited_scenario),
        public_inputs={"query": "x"},
        requested_behavior="delete_without_confirmation",
    )

    assert stale.status == "stale"
    assert prohibited.status == "prohibited"
    assert caller.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["contract", "scenario", "scenario_route"])
async def test_contract_or_scenario_digest_drift_makes_zero_calls(drift: str) -> None:
    accepted_contract = _contract()
    accepted_scenario = _scenario()
    runtime_contract = accepted_contract
    runtime_scenario = accepted_scenario
    if drift == "contract":
        runtime_contract = accepted_contract.model_copy(
            update={"prohibited_behaviors": ["changed_behavior"]}
        )
    elif drift == "scenario":
        runtime_scenario = accepted_scenario.model_copy(update={"title": "changed title"})
    else:
        runtime_scenario = accepted_scenario.model_copy(update={"route_id": "route.changed"})
    caller = FakeUsageCaller({"records.find": [UsageToolOutcome.success({})]})

    report = await HeadlessUsageEvaluator().run(
        contract=runtime_contract,
        scenario=runtime_scenario,
        caller=caller,
        attestation=_attestation(accepted_contract, accepted_scenario),
        public_inputs={"query": "x"},
    )

    assert report.status == "stale"
    assert caller.calls == []


def _action_contract(
    approval: str, *, condition_pointer: str = "/approval_required"
) -> DomainUsageContract:
    condition = ComparisonExpression(
        operator="eq",
        left=ReferenceOperand(kind="reference", pointer=condition_pointer),
        right=LiteralOperand(kind="literal", value=True),
    )
    lifecycle = UsageActionLifecycle.model_construct(
        id="lifecycle",
        action_id="action",
        prepare_step_id="prepare",
        approve_action_handle_binding_id="approve-action" if approval != "never" else None,
        commit_action_handle_binding_id="commit-action",
        status_action_handle_binding_id="status-action",
        approval=approval,
        approval_condition=condition if approval == "conditional" else None,
        approve_step_id="approve" if approval != "never" else None,
        approval_handle_binding_id="approval-proof" if approval != "never" else None,
        commit_step_id="commit",
        status_step_id="status",
        outcome_unknown_behavior="query_status",
    )
    steps = [
        _step("prepare", "action.prepare", phase="prepare"),
        _step("approve", "action.approve", depends=["prepare"], phase="approve"),
        _step("commit", "action.commit", depends=["approve", "prepare"], phase="commit"),
        _step("status", "action.status", depends=["prepare"], phase="status"),
    ]
    if approval == "never":
        steps = [
            steps[0],
            _step("commit", "action.commit", depends=["prepare"], phase="commit"),
            steps[3],
        ]
    bindings = []
    if approval != "never":
        bindings.append(
            UsageStepBinding.model_construct(
                id="approval-proof",
                source_kind="trusted_context",
                source_step_id=None,
                consumer_step_id="approve",
                source_pointer="/approval_handle",
                target_pointer="/approval_handle",
                mapping=None,
                value_kind="approval_handle",
            )
        )
        steps[1] = steps[1].model_copy(update={"binding_ids": ["approval-proof"]})
    contract = _contract(steps=steps, bindings=bindings, lifecycle=lifecycle)
    route = contract.tool_routes[0].model_copy(update={"result_step_id": "commit"})
    return contract.model_copy(update={"tool_routes": [route]})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("approval", "approval_required", "expected_phases"),
    [
        ("never", False, ["prepare", "commit"]),
        ("conditional", False, ["prepare", "commit"]),
        ("conditional", True, ["prepare", "approve", "commit"]),
        ("always", False, ["prepare", "approve", "commit"]),
    ],
)
async def test_action_approval_policy_controls_approve_phase_only(
    approval: str, approval_required: bool, expected_phases: list[str]
) -> None:
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque"})],
            "action.approve": [UsageToolOutcome.success({"approval": "ok"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
            "action.status": [UsageToolOutcome.success({"state": "done"})],
        }
    )

    contract = _action_contract(approval)
    scenario = _action_scenario()
    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"approval_required": approval_required},
        trusted_context={"approval_handle": "fake-proof"},
    )

    assert [entry.phase for entry in report.trace] == expected_phases


@pytest.mark.asyncio
async def test_explicit_operator_hook_replaces_approve_tool_without_leaking_handle() -> None:
    contract = _action_contract("always")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque-private"})],
            "action.approve": [UsageToolOutcome.success({"approval": "must-not-run"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
        }
    )

    class Hook:
        async def approve(
            self, *, capability_id: str, action_handle: SecretValue
        ) -> TrustedOperatorApproval:
            assert capability_id == "cap.approve"
            assert action_handle.get_secret_value() == "opaque-private"
            return TrustedOperatorApproval(
                capability_id=capability_id,
                approval_mechanism="loopback_operator_http_v1",
                origin_sha256="a" * 64,
                endpoint_path_sha256="b" * 64,
            )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        operator_approval_hook=Hook(),
    )

    assert report.status == "passed"
    assert [name for name, _ in caller.calls] == ["action.prepare", "action.commit"]
    approve = next(entry for entry in report.trace if entry.phase == "approve")
    assert approve.tool_name == "operator:loopback_operator_http_v1"
    prepare = next(entry for entry in report.trace if entry.phase == "prepare")
    assert prepare.result_sha256 is None
    direct_handle_digest = hashlib.sha256(b'{"action_handle":"opaque-private"}').hexdigest()
    assert direct_handle_digest not in report.model_dump_json()
    assert "opaque-private" not in report.model_dump_json()


def test_trusted_operator_result_is_not_serializable() -> None:
    result = TrustedOperatorApproval(
        capability_id="cap.approve",
        approval_mechanism="loopback_operator_http_v1",
        origin_sha256="a" * 64,
        endpoint_path_sha256="b" * 64,
    )
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(result)


@pytest.mark.asyncio
async def test_builtin_operator_hook_rejects_redirects_and_cross_origin() -> None:
    secret = SecretValue("s" * 40)
    with pytest.raises(ValueError, match="same-origin loopback"):
        LoopbackOperatorApprovalHook(
            gateway_url="http://127.0.0.1:8000",
            endpoint_url="http://127.0.0.1:8001/operator/actions/approve",
            secret=secret,
        )

    hook = LoopbackOperatorApprovalHook(
        gateway_url="http://127.0.0.1:8000",
        endpoint_url="http://127.0.0.1:8000/operator/actions/approve",
        secret=secret,
        transport=httpx.MockTransport(lambda _request: httpx.Response(307)),
    )
    with pytest.raises(UsageEvaluationError, match="approval failed"):
        await hook.approve(capability_id="cap.approve", action_handle=SecretValue("opaque-private"))


@pytest.mark.asyncio
async def test_prepare_output_turning_conditional_approval_true_requires_trusted_handle() -> None:
    contract = _action_contract("conditional", condition_pointer="/prepare/approval_required")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [
                UsageToolOutcome.success({"action_handle": "opaque", "approval_required": True})
            ],
            "action.approve": [UsageToolOutcome.success({"approval": "unexpected"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
    )

    assert report.status == "failed"
    assert report.outcome == "not_provisioned"
    assert [name for name, _ in caller.calls] == ["action.prepare"]
    assert [entry.phase for entry in report.trace] == ["prepare"]
    assert "opaque" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_prepare_output_turning_conditional_approval_false_skips_approve() -> None:
    contract = _action_contract("conditional", condition_pointer="/prepare/approval_required")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [
                UsageToolOutcome.success({"action_handle": "opaque", "approval_required": False})
            ],
            "action.approve": [UsageToolOutcome.success({"approval": "unexpected"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
    )

    assert report.status == "passed"
    assert [name for name, _ in caller.calls] == ["action.prepare", "action.commit"]


@pytest.mark.asyncio
async def test_runtime_conditional_approval_passes_exact_trusted_handle_binding() -> None:
    contract = _action_contract("conditional", condition_pointer="/prepare/approval_required")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [
                UsageToolOutcome.success({"action_handle": "opaque", "approval_required": True})
            ],
            "action.approve": [UsageToolOutcome.success({"approval": "ok"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        trusted_context={"approval_handle": "fake-runtime-proof"},
    )

    assert report.status == "passed"
    assert caller.calls[1] == (
        "action.approve",
        {"approval_handle": "fake-runtime-proof"},
    )
    assert "fake-runtime-proof" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_public_input_cannot_supply_approval_handle_or_replace_trusted_proof() -> None:
    contract = _action_contract("always")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque"})],
            "action.approve": [UsageToolOutcome.success({"approval": "ok"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"approval_handle": "malicious-public-value"},
    )

    assert report.status == "failed"
    assert report.outcome == "not_provisioned"
    assert caller.calls == []
    assert "malicious-public-value" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_trusted_context_rejects_non_approval_bindings_before_any_call() -> None:
    original = _contract()
    invalid_binding = original.input_bindings[0].model_copy(
        update={"source_kind": "trusted_context", "value_kind": "public_value"}
    )
    contract = original.model_copy(
        update={"input_bindings": [invalid_binding, original.input_bindings[1]]}
    )
    scenario = _scenario()
    caller = FakeUsageCaller({"records.find": [UsageToolOutcome.success({})]})

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        trusted_context={"query": "x"},
    )

    assert report.status == "failed"
    assert report.outcome == "not_provisioned"
    assert caller.calls == []


@pytest.mark.asyncio
async def test_successful_commit_does_not_call_status_when_commit_is_route_result() -> None:
    contract = _action_contract("never")
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
            "action.status": [UsageToolOutcome.success({"state": "done"})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"approval_required": False},
    )

    assert report.status == "passed"
    assert [entry.phase for entry in report.trace] == ["prepare", "commit"]


@pytest.mark.asyncio
async def test_result_dependency_closure_excludes_lexically_earlier_unrelated_status() -> None:
    original = _action_contract("never")
    route = original.tool_routes[0]
    renamed_steps = [
        step.model_copy(update={"id": "a-status"}) if step.id == "status" else step
        for step in route.steps
    ]
    renamed_route = route.model_copy(update={"steps": renamed_steps})
    lifecycle = original.action_lifecycles[0].model_copy(update={"status_step_id": "a-status"})
    contract = original.model_copy(
        update={"tool_routes": [renamed_route], "action_lifecycles": [lifecycle]}
    )
    scenario = _action_scenario()
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque"})],
            "action.commit": [UsageToolOutcome.success({"accepted": True})],
            "action.status": [UsageToolOutcome.success({"state": "done"})],
        }
    )

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"approval_required": False},
    )

    assert report.status == "passed"
    assert [entry.phase for entry in report.trace] == ["prepare", "commit"]


@pytest.mark.asyncio
async def test_status_route_can_be_queried_independently() -> None:
    contract = _contract(
        steps=[_step("status", "action.status", phase="status")],
        bindings=[],
    )
    scenario = _action_scenario()
    caller = FakeUsageCaller({"action.status": [UsageToolOutcome.success({"state": "done"})]})

    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
    )

    assert report.status == "passed"
    assert [entry.phase for entry in report.trace] == ["status"]
    assert report.status_outcome == "success"


@pytest.mark.asyncio
async def test_outcome_unknown_runs_status_only_after_commit_and_status_is_independent() -> None:
    caller = FakeUsageCaller(
        {
            "action.prepare": [UsageToolOutcome.success({"action_handle": "opaque"})],
            "action.commit": [UsageCallerError("outcome_unknown")],
            "action.status": [UsageToolOutcome.success({"state": "pending"})],
        }
    )

    contract = _action_contract("never")
    scenario = _action_scenario(kind="outcome_unknown", expected=["outcome_unknown"])
    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"approval_required": False},
    )

    assert report.status == "outcome_unknown"
    assert [entry.phase for entry in report.trace] == ["prepare", "commit", "status"]
    assert report.status_outcome == "success"


@pytest.mark.asyncio
async def test_plain_exception_is_redacted_and_cancelled_error_propagates() -> None:
    secret = "do-not-leak-this-exception-message"
    failed_caller = FakeUsageCaller({"records.find": [RuntimeError(secret)]})
    contract = _contract()
    scenario = _scenario(expected=["source_error"])
    report = await HeadlessUsageEvaluator().run(
        contract=contract,
        scenario=scenario,
        caller=failed_caller,
        attestation=_attestation(contract, scenario),
        public_inputs={"query": "x"},
    )
    cancelled_caller = FakeUsageCaller({"records.find": [asyncio.CancelledError()]})

    assert report.outcome == "source_error"
    assert secret not in report.model_dump_json()
    with pytest.raises(asyncio.CancelledError):
        await HeadlessUsageEvaluator().run(
            contract=contract,
            scenario=_scenario(),
            caller=cancelled_caller,
            attestation=_attestation(contract, _scenario()),
            public_inputs={"query": "x"},
        )
