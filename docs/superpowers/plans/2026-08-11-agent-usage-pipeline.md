# Agent Usage Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a second, optional ACC pipeline that turns one user-accepted MCP Release plus bounded domain source evidence into a platform-neutral, independently validated Agent Usage Package.

**Architecture:** Add an isolated `acc_core.usage` namespace, independent Usage project loader, validator, impact analyzer, deterministic `.accusage` builder, headless evaluator, and optional overlay/adapters. Keep Capability Project validation, `.accpkg`, `acc compile`, `acc pack`, and Generic Runtime unchanged; pipeline B only reads their frozen outputs and emits a separate artifact.

**Tech Stack:** Python 3.12+, Pydantic v2, argparse, JSON Schema Draft 2020-12, deterministic ZIP/JSON, MCP Python SDK, pytest, Ruff, mypy, YAML.

---

## File structure

Create focused modules instead of extending the Capability Project loader or packager:

```text
packages/acc-core/src/acc_core/usage/
├── __init__.py          # public Usage API
├── models.py            # strict platform-neutral contracts
├── project.py           # independent Usage project loader
├── acceptance.py        # frozen MCP release/tool snapshot verification
├── analyze.py           # route/binding/lifecycle verification
├── verification.py      # independent verification axes and release gate
├── impact.py            # domain/scenario dependency impact
├── packaging.py         # deterministic .accusage format
└── render.py            # platform-neutral guide/adapter input projection

packages/acc-core/src/acc_core/cli/usage.py
packages/acc-testkit/src/acc_testkit/usage/
packages/acc-runtime/src/acc_runtime/usage/
skills/acc-usage-engineer/
```

Hard boundaries for every task:

- do not add Usage members to `acc_core.validation.validate_project()`;
- do not add Usage members to `acc_core.packaging.build_pack()` or `.accpkg`;
- do not make `acc compile`, `acc pack`, or `acc run` invoke pipeline B;
- do not scan source code from Core or Runtime;
- do not treat user acceptance, frontend visibility, or host adapter success as source authorization;
- do not store credentials, identity values, source payloads, or exception text.

### Task 1: Strict Usage contracts and public Schemas

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/models.py`
- Create: `packages/acc-core/src/acc_core/usage/__init__.py`
- Create: `tests/unit/usage/test_models.py`
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Modify: `tests/unit/core/test_cli.py`
- Create: `schemas/usage-project.schema.json`
- Create: `schemas/usage-mcp-release-acceptance.schema.json`
- Create: `schemas/usage-source-snapshot.schema.json`
- Create: `schemas/usage-domain-index.schema.json`
- Create: `schemas/usage-domain-contract.schema.json`
- Create: `schemas/usage-scenario.schema.json`
- Create: `schemas/usage-release.schema.json`

- [x] **Step 1: Write failing strict-model tests**

Add tests that import and validate these public models:

```python
from acc_core.usage import (
    AgentUsageProject,
    AgentUsageRelease,
    DomainUsageContract,
    DomainUsageIndex,
    McpReleaseAcceptance,
    SourceSnapshot,
    UsageScenario,
)


def test_usage_models_are_current_strict_and_platform_neutral() -> None:
    acceptance = McpReleaseAcceptance.model_validate(_acceptance())
    assert acceptance.schema_version == "2"
    assert acceptance.pack_digest.startswith("sha256:")
    with pytest.raises(ValidationError):
        McpReleaseAcceptance.model_validate({**_acceptance(), "codex_skill": {}})


def test_usage_verification_axes_do_not_imply_one_another() -> None:
    release = AgentUsageRelease.model_validate(_limited_release())
    assert release.verification.user_accepted is True
    assert release.verification.real_mcp_verified is False
```

Cover stable sorted IDs, bounded clean text, UTC timestamps, exact `sha256:<64>`, frozen models, `extra="forbid"`, JSON Pointer syntax, unique step IDs, route DAG cycles, conditional Action approval, and secret-shaped fields being absent from the wire model.

- [x] **Step 2: Run the model test and verify RED**

Run:

```bash
uv run --frozen pytest -q tests/unit/usage/test_models.py
```

Expected: collection fails with `ModuleNotFoundError: No module named 'acc_core.usage'`.

- [x] **Step 3: Implement the minimal typed contracts**

Define a frozen base and the agreed facts:

```python
class UsageModel(StrictModel):
    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)


class AgentUsageProject(UsageModel):
    schema_version: Literal["2"]
    kind: Literal["agent_usage"]
    project: ProjectIdentity
    source_workspace: SourceWorkspace


class McpReleaseAcceptance(UsageModel):
    schema_version: Literal["2"]
    release_id: Identifier
    pack_digest: Sha256Digest
    ir_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    accepted_domain_ids: list[Identifier]
    test_report_digest: Sha256Digest
    known_limitations: list[BoundedText]
    accepted_by: Identifier
    accepted_at: UtcTimestamp


class UsageVerification(UsageModel):
    source_usage_traced: bool
    usage_contract_verified: bool
    headless_agent_verified: bool
    host_adapter_verified: bool
    real_mcp_verified: bool
    user_accepted: bool
```

Also implement `SourceSnapshot`, `UsageEvidenceClaim`, `UsageStepBinding`, `UsageToolStep`, `UsageToolRoute`, `UsageErrorBranch`, `UsageActionLifecycle`, `DomainUsageContract`, `UsageScenario`, `DomainUsageIndex`, `UsageDomainDecision`, and `AgentUsageRelease`. Use `ConditionExpression` and existing declarative `InputMapping`; do not add script/code fields.

- [x] **Step 4: Export exact public Schemas and verify GREEN**

Register seven `usage-*` names in `MODEL_SCHEMAS`, run:

```bash
uv run --frozen pytest -q tests/unit/usage/test_models.py tests/unit/core/test_cli.py -k 'usage or schema'
uv run --frozen acc schema --output /tmp/acc-usage-schemas --json
diff -ru schemas /tmp/acc-usage-schemas
```

Expected: tests pass and the schema diff is empty after copying only fresh generated schema files into `schemas/`.

- [x] **Step 5: Commit Task 1**

```bash
git add packages/acc-core/src/acc_core/usage packages/acc-core/src/acc_core/schemas/export.py schemas tests/unit/usage/test_models.py tests/unit/core/test_cli.py
git commit -m "feat(usage): 定义平台中立使用合同"
```

### Task 2: Independent Usage project loader and closure validation

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/project.py`
- Create: `tests/unit/usage/test_project_loader.py`
- Create: `tests/unit/usage/test_validation.py`
- Create: `tests/fixtures/usage/finance/`

- [x] **Step 1: Write failing loader and closure tests**

Test the independent API and cross-document closure:

```python
from acc_core.usage import validate_usage_project


def test_usage_project_loads_without_capability_directories(tmp_path: Path) -> None:
    project = write_usage_project(tmp_path)
    report = validate_usage_project(project)
    assert report.ok
    assert report.project.kind == "agent_usage"
    assert report.domain_contracts["finance"].domain_id == "finance"


def test_usage_project_rejects_capability_project(tmp_path: Path) -> None:
    report = validate_usage_project(write_capability_project(tmp_path))
    assert "ACC_USAGE_PROJECT_INVALID" in error_codes(report)
```

Cover missing fixed documents, duplicate IDs, symlinks including broken directory symlinks, nested files, unknown suffixes, oversized files, non-UTF-8, Capability/Usage project confusion, scenario/contract/index/release missing-orphan pairs, required scenario closure, and stable diagnostic paths.

- [x] **Step 2: Run tests and verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_project_loader.py tests/unit/usage/test_validation.py
```

Expected: import or attribute failures for `validate_usage_project` and `UsageProjectReport`.

- [x] **Step 3: Implement independent loading**

Expose:

```python
@dataclass(frozen=True, slots=True)
class UsageProjectReport:
    root: Path
    project: AgentUsageProject | None
    acceptance: McpReleaseAcceptance | None
    source_snapshot: SourceSnapshot | None
    domain_index: DomainUsageIndex | None
    domain_contracts: Mapping[str, DomainUsageContract]
    scenarios: Mapping[str, UsageScenario]
    decisions: Mapping[tuple[str, int], UsageDomainDecision]
    releases: Mapping[str, AgentUsageRelease]
    evidence_registry: Mapping[str, Evidence]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


def validate_usage_project(project_root: str | Path = ".") -> UsageProjectReport:
    return _UsageProjectLoader(Path(project_root)).load_and_validate()
```

Use `acc_core.io` safe reads. Load fixed `project.yaml`, `mcp-release-acceptance.yaml`, `source-snapshot.yaml`, `domain-index.yaml`; load one-level collections `domain-usage-contracts/`, `scenarios/`, `domain-decisions/`, `releases/`, and `usage-evidence/`. Never call `validate_project()`.

- [x] **Step 4: Implement closure and secret-safe diagnostics**

Add exact codes including:

```text
ACC_USAGE_PROJECT_INVALID
ACC_USAGE_CONTRACT_MISSING
ACC_USAGE_SCENARIO_UNKNOWN
ACC_USAGE_DOMAIN_NOT_ACCEPTED
ACC_USAGE_RELEASE_GATE_FAILED
ACC_USAGE_EVIDENCE_CLAIM_UNRESOLVED
```

Require every published domain to have exactly one current contract, decision, and release; every required scenario to exist and belong to that domain; every Evidence claim to match an independently loaded Evidence identity. Do not include source values in diagnostics.

- [x] **Step 5: Run adjacent regression and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_project_loader.py tests/unit/usage/test_validation.py tests/unit/core/test_project_validation.py
uv run --frozen ruff check packages/acc-core/src/acc_core/usage tests/unit/usage
uv run --frozen mypy packages/acc-core/src/acc_core/usage
git add packages/acc-core/src/acc_core/usage/project.py tests/unit/usage tests/fixtures/usage
git commit -m "feat(usage): 加载并校验独立使用工程"
```

### Task 3: MCP Release acceptance and final Tool snapshot attestation

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/acceptance.py`
- Create: `tests/unit/usage/test_acceptance.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/__init__.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Create or modify: `tests/unit/runtime/test_mcp.py`

- [x] **Step 1: Write failing acceptance and shared-digest tests**

Freeze a real `.accpkg`, canonical `tools/list` snapshot, runtime info, and acceptance. Assert all four digests must match and that changed descriptions, schemas, pack bytes, IR, or test report fail before Usage analysis.

```python
def test_acceptance_rejects_tool_snapshot_drift(tmp_path: Path) -> None:
    result = verify_mcp_release_acceptance(
        acceptance=acceptance(),
        pack_path=pack,
        tool_snapshot={"tools": [changed_tool()]},
        test_report_path=test_report,
    )
    assert result.code == "ACC_USAGE_DIGEST_MISMATCH"
```

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_acceptance.py tests/unit/runtime/test_mcp.py -k 'usage_acceptance or tool_schema_digest'
```

Expected: missing acceptance verifier or public Tool digest function.

- [x] **Step 3: Promote one canonical Tool digest API**

Move the existing Gateway-private algorithm behind a public, data-only API:

```python
def listed_tools_sha256(tools: Sequence[Tool]) -> str:
    payload = [
        {"name": t.name, "inputSchema": t.inputSchema, "outputSchema": t.outputSchema}
        for t in tools
    ]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
```

Gateway and Usage acceptance must call the same function. Keep the wire value in Runtime as bare 64 hex; normalize to `sha256:<64>` in Usage contracts.

- [x] **Step 4: Implement acceptance verification**

Use `verify_pack()` for immutable Pack integrity, safely parse its verified `compiled/ir.json`, canonicalize the separately frozen `mcp-tools.json`, and compare acceptance digests. Reject missing compiled IR, changed archive after verification, extra Tool snapshot fields, and project/domain mismatch. Never open arbitrary archive paths supplied by the caller.

- [x] **Step 5: Run regression and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_acceptance.py tests/unit/runtime/test_mcp.py tests/integration/pack/test_pack.py
uv run --frozen mypy packages/acc-core/src/acc_core/usage/acceptance.py packages/acc-runtime/src/acc_runtime/mcp
git add packages/acc-core/src/acc_core/usage/acceptance.py packages/acc-runtime/src/acc_runtime/mcp packages/acc-runtime/src/acc_runtime/gateway/runtime.py tests/unit/usage/test_acceptance.py tests/unit/runtime/test_mcp.py
git commit -m "feat(usage): 绑定已接受的 MCP 发布"
```

### Task 4: Tool-route, cross-step binding, Interaction, and Action analysis

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/analyze.py`
- Create: `tests/unit/usage/test_analyze.py`

- [x] **Step 1: Write failing multi-tool analysis tests**

Cover CRM search→detail, ERP shared identifier, empty search stopping before detail, required input from previous public output, optional array index without `minItems`, trusted context exposure, incomplete 403/404/timeout branches, multiple competing routes, and conditional Action approval.

```python
def test_search_empty_path_does_not_force_detail() -> None:
    report = analyze_domain_usage(contract(), scenario("empty"), accepted_release())
    assert report.ok
    assert report.routes[0].empty_success_step_id == "search"


def test_action_contract_cannot_turn_approval_into_source_authorization() -> None:
    report = analyze_domain_usage(unsafe_action_contract(), scenario(), accepted_release())
    assert "ACC_USAGE_ACTION_LIFECYCLE_UNSAFE" in error_codes(report)
```

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_analyze.py
```

Expected: missing `analyze_domain_usage`.

- [x] **Step 3: Implement deterministic analysis**

Expose:

```python
def analyze_domain_usage(
    *,
    report: UsageProjectReport,
    domain_id: str,
    compiled_ir: Mapping[str, JsonValue],
    tool_snapshot: Mapping[str, JsonValue],
) -> UsageAnalysisReport:
    return _UsageAnalyzer(
        report=report,
        compiled_ir=compiled_ir,
        tool_snapshot=tool_snapshot,
    ).analyze(domain_id)
```

Build `Domain -> Scenario -> ToolRoute -> Step -> Capability -> Tool Schema -> Evidence` edges. Reuse `SchemaRelation` directionally for every binding. Adopt already compiled Interaction defaults, conditions, related data, and result projections by digest rather than copying unverified frontend facts. Require public source pointers, guaranteed required paths, stable error branches, and exact Action proof/lifecycle references.

- [x] **Step 4: Add stable diagnostics and adjacent tests**

Implement:

```text
ACC_USAGE_CAPABILITY_UNKNOWN
ACC_USAGE_TOOL_UNKNOWN
ACC_USAGE_TOOL_ROUTE_UNCONSTRUCTIBLE
ACC_USAGE_STEP_OUTPUT_POINTER_UNPROVEN
ACC_USAGE_INPUT_SOURCE_UNRESOLVED
ACC_USAGE_ERROR_BRANCH_INCOMPLETE
ACC_USAGE_ACTION_LIFECYCLE_UNSAFE
ACC_USAGE_INTERACTION_DIGEST_MISMATCH
```

Run:

```bash
uv run --frozen pytest -q tests/unit/usage/test_analyze.py tests/unit/compiler/test_interaction_fidelity.py tests/unit/compiler/test_interaction_compiler.py
```

- [x] **Step 5: Commit Task 4**

```bash
git add packages/acc-core/src/acc_core/usage/analyze.py packages/acc-core/src/acc_core/usage/__init__.py tests/unit/usage/test_analyze.py
git commit -m "feat(usage): 验证跨工具业务调用合同"
```

### Task 5: Bounded domain source scan and Usage Evidence capture

**Files:**
- Create: `skills/acc-usage-engineer/SKILL.md`
- Create: `skills/acc-usage-engineer/HARNESS.md`
- Create: `skills/acc-usage-engineer/guides/01-preflight.md`
- Create: `skills/acc-usage-engineer/guides/02-scan-domain.md`
- Create: `skills/acc-usage-engineer/scripts/usage_evidence_capture.py`
- Create: `skills/acc-usage-engineer/templates/usage-scan-manifest.yaml`
- Create: `tests/unit/skill/test_usage_skill_structure.py`
- Create: `tests/unit/skill/test_usage_evidence_capture.py`

- [x] **Step 1: Write failing Skill and safe-capture tests**

Assert the Skill requires three distinct roots (`source_workspace`, `acc_project`, `usage_project`), accepted MCP digest first, one selected domain plus direct dependencies, frontend/backend/test classifications, zero source writes, and no host-specific core format. Test path escape, symlink, secret, oversized file, source mutation, and output outside `usage-evidence/{frontend,backend,tests}`.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/skill/test_usage_skill_structure.py tests/unit/skill/test_usage_evidence_capture.py
```

Expected: missing `skills/acc-usage-engineer` and script.

- [x] **Step 3: Implement the bounded scan workflow**

Reuse path/snapshot helpers from `skills/acc-engineer/scripts/inventory.py`, `verify_read_only_workspace.py`, and `evidence_capture.py`, but fix the destination root to the Usage project. The scan manifest must contain sorted:

```yaml
domain_id: finance
direct_dependency_domain_ids: []
frontend_include_paths: []
backend_include_paths: []
test_include_paths: []
mcp_domain_decision_refs: []
```

Core and Runtime must not invoke these scripts.

- [x] **Step 4: Run Skill regression and commit**

```bash
uv run --frozen pytest -q tests/unit/skill
uv run --frozen ruff check skills/acc-usage-engineer tests/unit/skill
uv run --frozen mypy skills/acc-usage-engineer/scripts tests/unit/skill
git add skills/acc-usage-engineer tests/unit/skill
git commit -m "feat(skill): 增加领域使用证据扫描"
```

### Task 6: Deterministic Usage domain workflow and CLI foundation

**Files:**
- Create: `packages/acc-core/src/acc_core/cli/usage.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Create: `tests/unit/usage/test_cli.py`
- Create: `tests/integration/usage/test_cli.py`

- [x] **Step 1: Write failing CLI tests**

Cover:

```text
acc usage init
acc usage status
acc usage scan --domain <id> --check
acc usage review --domain <id> --check
```

Assert `init` creates only Usage directories, does not create acceptance, does not touch source/Capability project, and rejects nonempty/symlink destinations. `status` returns one next dependency-ready domain and never trusts declared completed state without exact release closure.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py
```

Expected: argparse rejects the `usage` command.

- [x] **Step 3: Implement thin CLI routing**

Keep parsing in `cli/main.py` and behavior in `cli/usage.py`:

```python
def handle_usage_command(args: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    return _USAGE_HANDLERS[args.usage_command](args)


def status_usage_domains(report: UsageProjectReport) -> Mapping[str, JsonValue]:
    return UsageDomainWorkflow(report).status_document()


def check_usage_domain_review(
    report: UsageProjectReport,
    decision_path: Path,
) -> tuple[Diagnostic, ...]:
    return UsageDomainWorkflow(report).check_review(decision_path)
```

Use stable JSON envelopes, no Evidence bodies, no raw limitations, no identity values, and no writes for `--check`.

- [x] **Step 4: Run CLI adjacency and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py tests/unit/core/test_cli.py tests/integration/test_domain_cli_integration.py
git add packages/acc-core/src/acc_core/cli/usage.py packages/acc-core/src/acc_core/cli/main.py tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py
git commit -m "feat(cli): 增加 Agent Usage 领域向导"
```

### Task 7: Secret-free headless Usage evaluator

**Files:**
- Create: `packages/acc-testkit/src/acc_testkit/usage/models.py`
- Create: `packages/acc-testkit/src/acc_testkit/usage/evaluator.py`
- Create: `packages/acc-testkit/src/acc_testkit/usage/__init__.py`
- Create: `tests/unit/testkit/test_usage_evaluator.py`

- [x] **Step 1: Write failing evaluator tests**

Define a `UsageToolCaller` fake and test ordered route selection, pointer bindings, exact call count, empty stop, 403 preservation, timeout retry policy, stale digests producing zero calls, prohibited behavior rejected before call, and Action approval conditional on proof.

```python
async def test_no_approval_action_never_calls_approve() -> None:
    report = await evaluator.run(no_approval_scenario(), caller)
    assert [entry.phase for entry in report.trace if entry.phase] == ["prepare", "commit", "status"]
```

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/testkit/test_usage_evaluator.py
```

Expected: missing `acc_testkit.usage`.

- [x] **Step 3: Implement deterministic orchestration and trace**

Add:

```python
class UsageToolCaller(Protocol):
    async def call(
        self,
        tool_name: str,
        arguments: Mapping[str, JsonValue],
    ) -> UsageToolOutcome:
        raise NotImplementedError


class HeadlessUsageEvaluator:
    async def run(
        self,
        *,
        contract: DomainUsageContract,
        scenario: UsageScenario,
        caller: UsageToolCaller,
        attestation: UsageAttestation,
    ) -> UsageScenarioResult:
        self._verify_attestation(contract, scenario, attestation)
        return await self._execute_route(contract, scenario, caller)
```

Trace entries contain only scenario/route/tool/phase/outcome and canonical arguments/result hashes. Do not store state values, caller exception messages, principal, tenant, JWT, or payload. Compose `HeadlessInteractionEvaluator` only for adopted leaf interaction semantics.

- [x] **Step 4: Run full testkit regression and commit**

```bash
uv run --frozen pytest -q tests/unit/testkit
uv run --frozen mypy packages/acc-testkit/src/acc_testkit/usage tests/unit/testkit/test_usage_evaluator.py
git add packages/acc-testkit/src/acc_testkit/usage tests/unit/testkit/test_usage_evaluator.py
git commit -m "feat(testkit): 执行无敏感数据的使用场景"
```

### Task 8: Verification axes and host adapter conformance

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/verification.py`
- Create: `packages/acc-testkit/src/acc_testkit/usage/adapters.py`
- Create: `tests/unit/usage/test_verification.py`
- Create: `tests/unit/testkit/test_usage_adapter_conformance.py`

- [x] **Step 1: Write failing independent-axis tests**

Assert required skip/not-provisioned/stale blocks the corresponding axis, one adapter cannot verify another, source-connected cannot upgrade contract safety, user acceptance cannot upgrade any technical axis, and serialized/reloaded reports require trace re-ingestion.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_verification.py tests/unit/testkit/test_usage_adapter_conformance.py
```

- [x] **Step 3: Implement trace-derived reports and release gate**

Create exact-denominator reports with `not_run/passed/failed/stale/blocked`, report digests, scenario IDs, adapter IDs, and evidence references. `AgentUsageRelease.verification` is derived only after validating the corresponding report; never accept a caller-supplied `verified=True` as evidence.

- [x] **Step 4: Run and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_verification.py tests/unit/testkit/test_usage_adapter_conformance.py tests/unit/compiler/test_analysis_tools.py
git add packages/acc-core/src/acc_core/usage/verification.py packages/acc-testkit/src/acc_testkit/usage/adapters.py tests/unit/usage/test_verification.py tests/unit/testkit/test_usage_adapter_conformance.py
git commit -m "feat(usage): 分离使用验证与宿主一致性"
```

### Task 9: Domain/scenario impact and local staleness

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/impact.py`
- Create: `tests/unit/usage/test_impact.py`

- [x] **Step 1: Write failing four-state impact tests**

Test optional output addition→`revalidate`, input/output binding rename→`regenerate`, Capability removal→`blocked`, Action proof/Evidence change→`blocked`, unrelated domain→`unaffected`, direct dependency propagation, and unknown schema relation→fail closed.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_impact.py
```

- [x] **Step 3: Implement the independent graph**

Expose:

```python
class UsageImpactStatus(StrEnum):
    UNAFFECTED = "unaffected"
    REVALIDATE = "revalidate"
    REGENERATE = "regenerate"
    BLOCKED = "blocked"


def analyze_usage_impact(
    *,
    before: UsageSnapshot,
    after: UsageSnapshot,
    report: UsageProjectReport,
) -> UsageImpactReport:
    graph = UsageDependencyGraph.from_report(report)
    return graph.classify_changes(before=before, after=after)
```

Use precedence `blocked > regenerate > revalidate > unaffected`; do not import private `domains.impact` helpers or emit `DomainChangeRequest`.

- [x] **Step 4: Run adjacent regression and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_impact.py tests/unit/compiler/test_domain_impact.py
git add packages/acc-core/src/acc_core/usage/impact.py tests/unit/usage/test_impact.py
git commit -m "feat(usage): 分析领域使用合同局部失效"
```

### Task 10: Deterministic independent `.accusage` package

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/packaging.py`
- Create: `tests/integration/usage/test_package.py`

- [x] **Step 1: Write failing package safety tests**

Cover byte-identical double build, `.accusage` suffix, exact manifest/lock coverage, changed contract changes digest, symlink/nested/unknown/duplicate/oversized/encrypted/path traversal members rejected, and no `.accpkg`, source file, JWT, payload, or unverified domain embedded.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/integration/usage/test_package.py
```

- [x] **Step 3: Implement a separate format**

Use:

```text
format: acc.agent-usage-package
format_version: 2
suffix: .accusage
```

Implement `build_usage_package()` and `verify_usage_package()` with fixed ZIP timestamps, `ZIP_STORED`, canonical JSON, stable ordering, atomic replace, one-MiB member limit, and a dedicated member allowlist. Never call or parameterize `build_pack()`.

- [x] **Step 4: Prove Capability Pack remains closed and commit**

```bash
uv run --frozen pytest -q tests/integration/usage/test_package.py tests/integration/pack/test_pack.py
git add packages/acc-core/src/acc_core/usage/packaging.py tests/integration/usage/test_package.py
git commit -m "feat(usage): 构建独立确定性使用包"
```

### Task 11: MCP-native Usage overlay and public test clients

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/usage/overlay.py`
- Create: `packages/acc-runtime/src/acc_runtime/usage/__init__.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/stdio.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/streamable_http.py`
- Create: `tests/unit/runtime/test_usage_overlay.py`
- Create: `tests/e2e/test_usage_overlay_transports.py`

- [x] **Step 1: Write failing Resource/Prompt parity tests**

Use official SDK clients to list/read released domain resources and list/get one generated prompt over stdio and streamable HTTP. Assert only published domains appear, unknown/stale digest fails closed, resources are canonical JSON, prompts have bounded non-secret arguments, and tools/list/call stay delegated unchanged.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/runtime/test_usage_overlay.py tests/e2e/test_usage_overlay_transports.py
```

- [x] **Step 3: Implement independent overlay**

Create `AgentUsageOverlayMcpServer` that consumes a verified `.accusage` plus a base MCP server. Delegate Tool methods exactly; append fixed URI Resources and generated Prompts from platform-neutral contracts. Do not modify the base `.accpkg`, Tool Schema, or GenericRuntime.

- [x] **Step 4: Expose public client APIs and commit**

Add public `list_resources`, `read_resource`, `list_prompts`, and `get_prompt` methods to both test clients; do not use `_active_session()` in new tests.

```bash
uv run --frozen pytest -q tests/unit/runtime/test_usage_overlay.py tests/e2e/test_usage_overlay_transports.py tests/unit/testkit/test_mcp_client.py
git add packages/acc-runtime/src/acc_runtime/usage packages/acc-testkit/src/acc_testkit/mcp_client tests/unit/runtime/test_usage_overlay.py tests/e2e/test_usage_overlay_transports.py
git commit -m "feat(runtime): 暴露平台中立使用指南覆盖层"
```

### Task 12: Platform-neutral rendering and reference adapters

**Files:**
- Create: `packages/acc-core/src/acc_core/usage/render.py`
- Create: `tests/unit/usage/test_render.py`
- Create: `tests/fixtures/usage/adapters/generic-markdown/`
- Create: `tests/fixtures/usage/adapters/reference-host/`

- [x] **Step 1: Write failing renderer tests**

Assert the generic guide and adapter input contain only released goals/routes/safety, preserve digest and verification limits, never include Evidence locators or secrets, and reject an adapter that adds tools, Action shortcuts, permissions, or unsupported features.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_render.py
```

- [x] **Step 3: Implement faithful projection**

Expose:

```python
class UsageAdapter(Protocol):
    adapter_id: str

    def render(
        self,
        release: AgentUsageRelease,
        package: VerifiedUsagePackage,
    ) -> AdapterArtifacts:
        raise NotImplementedError


def render_generic_agent_guide(
    release: AgentUsageRelease,
    package: VerifiedUsagePackage,
) -> bytes:
    return GenericMarkdownRenderer().render(release, package).guide_bytes


def validate_adapter_artifacts(
    release: AgentUsageRelease,
    package: VerifiedUsagePackage,
    artifacts: AdapterArtifacts,
) -> tuple[Diagnostic, ...]:
    return AdapterArtifactValidator(release, package).validate(artifacts)
```

The generic renderer is the reference output. Do not name the core output `SKILL.md` and do not require any Codex package.

- [x] **Step 4: Run and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_render.py
git add packages/acc-core/src/acc_core/usage/render.py tests/unit/usage/test_render.py tests/fixtures/usage/adapters
git commit -m "feat(usage): 渲染平台中立 Agent 指南"
```

### Task 13: Complete CLI build/test/impact/release/export flow

**Files:**
- Modify: `packages/acc-core/src/acc_core/cli/usage.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `tests/unit/usage/test_cli.py`
- Modify: `tests/integration/usage/test_cli.py`

- [x] **Step 1: Write failing command-flow tests**

Cover:

```text
acc usage build --domain <id>
acc usage test --domain <id>
acc usage impact <change-set>
acc usage release --domain <id> --check
acc usage export --adapter <id>
```

Assert build requires acceptance and contract verification; test never claims real MCP without explicit live evidence; impact is read-only unless a specific output path is authorized; release enforces all required gates; export cannot mutate the Usage package or source.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py -k 'build or test or impact or release or export'
```

- [x] **Step 3: Implement command orchestration**

Keep command handlers thin and call the public Usage APIs from Tasks 2–12. JSON failure envelopes use `ok=false`, no partial success result, and stable exit codes. Every write uses atomic, project-confined, no-symlink output.

- [x] **Step 4: Run full Usage CLI and commit**

```bash
uv run --frozen pytest -q tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py
git add packages/acc-core/src/acc_core/cli/usage.py packages/acc-core/src/acc_core/cli/main.py tests/unit/usage/test_cli.py tests/integration/usage/test_cli.py
git commit -m "feat(cli): 完成 Agent Usage 发布工作流"
```

### Task 14: Complete the Usage Engineer workflow and handoff

**Files:**
- Modify: `skills/acc-usage-engineer/SKILL.md`
- Modify: `skills/acc-usage-engineer/HARNESS.md`
- Create: `skills/acc-usage-engineer/guides/03-model.md`
- Create: `skills/acc-usage-engineer/guides/04-review.md`
- Create: `skills/acc-usage-engineer/guides/05-build.md`
- Create: `skills/acc-usage-engineer/guides/06-test.md`
- Create: `skills/acc-usage-engineer/guides/07-impact.md`
- Create: `skills/acc-usage-engineer/guides/08-release.md`
- Create: `skills/acc-usage-engineer/templates/domain-usage-contract.yaml`
- Create: `skills/acc-usage-engineer/templates/usage-scenario.yaml`
- Create: `skills/acc-usage-engineer/templates/usage-domain-decision.yaml`
- Modify: `tests/unit/skill/test_usage_skill_structure.py`

- [x] **Step 1: Write failing workflow tests**

Require B0–B9, one domain at a time, automatic handling of evidenced facts, grouped questions only for scope/conflict/high-risk/real-test boundary, feedback routing to A or B, independent verification axes, no total score, no platform-specific core, no permission grant language, and stop before Git review.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/unit/skill/test_usage_skill_structure.py
```

- [x] **Step 3: Implement guides/templates and validate**

The templates must intentionally fail if digest placeholders are not replaced. Include Read search→detail, frontend default/condition, and conditional-approval Action examples without project-specific names.

```bash
uv run --frozen pytest -q tests/unit/skill
uv run --frozen ruff check skills/acc-usage-engineer tests/unit/skill
git add skills/acc-usage-engineer tests/unit/skill/test_usage_skill_structure.py
git commit -m "feat(skill): 完成 Agent Usage 领域工作流"
```

### Task 15: Cross-industry fixtures, E2E, and public documentation

**Files:**
- Create: `tests/fixtures/usage/{crm,erp,finance,monitoring,cms,permissions,mobile}/`
- Create: `tests/e2e/test_agent_usage_domain_profiles.py`
- Modify: `README.md`
- Modify: `docs/progress.md`
- Create: `docs/architecture/adr/009-agent-usage-pipeline.md`

- [x] **Step 1: Write failing cross-industry E2E tests**

Parameterize seven current-format fixtures. Cover CRM search→detail, ERP shared ID, Finance conditional-approval Action, monitoring stale status, CMS long text, permissions with source JWT final authority, and mobile client-only interaction. Assert no fixture claims `real_mcp_verified` without a real trace.

- [x] **Step 2: Verify RED**

```bash
uv run --frozen pytest -q tests/e2e/test_agent_usage_domain_profiles.py
```

- [x] **Step 3: Add fixtures and truthful docs**

Document the two pipelines, optional/recommended boundary, source re-scan, platform-neutral package, one-domain confirmation, six independent axes, source authorization, and limited release semantics. Avoid product-specific examples in README.

- [x] **Step 4: Run E2E and commit**

```bash
uv run --frozen pytest -q tests/e2e/test_agent_usage_domain_profiles.py
uv run --frozen ruff check tests/e2e/test_agent_usage_domain_profiles.py
git diff --check
git add tests/fixtures/usage tests/e2e/test_agent_usage_domain_profiles.py README.md docs/progress.md docs/architecture/adr/009-agent-usage-pipeline.md
git commit -m "docs(usage): 交付跨行业使用管道示例"
```

### Task 16: Independent review and final release gates

**Files:**
- Verify all Task 1–15 files
- Modify only files required by concrete review findings

- [x] **Step 1: Run security and boundary searches**

```bash
rg -n "Codex Skill.*core|source_connected_verified.*=.*true|Authorization:|Bearer [A-Za-z0-9_-]+|password:" packages/acc-core/src/acc_core/usage packages/acc-testkit/src/acc_testkit/usage packages/acc-runtime/src/acc_runtime/usage skills/acc-usage-engineer tests/fixtures/usage
rg -n "usage" packages/acc-core/src/acc_core/packaging/pack.py packages/acc-core/src/acc_core/validation/project.py
```

Expected: no secret values, no false verification upgrade, and no Usage members added to Capability Pack/Project paths.

- [x] **Step 2: Run focused complete Usage gate**

```bash
uv run --frozen pytest -q tests/unit/usage tests/integration/usage tests/unit/testkit/test_usage_evaluator.py tests/unit/testkit/test_usage_adapter_conformance.py tests/unit/runtime/test_usage_overlay.py tests/e2e/test_usage_overlay_transports.py tests/e2e/test_agent_usage_domain_profiles.py tests/unit/skill/test_usage_skill_structure.py tests/unit/skill/test_usage_evidence_capture.py
```

- [x] **Step 3: Run adjacent compatibility gate**

```bash
uv run --frozen pytest -q tests/unit/core tests/unit/compiler tests/unit/runtime tests/unit/testkit tests/integration/pack
```

- [x] **Step 4: Run full static and test gates**

```bash
uv lock --check
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts skills/acc-usage-engineer/scripts
uv run --frozen pytest -q
uv run --frozen acc schema --output /tmp/acc-final-schemas --json
diff -ru schemas /tmp/acc-final-schemas
git diff --check
```

- [x] **Step 5: Verify deterministic artifacts**

Build the same `.accusage` twice from one fixture and require byte-identical SHA-256. Verify a changed unrelated domain leaves the selected domain `unaffected`; changed binding produces `regenerate`; deleted Capability produces `blocked`.

- [x] **Step 6: Independent review and final commit**

Require reviewers to report Critical/Important findings against the spec, fix each with a RED→GREEN regression, rerun Steps 1–5, then commit only reviewed files:

```bash
git status --short
git commit -m "feat(usage): 完成独立 Agent 使用管道"
```

Final acceptance requires:

- pipeline A runs and builds `.accpkg` without any Usage project;
- pipeline B refuses an unaccepted or drifted MCP Release;
- frontend source evidence can construct cross-tool usage without granting permissions;
- a user confirms one domain, not every route/tool;
- the core package is platform neutral and works without a host adapter;
- verification axes remain independent;
- only affected domains become stale;
- source JWT/API remains final authority;
- no real mutation occurs without explicit environment-level authorization.
