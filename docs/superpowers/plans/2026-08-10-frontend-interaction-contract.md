# ACC Frontend Interaction Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add evidence-bound, platform-neutral frontend interaction inventories and Capability interaction contracts so ACC can validate defaults, input bindings, option sources, conditions, related data, presentation states, and client-verification truth instead of treating frontend usage as a route-call string.

**Architecture:** Keep `ScopeInventory`, `SourceContract`, `UIInteractionInventory`, and `InteractionContract` as separate authorities. Core loads and validates the two new sidecars, Compiler emits a canonical interaction attestation and digest, Runtime exposes a read-only manifest without becoming a UI engine, Testkit executes a headless reference state machine, and Coverage reports independent interaction axes. Framework-specific discovery remains outside Core and must normalize to the same contracts.

**Tech Stack:** Python 3.12, Pydantic v2, JSON Schema Draft 2020-12, PyYAML, MCP Python SDK, pytest, Ruff, mypy.

---

## File map

- `packages/acc-core/src/acc_core/interactions/models.py`: strict inventory and contract documents.
- `packages/acc-core/src/acc_core/interactions/expressions.py`: bounded condition AST and evaluator-independent validation.
- `packages/acc-core/src/acc_core/interactions/validate.py`: cross-document, Schema, Evidence, and graph validation.
- `packages/acc-core/src/acc_core/interactions/compile.py`: canonical interaction attestation and digest.
- `packages/acc-core/src/acc_core/validation/project.py`: project loading and one-to-one sidecar closure.
- `packages/acc-core/src/acc_core/coverage/interaction.py`: independent interaction Coverage axes.
- `packages/acc-runtime/src/acc_runtime/interactions.py`: immutable public interaction manifest.
- `packages/acc-testkit/src/acc_testkit/interactions/`: headless state evaluator and trace models.
- `skills/acc-engineer/scripts/interaction_audit.py`: project-level semantic audit for generated ACC projects.

### Task 1: UI interaction inventory models

**Files:**
- Create: `packages/acc-core/src/acc_core/interactions/__init__.py`
- Create: `packages/acc-core/src/acc_core/interactions/models.py`
- Test: `tests/unit/core/test_interaction_models.py`

- [ ] **Step 1: Write failing model tests**

```python
from pydantic import TypeAdapter, ValidationError

from acc_core.interactions import UIInteractionInventory


def test_complete_inventory_has_a_surface_interaction_denominator() -> None:
    inventory = UIInteractionInventory.model_validate(
        {
            "schema_version": "2",
            "scope": {"mode": "complete", "evidence_sources": ["frontend-tree"]},
            "surfaces": [
                {
                    "id": "customers",
                    "kind": "page",
                    "route_or_entry": "/customers",
                    "business_purpose": "Manage customers",
                    "evidence_sources": ["customer-page"],
                }
            ],
            "interactions": [
                {
                    "id": "customers.initial-load",
                    "surface_id": "customers",
                    "business_intent": "Load visible customers",
                    "trigger": {"kind": "screen_load"},
                    "route_ids": ["GET /api/customers"],
                    "call_order": "sequential",
                    "input_bindings": [],
                    "defaults": [],
                    "option_sources": [],
                    "conditions": [],
                    "related_data": [],
                    "result_consumption": [],
                    "states": [],
                    "evidence_claims": [],
                    "unknowns": [],
                }
            ],
            "summary": {"surfaces": 1, "interactions": 1, "unresolved": 0},
        }
    )
    assert inventory.scope.mode == "complete"


def test_complete_inventory_rejects_divergent_summary() -> None:
    document = _complete_inventory_document()
    document["summary"]["interactions"] = 2
    with pytest.raises(ValidationError, match="summary must exactly match"):
        UIInteractionInventory.model_validate(document)
```

- [ ] **Step 2: Run RED test**

Run: `uv run --frozen pytest -q tests/unit/core/test_interaction_models.py`

Expected: collection fails because `acc_core.interactions` does not exist.

- [ ] **Step 3: Implement strict models**

Implement frozen, `extra="forbid"`, strict models with these public types:

```python
class InteractionScope(StrictModel):
    mode: Literal["none", "discovered", "complete"]
    evidence_sources: list[NonEmptyString] = Field(default_factory=list)
    rationale: NonEmptyString | None = None

class UISurface(StrictModel):
    id: NonEmptyString
    kind: Literal["page", "dialog", "panel", "mobile_screen", "command", "embedded_flow"]
    route_or_entry: NonEmptyString
    business_purpose: NonEmptyString
    evidence_sources: list[NonEmptyString]

class UIInteraction(StrictModel):
    id: NonEmptyString
    surface_id: NonEmptyString
    business_intent: NonEmptyString
    trigger: InteractionTrigger
    route_ids: list[NonEmptyString]
    call_order: Literal["sequential", "parallel", "independent"]
    input_bindings: list[InputBinding]
    defaults: list[InteractionDefault]
    option_sources: list[OptionSource]
    conditions: list[InteractionCondition]
    related_data: list[RelatedDataBinding]
    result_consumption: list[ResultConsumption]
    states: list[InteractionState]
    evidence_claims: list[InteractionEvidenceClaim]
    unknowns: list[NonEmptyString]

class UIInteractionInventory(StrictModel):
    schema_version: Literal["2"]
    scope: InteractionScope
    surfaces: list[UISurface]
    interactions: list[UIInteraction]
    summary: InteractionSummary
```

Validators enforce unique sorted IDs, real surface references, `mode=none` with empty denominators and evidence-backed rationale, and exact summary counters.

- [ ] **Step 4: Run GREEN and adjacent tests**

Run: `uv run --frozen pytest -q tests/unit/core/test_interaction_models.py tests/unit/core/test_models.py`

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/interactions tests/unit/core/test_interaction_models.py
git commit -m "feat(core): 建立前端交互清单合同"
```

### Task 2: Capability InteractionContract and safe conditions

**Files:**
- Create: `packages/acc-core/src/acc_core/interactions/expressions.py`
- Modify: `packages/acc-core/src/acc_core/interactions/models.py`
- Modify: `packages/acc-core/src/acc_core/interactions/__init__.py`
- Test: `tests/unit/core/test_interaction_contract_models.py`

- [ ] **Step 1: Add RED tests for defaults, bindings, options, and cycles**

```python
def test_interaction_contract_binds_a_producer_value_to_consumer_input() -> None:
    contract = CapabilityInteractionContract.model_validate(_contract_document())
    binding = contract.related_data[0]
    assert binding.producer_id == "search_customers"
    assert binding.output_pointer == "/items/0/id"
    assert binding.target_pointer == "/customer_id"


def test_condition_ast_rejects_arbitrary_source_expression() -> None:
    document = _contract_document()
    document["conditions"] = [{"target": "visible", "expression": "window.user.admin"}]
    with pytest.raises(ValidationError):
        CapabilityInteractionContract.model_validate(document)
```

- [ ] **Step 2: Run RED test**

Run: `uv run --frozen pytest -q tests/unit/core/test_interaction_contract_models.py`

Expected: import failure for `CapabilityInteractionContract`.

- [ ] **Step 3: Implement the public contract and discriminated AST**

```python
class ReferenceOperand(StrictModel):
    kind: Literal["reference"]
    pointer: JsonPointer

class LiteralOperand(StrictModel):
    kind: Literal["literal"]
    value: JsonValue

type ConditionExpression = Annotated[
    AllExpression | AnyExpression | NotExpression | ComparisonExpression,
    Field(discriminator="operator"),
]

class CapabilityInteractionContract(StrictModel):
    schema_version: Literal["2"]
    capability_id: NonEmptyString
    interaction_ids: list[NonEmptyString]
    public_input_bindings: list[InputBinding]
    trusted_input_bindings: list[InputBinding]
    defaults: list[InteractionDefault]
    option_sources: list[OptionSource]
    conditions: list[InteractionCondition]
    related_data: list[RelatedDataBinding]
    result_consumption: list[ResultConsumption]
    required_scenarios: list[NonEmptyString]
    omissions: list[InteractionOmission]
```

Allow only `all`, `any`, `not`, `eq`, `ne`, `in`, and `present`; condition targets are `visible`, `enabled`, `required`, and `reset`. Enforce unique pointers and sorted stable IDs.

- [ ] **Step 4: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_interaction_contract_models.py`

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/interactions tests/unit/core/test_interaction_contract_models.py
git commit -m "feat(core): 定义能力交互合同与安全条件"
```

### Task 3: Schema export and project loading

**Files:**
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `schemas/`
- Test: `tests/unit/core/test_project_validation.py`
- Test: `tests/unit/core/test_cli.py`

- [ ] **Step 1: Write RED tests for schema names and sidecar closure**

```python
def test_frontend_project_requires_inventory_and_one_contract_per_capability(tmp_path: Path) -> None:
    project = _valid_project(tmp_path)
    _write_ui_inventory(project, mode="complete")
    report = validate_project(project)
    assert any(item.code == "ACC_UI_INTERACTION_CONTRACT_MISSING" for item in report.diagnostics)


def test_schema_command_exports_interaction_contracts(tmp_path: Path) -> None:
    completed = _run_acc("schema", "--output", str(tmp_path), "--json")
    assert completed.returncode == 0
    assert (tmp_path / "ui-interaction-inventory.schema.json").is_file()
    assert (tmp_path / "interaction-contract.schema.json").is_file()
```

- [ ] **Step 2: Run RED tests**

Run: `uv run --frozen pytest -q tests/unit/core/test_project_validation.py tests/unit/core/test_cli.py -k interaction`

Expected: missing schema exports and no sidecar diagnostics.

- [ ] **Step 3: Extend ValidationReport and loader**

Add typed fields:

```python
ui_interaction_inventory: UIInteractionInventory | None = None
ui_interaction_inventory_path: str | None = None
interaction_contracts: dict[str, CapabilityInteractionContract] = field(default_factory=dict)
interaction_contract_paths: dict[str, str] = field(default_factory=dict)
```

Load `ui-interaction-inventory.yaml` and `interaction-contracts/*.yaml`. Require exact closure over interactions adopted by referenced Capabilities whenever interaction scope is `discovered` or `complete`; reject orphans and duplicates, while evidence-backed omissions remain explicit inventory dispositions. `acc init` creates the empty `interaction-contracts/` directory but does not fabricate an inventory; Analyze creates the inventory only after client-surface discovery.

- [ ] **Step 4: Export canonical schemas and regenerate tracked files**

Run: `uv run --frozen acc schema --output schemas --json`

Expected: two new stable schema files plus existing schemas.

- [ ] **Step 5: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_project_validation.py tests/unit/core/test_cli.py`

- [ ] **Step 6: Commit**

```bash
git add packages/acc-core/src/acc_core/schemas/export.py packages/acc-core/src/acc_core/validation/project.py packages/acc-core/src/acc_core/cli/main.py schemas tests/unit/core
git commit -m "feat(core): 加载并校验交互侧车"
```

### Task 4: Semantic fidelity validator

**Files:**
- Create: `packages/acc-core/src/acc_core/interactions/validate.py`
- Test: `tests/unit/compiler/test_interaction_fidelity.py`

- [ ] **Step 1: Write RED tests for the platform safety rules**

Cover these exact diagnostics:

```python
@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (_unknown_route, "ACC_UI_INTERACTION_ROUTE_UNKNOWN"),
        (_missing_evidence, "ACC_UI_INTERACTION_EVIDENCE_MISSING"),
        (_invalid_default, "ACC_UI_DEFAULT_AUTHORITY_UNPROVEN"),
        (_bad_option_pointer, "ACC_UI_OPTION_SOURCE_UNTRACED"),
        (_condition_cycle, "ACC_UI_CONDITION_CYCLE"),
        (_broken_join, "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN"),
        (_hidden_permission, "ACC_UI_HIDDEN_NOT_AUTHORIZATION"),
    ],
)
def test_interaction_fidelity_fails_closed(mutate, code):
    report = analyze_interaction_fidelity(**mutate(_valid_documents()))
    assert code in {item.code for item in report.diagnostics}
```

- [ ] **Step 2: Run RED test**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_interaction_fidelity.py`

- [ ] **Step 3: Implement pure validation**

Public API:

```python
@dataclass(frozen=True, slots=True)
class InteractionValidationReport:
    diagnostics: tuple[Diagnostic, ...]
    interaction_ids: tuple[str, ...]
    dependency_edges: tuple[tuple[str, str], ...]

def analyze_interaction_fidelity(
    *,
    project: Project,
    scope_inventory: ScopeInventory,
    ui_inventory: UIInteractionInventory,
    contracts: Mapping[str, CapabilityInteractionContract],
    capabilities: Mapping[str, Capability],
    operations: Mapping[str, Operation],
    policies: Mapping[str, Policy],
) -> InteractionValidationReport: ...
```

Use existing Schema relation helpers for producer-output to consumer-input compatibility. Validate defaults with Draft 2020-12, detect condition/producer cycles with deterministic DFS, and compare presentation pointers only against policy-visible Capability output.

- [ ] **Step 4: Run GREEN and compiler adjacency**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_interaction_fidelity.py tests/unit/compiler/test_schema_fidelity.py tests/unit/compiler/test_capability_quality.py`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/interactions/validate.py tests/unit/compiler/test_interaction_fidelity.py
git commit -m "feat(core): 证明前端交互语义闭环"
```

### Task 5: Scope cross-references and interaction audit

**Files:**
- Modify: `packages/acc-core/src/acc_core/scope/models.py`
- Create: `skills/acc-engineer/scripts/interaction_audit.py`
- Modify: `skills/acc-engineer/templates/scope-inventory.yaml`
- Create: `skills/acc-engineer/templates/ui-interaction-inventory.yaml`
- Create: `skills/acc-engineer/templates/interaction-contract.yaml`
- Test: `tests/unit/core/test_scope_models.py`
- Create: `tests/unit/skill/test_interaction_audit.py`

- [ ] **Step 1: Add RED tests**

Assert `ScopeRoute.interaction_ids` defaults to `[]`, template `usage_evidence_sources` defaults to `[]`, unknown route/interaction links fail, complete mode with unresolved interactions fails, and source/frontend path secrets never appear in JSON diagnostics.

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/core/test_scope_models.py tests/unit/skill/test_interaction_audit.py`

- [ ] **Step 3: Implement cross-links and CLI script**

The script interface is:

```bash
python3 skills/acc-engineer/scripts/interaction_audit.py \
  --project /absolute/acc-project \
  --output interaction-audit-report.json
```

It loads Core typed models, emits stable sorted diagnostics, never imports source-system code, and performs no frontend parsing. Framework adapters or Agents create the normalized inventory.

- [ ] **Step 4: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_scope_models.py tests/unit/skill/test_interaction_audit.py`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/scope/models.py skills/acc-engineer tests/unit/core/test_scope_models.py tests/unit/skill/test_interaction_audit.py
git commit -m "feat(skill): 增加交互清单审计门禁"
```

### Task 6: Compiler, IR, and Pack attestation

**Files:**
- Create: `packages/acc-core/src/acc_core/interactions/compile.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/packaging/pack.py`
- Test: `tests/unit/compiler/test_interaction_compiler.py`
- Test: `tests/integration/pack/test_pack.py`

- [ ] **Step 1: Add RED deterministic attestation tests**

```python
def test_compiler_emits_canonical_interaction_attestation() -> None:
    report = compile_project(_validated_interaction_project())
    attestation = report.ir["interactions"]
    assert set(attestation) == {"digest", "inventory", "contracts", "dependencies"}
    assert len(attestation["digest"]) == 64


def test_pack_digest_changes_when_interaction_semantics_change(tmp_path: Path) -> None:
    first = build_pack(_project(tmp_path), output_path=tmp_path / "first.accpkg")
    _change_default_submission_behavior(tmp_path)
    second = build_pack(_project(tmp_path), output_path=tmp_path / "second.accpkg")
    assert first.sha256 != second.sha256
```

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_interaction_compiler.py tests/integration/pack/test_pack.py -k interaction`

- [ ] **Step 3: Implement canonical compilation**

```python
@dataclass(frozen=True, slots=True)
class CompiledInteractionAttestation:
    digest: str
    inventory: dict[str, JsonValue]
    contracts: dict[str, dict[str, JsonValue]]
    dependencies: tuple[tuple[str, str], ...]

def compile_interactions(report: ValidationReport) -> CompiledInteractionAttestation: ...
```

Canonical JSON uses sorted keys, compact separators, UTF-8, and SHA-256. Pack directory allowlists include `ui-interaction-inventory.yaml` and `interaction-contracts/`; lock coverage and traversal limits remain unchanged.

- [ ] **Step 4: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_interaction_compiler.py tests/integration/pack/test_pack.py`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/interactions/compile.py packages/acc-core/src/acc_core/compiler/ir.py packages/acc-core/src/acc_core/packaging/pack.py tests
git commit -m "feat(compiler): 编译交互证明与确定性摘要"
```

### Task 7: Runtime interaction manifest and Gateway attestation

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/interactions.py`
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/models.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Test: `tests/unit/runtime/test_interaction_manifest.py`
- Test: `tests/unit/runtime/test_mcp.py`
- Test: `tests/unit/runtime/gateway/test_gateway_models.py`

- [ ] **Step 1: Add RED tests**

```python
def test_runtime_exposes_only_public_interaction_manifest() -> None:
    manifest = GenericRuntime.from_pack(PACK).interaction_manifest()
    assert manifest.digest == EXPECTED_DIGEST
    assert "evidence" not in manifest.model_dump_json().casefold()
    assert "token" not in manifest.model_dump_json().casefold()


def test_gateway_info_attests_interactions_separately() -> None:
    info = composition.runtime_info()
    assert info.interaction_sha256 == runtime.interaction_manifest().digest
    assert info.interaction_sha256 != info.tool_schema_sha256


async def test_mcp_exposes_the_versioned_read_only_interaction_resource() -> None:
    server = CapabilityMcpServer(RUNTIME).create_server()
    resources = await _list_resources(server)
    assert [resource.uri for resource in resources] == ["acc://interactions/v2/manifest"]


async def test_runtime_applies_only_compiled_public_defaults() -> None:
    result = await RUNTIME.call("search_customers", {})
    assert CALLER.calls == [("crm.search_customers", {"current": 1, "size": 20})]
    assert result == EXPECTED_RESULT
```

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/runtime/test_interaction_manifest.py tests/unit/runtime/gateway/test_gateway_models.py`

- [ ] **Step 3: Implement immutable manifest**

```python
class RuntimeInteractionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["2"]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    interaction_ids: tuple[str, ...]
    capability_contracts: dict[str, PublicCapabilityInteraction]
```

Do not execute frontend code or arbitrary conditions in MCP Tool calls. Implement `normalize_interaction_arguments(capability_id, arguments, manifest)` as a pure function that applies only Compiler-emitted public defaults with `submission=send`; explicit caller values, including `null`, win. Trusted defaults remain in `PrincipalContext`/Workflow bindings and never enter public arguments. JSON Schema `default` alone remains non-executable. Register the immutable manifest as MCP Resource `acc://interactions/v2/manifest`, and add `interaction_sha256` to `GatewayRuntimeInfo` and `/runtime/info` without identity or source evidence.

- [ ] **Step 4: Run GREEN and runtime regressions**

Run: `uv run --frozen pytest -q tests/unit/runtime tests/integration/runtime/test_gateway_http.py`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-runtime/src/acc_runtime tests/unit/runtime tests/integration/runtime/test_gateway_http.py
git commit -m "feat(runtime): 暴露只读交互证明清单"
```

### Task 8: Headless interaction evaluator

**Files:**
- Create: `packages/acc-testkit/src/acc_testkit/interactions/__init__.py`
- Create: `packages/acc-testkit/src/acc_testkit/interactions/models.py`
- Create: `packages/acc-testkit/src/acc_testkit/interactions/evaluator.py`
- Test: `tests/unit/testkit/test_interaction_evaluator.py`

- [ ] **Step 1: Write RED scenario tests**

Tests cover missing/null/explicit defaults, omit/send/send-if-changed, option success/empty/error/paging, cascade dependency change, stale response rejection, visible/enabled/required/reset, hidden clear/preserve, all declared states, value/label mapping, principal/tenant cache keys, and Action lifecycle events.

```python
async def test_cascade_change_rejects_stale_option_response() -> None:
    evaluator = HeadlessInteractionEvaluator(CONTRACT, caller=DelayedCaller())
    first = evaluator.dispatch("change", {"country_id": "cn"})
    second = evaluator.dispatch("change", {"country_id": "sg"})
    await second
    await first
    assert evaluator.state.options["city_id"] == SINGAPORE_OPTIONS
```

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/testkit/test_interaction_evaluator.py`

- [ ] **Step 3: Implement deterministic evaluator**

Public API:

```python
class InteractionCaller(Protocol):
    async def call(self, capability_id: str, arguments: Mapping[str, JsonValue]) -> JsonValue: ...

class HeadlessInteractionEvaluator:
    def __init__(self, contract: RuntimeInteractionManifest, *, caller: InteractionCaller): ...
    async def dispatch(self, event: str, payload: Mapping[str, JsonValue]) -> InteractionTrace: ...

class ClientAdapterConformanceReport(BaseModel):
    schema_version: Literal["2"]
    adapter_id: str
    interaction_digest: str
    required_scenarios: tuple[str, ...]
    passed_scenarios: tuple[str, ...]
    failed_scenarios: tuple[str, ...]
    skipped_scenarios: tuple[str, ...]
    evidence_sources: tuple[str, ...]
```

Use monotonic request generations to reject stale option responses. Cache keys include capability, canonical arguments, principal digest, and tenant digest. Trace data contains IDs and state categories, never credentials or raw trusted context. A client adapter reaches `client_adapter_verified` only when its report matches the manifest digest and every required scenario passed; skipped required scenarios fail closed.

- [ ] **Step 4: Run GREEN and Testkit suite**

Run: `uv run --frozen pytest -q tests/unit/testkit`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-testkit/src/acc_testkit/interactions tests/unit/testkit
git commit -m "feat(testkit): 增加无界面交互验证器"
```

### Task 9: Interaction Coverage axes and CLI

**Files:**
- Create: `packages/acc-core/src/acc_core/coverage/interaction.py`
- Modify: `packages/acc-core/src/acc_core/coverage/models.py`
- Modify: `packages/acc-core/src/acc_core/coverage/analyze.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/compiler/test_analysis_tools.py`
- Test: `tests/integration/test_cli_milestone2.py`

- [ ] **Step 1: Add RED multi-axis tests**

```python
def test_route_closure_does_not_hide_interaction_gaps() -> None:
    report = analyze_coverage(_report_with_closed_routes_and_missing_defaults())
    assert report.route_disposition.broken_route_ids == ()
    assert report.default_provenance.unproven_interaction_ids == ("orders.initial-load",)
    assert not hasattr(report, "score")
```

Assert all ten new axes are present and deterministic, `client_adapter_evidence` stays `not_verified` after source-connected observations, and required skipped interaction scenarios cannot produce `headless_verified`.

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_analysis_tools.py tests/integration/test_cli_milestone2.py -k interaction`

- [ ] **Step 3: Implement independent axes**

Add `surface_disposition`, `interaction_trace`, `input_binding_fidelity`, `default_provenance`, `option_resolution`, `condition_coverage`, `related_data_graph`, `state_scenarios`, `presentation_projection`, and `client_adapter_evidence`. Do not add an aggregate status or score.

- [ ] **Step 4: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_analysis_tools.py tests/integration/test_cli_milestone2.py`

- [ ] **Step 5: Commit**

```bash
git add packages/acc-core/src/acc_core/coverage packages/acc-core/src/acc_core/cli/main.py tests
git commit -m "feat(coverage): 增加前端交互独立覆盖轴"
```

### Task 10: Engineer Skill and maintained example

**Files:**
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/02-analyze.md`
- Modify: `skills/acc-engineer/guides/03-model.md`
- Modify: `skills/acc-engineer/guides/04-plan.md`
- Modify: `skills/acc-engineer/guides/05-implement.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/08-refine.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Modify: `examples/fastapi-crm/acc-project/`
- Test: `tests/unit/skill/test_skill_structure.py`
- Test: `tests/e2e/test_fastapi_crm_example.py`

- [ ] **Step 1: Add RED Skill and example assertions**

Assert Skill requires interaction discovery/audit, no longer says Analyze only GET/HEAD or Model only Read, templates do not prefill fake usage evidence, maintained CRM includes a complete UI inventory and three Capability contracts, and Handoff distinguishes `headless_verified` from `client_adapter_verified`.

- [ ] **Step 2: Run RED**

Run: `uv run --frozen pytest -q tests/unit/skill/test_skill_structure.py tests/e2e/test_fastapi_crm_example.py`

- [ ] **Step 3: Update the workflow and example**

Phase changes:

- Analyze discovers surfaces, events, bindings, defaults, options, conditions, related data, states, and unknowns.
- Model preserves Read and Action semantics and builds the interaction dependency graph.
- Plan adopts or explicitly omits each high-value interaction.
- Implement creates InteractionContracts only from Evidence.
- Validate runs `interaction_audit.py` after `scope_audit.py` and before `acc validate`.
- Test runs default/cascade/state/related-data/Action scenarios.
- Refine compares interaction axes independently.
- Handoff reports interaction scope and verification level.

- [ ] **Step 4: Run GREEN**

Run: `uv run --frozen pytest -q tests/unit/skill tests/e2e/test_fastapi_crm_example.py`

- [ ] **Step 5: Commit**

```bash
git add skills/acc-engineer examples/fastapi-crm/acc-project tests/unit/skill tests/e2e/test_fastapi_crm_example.py
git commit -m "feat(skill): 将前端交互证据纳入 ACC 流程"
```

### Task 11: Cross-industry conformance fixtures and release gates

**Files:**
- Create: `tests/fixtures/interactions/crm/`
- Create: `tests/fixtures/interactions/erp/`
- Create: `tests/fixtures/interactions/finance/`
- Create: `tests/fixtures/interactions/monitoring/`
- Create: `tests/fixtures/interactions/cms/`
- Create: `tests/fixtures/interactions/permissions/`
- Create: `tests/fixtures/interactions/mobile/`
- Create: `tests/e2e/test_interaction_contract_profiles.py`
- Modify: `README.md`
- Modify: `docs/progress.md`
- Modify: `docs/architecture/adr/007-versioned-quality-and-action-safety.md`

- [ ] **Step 1: Add fixture-driven E2E tests**

Each fixture proves one distinct contract: CRM list/detail, ERP defaults/options/concurrency, finance independent filters, monitoring refresh/stale, CMS long-text projection, permissions identity-scoped options, and mobile cascades. The Action fixture must use preview/approve/commit/status and never a direct mutation Tool.

- [ ] **Step 2: Run focused E2E**

Run: `uv run --frozen pytest -q tests/e2e/test_interaction_contract_profiles.py`

Expected: all profiles pass and no framework/product name is required by Core models.

- [ ] **Step 3: Update public documentation**

Document the authority split, new files, audit order, verification labels, Runtime non-UI boundary, and the fact that source-connected does not imply client-adapter verification.

- [ ] **Step 4: Run complete release gates**

```bash
uv lock --check
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts
uv run --frozen pytest -q
```

Regenerate schemas to a temporary directory and compare with `schemas/`. Validate, compile, cover, and pack the CRM example twice; require identical SHA-256 digests. Run scans confirming no secret values, arbitrary client expressions, framework-specific Core imports, or source-system writes.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/interactions tests/e2e/test_interaction_contract_profiles.py README.md docs
git commit -m "feat: 完成通用前端交互合同闭环"
```

## Final acceptance checklist

- [ ] UI and route denominators are independent and closed.
- [ ] Every adopted default, option, condition, relation, presentation field, and state has typed Evidence or remains explicitly unknown.
- [ ] Capability public inputs are constructible; trusted inputs remain non-public.
- [ ] Frontend hidden/disabled state never grants authorization.
- [ ] Interaction conditions are bounded AST values, not executable code.
- [ ] Headless, source-connected, and real-client verification labels remain independent.
- [ ] Read and Action security behavior remains fail-closed.
- [ ] Core contains no Vue, React, Angular, Flutter, mobile platform, or product-specific branch.
- [ ] Source workspaces remain unchanged.
