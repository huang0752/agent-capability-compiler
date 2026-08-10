# Quality Contract and Coverage v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add evidence-backed schema fidelity, constructible capability planning, multi-axis coverage, output budgets, and a non-fabricating v1-to-v2 migration path.

**Architecture:** Project v2 adds separate SourceContract and CapabilityQuality documents without polluting standard JSON Schema. Core compiles verified summaries into IR/Pack v2; Runtime consumes only enforcement metadata. Project/IR/Pack v1 remain behaviorally compatible.

**Tech Stack:** Python 3.12, Pydantic v2, JSON Schema Draft 2020-12, Typer, pytest, deterministic ZIP packaging.

---

### Task 1: Add SourceContract and schema-provenance models

**Files:**
- Create: `packages/acc-core/src/acc_core/contracts/models.py`
- Create: `packages/acc-core/src/acc_core/contracts/__init__.py`
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Test: `tests/unit/core/test_source_contract_models.py`

- [ ] **Step 1: Write failing strict-model tests**

Cover invalid pointers, duplicate claims, missing targets, recursive schemas, all four authority levels and stable schema export.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/core/test_source_contract_models.py`

Expected: missing `acc_core.contracts`.

- [ ] **Step 3: Implement the public models**

```python
class SchemaProvenance(StrictModel):
    target_pointer: JsonPointer
    evidence: Evidence
    evidence_schema_pointer: JsonPointer
    authority: Literal["contract", "implementation", "test", "observation"]

class SourceContract(StrictModel):
    schema_version: Literal["2"]
    id: NonEmptyString
    operation_id: NonEmptyString
    request_schema: JsonObject
    response_schema: JsonObject
    request_completeness: Literal["complete", "partial", "unknown"]
    response_completeness: Literal["complete", "partial", "unknown"]
    provenance: list[SchemaProvenance]
```

Model validation resolves each target pointer against request or response schema and rejects duplicate claim identities.

- [ ] **Step 4: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_source_contract_models.py tests/unit/core/test_models.py`

### Task 2: Add CapabilityQuality and Project v2 models

**Files:**
- Create: `packages/acc-core/src/acc_core/quality/models.py`
- Create: `packages/acc-core/src/acc_core/quality/__init__.py`
- Modify: `packages/acc-core/src/acc_core/models/__init__.py`
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Test: `tests/unit/core/test_capability_quality_models.py`

- [ ] **Step 1: Write failing model tests**

Cover selector acquisition consistency, producer IDs, output budget bounds, long-text acknowledgement, v1-with-quality rejection, and v2-without-profile rejection.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/core/test_capability_quality_models.py`

- [ ] **Step 3: Implement the v2 sidecar contract**

```python
class CapabilityInputQuality(StrictModel):
    kind: Literal["query", "filter", "resource_selector", "trusted_context", "literal"]
    resource_type: NonEmptyString | None = None
    acquisition: Literal[
        "caller", "trusted_context", "default", "upstream_step", "capability_output"
    ]
    producers: list[NonEmptyString] = Field(default_factory=list)

class OutputBudget(StrictModel):
    max_bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    long_text_disclosures: list[LongTextDisclosure] = Field(default_factory=list)

class CapabilityQuality(StrictModel):
    schema_version: Literal["2"]
    capability_id: NonEmptyString
    intent: CapabilityIntent
    inputs: dict[NonEmptyString, CapabilityInputQuality]
    composition: CompositionQuality
    output_budget: OutputBudget
```

Project v1 may not declare v2 quality configuration; Project v2 must select `standard` or `release` profile.

- [ ] **Step 4: Verify GREEN and v1 compatibility**

Run: `uv run --frozen pytest -q tests/unit/core/test_capability_quality_models.py tests/unit/core/test_models.py`

### Task 3: Load and close v2 project sidecars

**Files:**
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/core/test_project_validation.py`
- Test: `tests/unit/core/test_cli.py`

- [ ] **Step 1: Write failing missing/duplicate/orphan tests**
- [ ] **Step 2: Run `uv run --frozen pytest -q tests/unit/core/test_project_validation.py -k 'source_contract or capability_quality or version_two'` and confirm RED**
- [ ] **Step 3: Extend `ValidationReport` with typed sidecar maps and paths**
- [ ] **Step 4: Require exactly one SourceContract per Operation and one CapabilityQuality per Capability in v2**
- [ ] **Step 5: Require provenance Evidence identity to match the corresponding Operation Evidence**
- [ ] **Step 6: Re-run focused tests and confirm GREEN; v1 without sidecar directories remains valid**

Stable diagnostics are `ACC_SOURCE_CONTRACT_MISSING/DUPLICATE/ORPHAN`, `ACC_CAPABILITY_QUALITY_MISSING/DUPLICATE/ORPHAN`, and `ACC_SCHEMA_PROVENANCE_EVIDENCE_MISMATCH`.

### Task 4: Implement conservative schema-fidelity comparison

**Files:**
- Create: `packages/acc-core/src/acc_core/contracts/schema_relation.py`
- Create: `packages/acc-core/src/acc_core/contracts/fidelity.py`
- Test: `tests/unit/compiler/test_schema_fidelity.py`

- [ ] **Step 1: Write failing directionality tests**

The mandatory regression is: source permissions array has no `maxItems`; Operation declares `maxItems: 100`; output comparison must report narrower-than-evidence. Also cover input direction, observation-as-bound, recursion and unknown combinations.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_schema_fidelity.py`

- [ ] **Step 3: Implement tri-state relations**

```python
class SchemaRelation(StrEnum):
    PROVEN = "proven"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"

def compare_operation_input(declared: JsonObject, source: JsonObject) -> RelationReport:
    """Prove declared_request is a subset of source_accepted."""

def compare_operation_output(source: JsonObject, declared: JsonObject) -> RelationReport:
    """Prove source_possible is a subset of declared_output."""
```

Support only sound rules for type, required, enum/const, numeric/string/array bounds, items, properties, additionalProperties, local refs and safely decidable combinations. Use visited schema pairs for recursion. Never convert unknown to pass.

- [ ] **Step 4: Bind restrictive keywords to provenance**

Observation cannot prove upper bounds. Emit `ACC_SCHEMA_CONSTRAINT_PROVENANCE_MISSING`, `ACC_SCHEMA_OUTPUT_NARROWER_THAN_EVIDENCE`, `ACC_SCHEMA_EVIDENCE_COMPARISON_UNKNOWN`, or `ACC_SCHEMA_OBSERVATION_USED_AS_BOUND`.

- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_schema_fidelity.py`

### Task 5: Analyze constructability and composition

**Files:**
- Create: `packages/acc-core/src/acc_core/quality/graph.py`
- Create: `packages/acc-core/src/acc_core/quality/analyze.py`
- Test: `tests/unit/compiler/test_capability_quality.py`

- [ ] **Step 1: Write failing cross-domain fixtures**

CRM search→detail must be reachable; detail-only customer ID must be a dead end; ERP calls sharing order ID are a valid aggregate; finance calls with unrelated IDs report independent fan-in; single-job monitor is valid; compare permits two same-type IDs with justification; list followed by mandatory detail must retain an empty-success path.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_capability_quality.py`

- [ ] **Step 3: Implement workflow and ecosystem graphs**

Represent workflow calls as nodes, step-output references as data edges, shared agent selectors as anchors, and producer Capability outputs as ecosystem discovery edges. Entrypoints have no required selector or only query/filter/default/trusted-context inputs.

- [ ] **Step 4: Emit deterministic findings**

Use `ACC_CAPABILITY_REQUIRED_SELECTOR_UNDISCOVERABLE`, `ACC_CAPABILITY_INDEPENDENT_CALL_FANIN`, `ACC_CAPABILITY_LIST_DETAIL_COUPLED`, `ACC_CAPABILITY_OPERATION_BUDGET_EXCEEDED`, `ACC_CAPABILITY_EMPTY_SUCCESS_PATH_MISSING`, and `ACC_COVERAGE_DISCOVERY_DEAD_END`.

- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_capability_quality.py`

### Task 6: Estimate output size without fabricating bounds

**Files:**
- Create: `packages/acc-core/src/acc_core/quality/output_size.py`
- Test: `tests/unit/compiler/test_output_size.py`

- [ ] **Step 1: Write failing bounded/unknown tests**

Include unbounded permission arrays, bounded arrays of objects, recursive schemas, Unicode strings, 129 KiB output against a 64 KiB budget, and unacknowledged prompt content.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_output_size.py`

- [ ] **Step 3: Implement a conservative estimator**

```python
@dataclass(frozen=True)
class OutputSizeEstimate:
    status: Literal["proven_bounded", "unknown"]
    max_bytes: int | None
    unknown_pointers: tuple[str, ...]
```

Open objects, missing maxLength/maxItems, unbounded recursion and undecidable combinations return unknown. Estimation uses the same canonical compact UTF-8 JSON convention as Runtime.

- [ ] **Step 4: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_output_size.py`

### Task 7: Orchestrate quality gates and compile IR v2

**Files:**
- Create: `packages/acc-core/src/acc_core/quality/report.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/compiler/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/compiler/test_quality_gate.py`
- Test: `tests/unit/compiler/test_compiler.py`

- [ ] **Step 1: Write failing profile and IR-version tests**
- [ ] **Step 2: Confirm RED with `uv run --frozen pytest -q tests/unit/compiler/test_quality_gate.py`**
- [ ] **Step 3: Implement `legacy-audit`, `standard`, and `release` severity profiles**
- [ ] **Step 4: Add `acc quality PROJECT --profile ... --json`**
- [ ] **Step 5: Keep v1 compiler bytes stable and emit IR v2 only for Project v2**

IR v2 stores selector/output enforcement summaries and sidecar digests beside Capability definitions; it does not carry raw Evidence content.

- [ ] **Step 6: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_quality_gate.py tests/unit/compiler/test_compiler.py tests/unit/core/test_cli.py -k 'quality or ir_version or legacy'`

### Task 8: Produce multi-axis Coverage v2

**Files:**
- Modify: `packages/acc-core/src/acc_core/coverage/analyze.py`
- Modify: `packages/acc-core/src/acc_core/coverage/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/compiler/test_analysis_tools.py`
- Test: `tests/integration/test_cli_milestone2.py`

- [ ] **Step 1: Write failing v1-compatibility and v2-axis tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Preserve `analyze_coverage_v1()` exact output and add `analyze_coverage_v2()`**

V2 returns operation trace, scenario coverage, constructability, discoverability graph, composition, schema fidelity, output budget and live observations as independent objects. It does not emit a single aggregate score, and a valuable single-operation Capability is not automatically a risk.

Before wiring route disposition, promote the platform-neutral part of `scope-inventory.yaml` into Core:

- Create `packages/acc-core/src/acc_core/scope/models.py`, `packages/acc-core/src/acc_core/scope/analyze.py`, and `packages/acc-core/src/acc_core/scope/__init__.py`.
- Add `tests/unit/core/test_scope_models.py`.
- Make `skills/acc-engineer/scripts/scope_audit.py` consume the Core model while preserving its existing JSON diagnostics.
- Let `ValidationReport` optionally load the typed inventory so Coverage v2 owns the route-disposition axis rather than linking to a second parser.

- [ ] **Step 4: Add `coverage --version {1,2}` with project-version default**
- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_analysis_tools.py tests/integration/test_cli_milestone2.py -k coverage`

### Task 9: Add Pack/Loader v2 compatibility

**Files:**
- Modify: `packages/acc-core/src/acc_core/packaging/pack.py`
- Modify: `packages/acc-runtime/src/acc_runtime/loader/__init__.py`
- Test: `tests/integration/pack/test_pack.py`
- Create: `tests/unit/runtime/test_loader_versions.py`

- [ ] **Step 1: Write failing v1/v2/cross-version tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Implement version-aware member allowlists and manifest/lock/IR agreement**
- [ ] **Step 4: Assert v1 pack digest fixture remains unchanged and v2 builds deterministically**
- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/integration/pack/test_pack.py tests/unit/runtime/test_loader_versions.py`

### Task 10: Enforce Capability output budgets at Runtime

**Files:**
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/errors/__init__.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/audit.py`
- Test: `tests/unit/runtime/test_runtime.py`
- Test: `tests/unit/runtime/gateway/test_audit.py`

- [ ] **Step 1: Write failing boundary, Unicode and secret-leak tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: After Policy filtering and output-schema validation, count canonical compact UTF-8 bytes**
- [ ] **Step 4: Raise `ACC_RUNTIME_CAPABILITY_OUTPUT_TOO_LARGE` with only capability ID and byte counts**
- [ ] **Step 5: Record optional `output_bytes` in audit metadata without payload**
- [ ] **Step 6: Verify GREEN across stdio and Gateway**

Run: `uv run --frozen pytest -q tests/unit/runtime/test_runtime.py tests/unit/runtime/gateway/test_audit.py tests/e2e/test_generic_auth_stdio.py tests/e2e/test_multi_user_http_gateway.py -k 'output_budget or output_bytes or legacy_v1'`

### Task 11: Add non-fabricating migration and cross-industry fixtures

**Files:**
- Create: `packages/acc-core/src/acc_core/migration/v1_to_v2.py`
- Create: `packages/acc-core/src/acc_core/migration/__init__.py`
- Create: `tests/unit/core/test_migration_v2.py`
- Create: `tests/fixtures/quality/`
- Create: `tests/e2e/test_quality_profiles.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/02-analyze.md`
- Modify: `skills/acc-engineer/guides/03-model.md`
- Modify: `skills/acc-engineer/guides/04-plan.md`
- Modify: `skills/acc-engineer/guides/05-implement.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/08-refine.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Test: `tests/unit/skill/test_skill_structure.py`

- [ ] **Step 1: Write failing check/write atomicity and no-placeholder tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Implement `acc migrate --to 2 --check|--write`**

Check mode never writes. Write mode succeeds only when complete sidecars already exist; it never invents provenance, maxItems, maxLength or placeholder Evidence. Failure leaves the project byte-for-byte unchanged.

- [ ] **Step 4: Add CRM, ERP, monitoring, finance, CMS/LLM, permissions and recursive-schema fixtures**
- [ ] **Step 5: Update Skill language to distinguish evidence-faithful Operation schemas from minimum-disclosure Capability projections**
- [ ] **Step 6: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_migration_v2.py tests/unit/skill/test_skill_structure.py tests/e2e/test_quality_profiles.py`

### Task 12: Run the quality-contract release gate

- [ ] **Step 1: Run formatting, lint, types and full tests**

```bash
uv lock --check
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts
uv run --frozen pytest -q
```

- [ ] **Step 2: Export schemas and validate v1/v2 fixtures**

Run `acc schema`, `acc validate`, `acc quality`, `acc compile --check`, and `acc coverage` for representative v1 and v2 projects.

- [ ] **Step 3: Build each fixture twice and compare SHA-256**

Expected: v1 behavior remains compatible; v2 Pack builds are reproducible; no diagnostic is hidden or converted from unknown into pass.
