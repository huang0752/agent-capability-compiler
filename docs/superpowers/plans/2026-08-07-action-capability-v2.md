# Action Capability v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add evidence-bound business actions with explicit deployment authorization, prepare/approve/commit lifecycle, idempotency, optimistic concurrency, safe retries, durable state boundaries, and multi-user isolation while keeping every v1 Pack read-only.

**Architecture:** Project/Operation/Capability/IR/Pack v2 introduce strict read/action discriminated models. A transport-neutral ActionCoordinator owns lifecycle and state; HttpProvider executes compiled request contracts; Gateway/MCP expose only safe public handles. DeploymentPolicy defaults to read-only and is intersected with user scope and approvals.

**Tech Stack:** Python 3.12, Pydantic v2, httpx, MCP Python SDK 1.x, pytest, deterministic Pack format.

---

### Task 1: Introduce strict v1/v2 model dispatch

**Files:**
- Create: `packages/acc-core/src/acc_core/models/v1.py`
- Create: `packages/acc-core/src/acc_core/models/v2.py`
- Create: `packages/acc-core/src/acc_core/models/actions.py`
- Modify: `packages/acc-core/src/acc_core/models/__init__.py`
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Test: `tests/unit/core/test_action_models.py`
- Test: `tests/unit/core/test_action_schema_export.py`

- [ ] **Step 1: Write failing version-dispatch tests**

Assert v1 still rejects write methods; v2 explicitly distinguishes read and action; a project cannot mix incompatible document versions; exported v1 and v2 schemas are distinct and stable.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/core/test_action_models.py tests/unit/core/test_action_schema_export.py`

- [ ] **Step 3: Implement public effect and risk types**

```python
type Effect = Literal["read", "create", "update", "delete", "transition", "execute"]
type Risk = Literal["low", "medium", "high", "critical"]
type Reversibility = Literal["reversible", "compensatable", "irreversible", "unknown"]
type ExecutionMode = Literal["single", "source_transaction", "saga"]
```

Version dispatch occurs before parsing a concrete document. Do not make one broad Pydantic model accept both versions.

- [ ] **Step 4: Implement Operation v2 HTTP contracts**

Support JSON request bodies, explicit success statuses, `json|empty|json_or_empty` responses, bounded request bytes, idempotency injection, concurrency preconditions and forbidden-header validation. GET/HEAD remain read-only; unsafe methods declared read require explicit evidence classification.

- [ ] **Step 5: Verify GREEN and v1 compatibility**

Run: `uv run --frozen pytest -q tests/unit/core/test_action_models.py tests/unit/core/test_action_schema_export.py tests/unit/core/test_models.py`

### Task 2: Add ActionCapability v2 and compiler proofs

**Files:**
- Create: `packages/acc-core/src/acc_core/compiler/actions.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Test: `tests/unit/compiler/test_action_compiler.py`
- Test: `tests/unit/core/test_action_project_validation.py`

- [ ] **Step 1: Write failing safety-proof tests**

Preview using a mutation fails; risk/effect under-reporting fails; zero or multiple commit mutations fail; mutation inside parallel/foreach fails; missing approval/idempotency/concurrency contracts fail; prepared bindings exposed as public input fail; one legal single-action fixture compiles deterministically.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_action_compiler.py tests/unit/core/test_action_project_validation.py`

- [ ] **Step 3: Implement the Action capability contract**

```python
class ActionCapabilityV2(StrictModel):
    schema_version: Literal["2"]
    kind: Literal["action"]
    id: NonEmptyString
    input_schema: JsonObject
    output_schema: JsonObject
    action: ActionContract
    preview_workflow: Annotated[list[WorkflowStep], Field(min_length=1)]
    commit_workflow: Annotated[list[WorkflowStep], Field(min_length=1)]
    policy: NonEmptyString
    evals: Annotated[list[NonEmptyString], Field(min_length=1)]
```

Compiler derives effects, maximum risk, scopes and approval requirements from commit dependencies. It never trusts lower values handwritten on the Capability.

- [ ] **Step 4: Compile an action inventory and deployment matrix into IR v2**
- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_action_compiler.py tests/unit/compiler/test_compiler.py`

### Task 3: Package and load Action Pack v2 safely

**Files:**
- Modify: `packages/acc-core/src/acc_core/packaging/pack.py`
- Modify: `packages/acc-runtime/src/acc_runtime/loader/__init__.py`
- Create: `tests/integration/pack/test_pack_v2_actions.py`

- [ ] **Step 1: Write failing format and compatibility tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Require manifest, lock, IR and contract versions to agree**
- [ ] **Step 4: Make current Runtime load v1/v2 and make v1-only code reject v2 before reading executable IR**
- [ ] **Step 5: Build the same v2 Pack twice and compare digests; reassert a fixed v1 golden Pack**

Run: `uv run --frozen pytest -q tests/integration/pack/test_pack_v2_actions.py tests/integration/pack/test_pack.py`

### Task 4: Execute action-aware HTTP contracts without unsafe replay

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/providers/results.py`
- Modify: `packages/acc-runtime/src/acc_runtime/providers/http.py`
- Modify: `packages/acc-runtime/src/acc_runtime/errors/__init__.py`
- Test: `tests/unit/runtime/test_http_actions.py`

- [ ] **Step 1: Write failing body/status/header/retry tests**

Cover JSON body and size, 201/202/204, Runtime-injected Idempotency-Key and If-Match, sensitive-header rejection, 409/412 conflict, send-then-disconnect outcome unknown, mutation no replay, and unchanged read 401 refresh behavior.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/runtime/test_http_actions.py`

- [ ] **Step 3: Return internal execution metadata**

```python
@dataclass(frozen=True)
class OperationExecutionResult:
    value: JsonValue
    status_code: int
    selected_headers: Mapping[str, str]
```

Normal workflows only receive `value`; ActionCoordinator alone receives compiled selected headers. Agent inputs cannot control Authorization, Cookie, Host, Content-Length, idempotency or concurrency headers.

- [ ] **Step 4: Separate authentication refresh from mutation replay**

If a mutation may have reached the source and no source idempotency contract proves safe recovery, return `ACC_RUNTIME_ACTION_OUTCOME_UNKNOWN` and do not retry.

- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/runtime/test_http_actions.py tests/unit/runtime/test_http_auth.py`

### Task 5: Implement ActionCoordinator and state model

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/actions/models.py`
- Create: `packages/acc-runtime/src/acc_runtime/actions/store.py`
- Create: `packages/acc-runtime/src/acc_runtime/actions/approval.py`
- Create: `packages/acc-runtime/src/acc_runtime/actions/errors.py`
- Create: `packages/acc-runtime/src/acc_runtime/actions/coordinator.py`
- Create: `packages/acc-runtime/src/acc_runtime/actions/__init__.py`
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/execution/executor.py`
- Test: `tests/unit/runtime/actions/test_coordinator.py`
- Test: `tests/unit/runtime/actions/test_store.py`
- Test: `tests/unit/runtime/actions/test_approval.py`
- Test: `tests/unit/runtime/actions/test_concurrency.py`
- Test: `tests/unit/runtime/actions/test_idempotency.py`

- [ ] **Step 1: Write failing lifecycle and isolation tests**

Prepare has no side effect; approval binds the exact action digest; A cannot approve/commit B; session/tenant/Pack/input changes invalidate handles; expiry/replay/repeated commit are stable; conflict and outcome unknown remain distinct; cancellation and tracebacks contain no secrets.

- [ ] **Step 2: Verify RED**

Run: `uv run --frozen pytest -q tests/unit/runtime/actions`

- [ ] **Step 3: Implement the public coordinator API**

```python
class ActionCoordinator:
    async def prepare(self, capability_id, arguments, principal_context) -> PreparedActionPublic: ...
    async def approve(self, action_handle, approval_handle, authority_context) -> ActionStatus: ...
    async def commit(self, action_handle, principal_context) -> ActionResult: ...
    async def status(self, action_handle, principal_context) -> ActionStatus: ...
```

State transitions are `PREPARED → APPROVED → COMMITTING → SUCCEEDED|FAILED|OUTCOME_UNKNOWN`, with terminal `EXPIRED`. Store raw action state only on the trusted side; public handles are random and stored by digest.

- [ ] **Step 4: Define durable-store boundary**

In-memory Store is explicitly development/test only. Production Gateway deployment with Action enabled requires a durable Store contract; no built-in database or control plane is introduced.

- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/runtime/actions`

### Task 6: Add DeploymentPolicy and two-time authorization

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/deployment.py`
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Test: `tests/unit/runtime/test_deployment_policy.py`

- [ ] **Step 1: Write failing default-deny tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Implement immutable DeploymentPolicy**

```python
@dataclass(frozen=True)
class DeploymentPolicy:
    allowed_effects: frozenset[Effect] = frozenset({"read"})
    max_risk: Risk = "low"
    capability_allowlist: frozenset[str] | None = None
    require_durable_action_store: bool = True
    action_audit_mode: Literal["required", "best_effort"] = "required"
```

Check policy and effective scopes during both prepare and commit. Pack declarations never mutate this policy.

- [ ] **Step 4: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/runtime/test_deployment_policy.py tests/unit/runtime/test_runtime.py`

### Task 7: Expose safe Action semantics through Gateway and MCP

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/gateway/actions.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/service.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/models.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/audit.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Test: `tests/unit/runtime/gateway/test_action_policy.py`
- Test: `tests/unit/runtime/gateway/test_action_sessions.py`
- Test: `tests/unit/runtime/gateway/test_action_audit.py`
- Test: `tests/unit/runtime/test_mcp_actions.py`
- Test: `tests/integration/runtime/test_gateway_actions.py`

- [ ] **Step 1: Write failing listing, lifecycle and secret-boundary tests**

Default deployment only lists/executes read; allowed effect/risk/allowlist gates tools; Action prepare/commit/status is session-bound; logout expires pending actions; action/approval handles never appear in business input schemas, logs or exceptions; commit rechecks scope/effect.

- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Route every transport through one ActionCoordinator**
- [ ] **Step 4: Keep approval handles outside MCP business arguments**

Where host elicitation exists it invokes the trusted approval adapter; otherwise the public result returns `approval_required` plus an action handle and safe preview, and status is queried separately.

- [ ] **Step 5: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/runtime/gateway/test_action_policy.py tests/unit/runtime/gateway/test_action_sessions.py tests/unit/runtime/gateway/test_action_audit.py tests/unit/runtime/test_mcp_actions.py tests/integration/runtime/test_gateway_actions.py`

### Task 8: Add explicit CLI deployment and sandbox gates

**Files:**
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/core/test_cli_actions.py`

- [ ] **Step 1: Write failing default, explicit and invalid-combination tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Add `--allow-effect`, `--max-risk`, and repeatable `--allow-capability`**
- [ ] **Step 4: Emit per-tool scope/effect/risk/approval availability in `acc run --json`**
- [ ] **Step 5: Reject Action Gateway without required durable Store/audit configuration**
- [ ] **Step 6: Add `acc test action-sandbox ... --allow-source-write` with explicit sandbox profile and no production default**
- [ ] **Step 7: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/core/test_cli_actions.py`

### Task 9: Extend Testkit with stateful Action evidence

**Files:**
- Create: `packages/acc-testkit/src/acc_testkit/actions/`
- Modify: `packages/acc-testkit/src/acc_testkit/fake_system/system.py`
- Modify: `packages/acc-testkit/src/acc_testkit/recording.py`
- Test: `tests/unit/testkit/test_stateful_actions.py`
- Test: `tests/unit/testkit/test_action_assertions.py`
- Test: `tests/unit/testkit/test_action_redaction.py`
- Test: `tests/e2e/test_multi_user_gateway_actions.py`

- [ ] **Step 1: Write failing before/after, idempotency and concurrency tests**
- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Add stateful resources, request body/header capture, ETag/version, idempotency, 204, 409/412 and send-then-timeout faults**
- [ ] **Step 4: Add assertions for before → action → after → audit and repeated commit**
- [ ] **Step 5: Verify multi-user Gateway isolation and secret scans**

Run: `uv run --frozen pytest -q tests/unit/testkit/test_stateful_actions.py tests/unit/testkit/test_action_assertions.py tests/unit/testkit/test_action_redaction.py tests/e2e/test_multi_user_gateway_actions.py`

### Task 10: Define Adapter and Skill boundaries

**Files:**
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/01-preflight.md`
- Modify: `skills/acc-engineer/guides/02-analyze.md`
- Modify: `skills/acc-engineer/guides/03-model.md`
- Modify: `skills/acc-engineer/guides/04-plan.md`
- Modify: `skills/acc-engineer/guides/05-implement.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Test: `tests/unit/skill/test_skill_structure.py`

- [ ] **Step 1: Write failing Skill assertions**
- [ ] **Step 2: Keep default scope `system_readonly_complete`, but inventory all discovered effects**
- [ ] **Step 3: Require explicit user Action scope, transaction/permission/idempotency/concurrency Evidence, and sandbox before generating formal Actions**
- [ ] **Step 4: Report read and action coverage/verification separately and continue prohibiting production writes**
- [ ] **Step 5: Keep Adapter SDK v1 read-only until a v2 Action Adapter implements the same DeploymentPolicy and ActionCoordinator contracts; reject unsupported Action adapters explicitly**
- [ ] **Step 6: Verify GREEN**

Run: `uv run --frozen pytest -q tests/unit/skill/test_skill_structure.py tests/unit/adapter_sdk`

### Task 11: Add a platform-neutral Order action fixture

**Files:**
- Create: `tests/fixtures/actions/order-system/`
- Create: `tests/e2e/test_order_action_fixture.py`

- [ ] **Step 1: Write failing fixture acceptance**

The fixture contains read preview `GET /orders/{id}` and action `POST /orders/{id}/approve` with ETag and Idempotency-Key. Exercise prepare, external fake approval, commit, duplicate commit, 409/412, logout, outcome unknown and A/B isolation.

- [ ] **Step 2: Confirm RED**
- [ ] **Step 3: Implement only the generic fixture data and Pack v2 documents**
- [ ] **Step 4: Verify GREEN and ensure no production module contains fixture-specific IDs**

Run: `uv run --frozen pytest -q tests/e2e/test_order_action_fixture.py`

### Task 12: Run Action release gates

- [ ] **Step 1: Run focused Action suites and full v1 regression**
- [ ] **Step 2: Run Ruff, mypy and all pytest suites**
- [ ] **Step 3: Build v1 and v2 Packs twice and compare SHA-256**
- [ ] **Step 4: Scan Pack, MCP schemas, reports, repr, exceptions and audit for credentials and approval material**
- [ ] **Step 5: Verify default Runtime can execute v1 reads but cannot list or call an Action without explicit deployment authorization**

