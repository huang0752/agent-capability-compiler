# Action MCP End-to-End Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose compiler-proven business Actions through a safe MCP/Gateway prepare → external approval → commit → status lifecycle and generate evidence-bound baogao-jin Action capabilities without executing real source mutations.

**Architecture:** Read capabilities remain ordinary MCP tools. Each Action capability is exposed only as a business-specific prepare tool; opaque lifecycle handles are consumed by generic approve, commit, and status tools. `ActionCoordinator` remains the sole mutation authority, Gateway request authentication supplies `PrincipalContext`, and production composition fails closed unless the operator injects an Action Store, ApprovalAuthority, audit sink, effect/risk ceiling, and identity salt.

**Tech Stack:** Python 3.12+, Pydantic, official MCP Python SDK, Starlette Streamable HTTP, httpx, pytest, Ruff, mypy.

**Implemented:** 2026-08-10. The public lifecycle was kept in the existing MCP server module instead of introducing a second adapter module. Gateway composition now derives the Coordinator from loaded IR and the shared Provider via `actions/runtime.py`; official SDK coverage lives in `tests/integration/runtime/test_action_mcp_gateway.py`. The baogao-jin candidate contains 110 Read capabilities plus three evidence-bound finance void Actions and an offline compiled-IR lifecycle test. Production durable Store, approval issuer, and audit backends remain deployment integrations rather than built-in implementations.

---

### Task 1: Public Action lifecycle projection

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/mcp/actions.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/__init__.py`
- Test: `tests/unit/runtime/test_mcp_actions.py`

- [ ] Write RED tests proving Action capabilities are absent from ordinary read calls but appear as `<capability>.prepare` tools with the Capability input Schema and safe MCP annotations.
- [ ] Add RED tests for `acc.action.approve`, `acc.action.commit`, and `acc.action.status`, including reserved identity argument rejection and data-free structured errors.
- [ ] Implement an `ActionLifecycleRuntime` protocol with `action_tools()`, `prepare_action()`, `approve_action()`, `commit_action()`, and `action_status()` methods.
- [ ] Serialize `SecretValue` handles only at the final MCP response boundary; never place them in repr, logs, exceptions, tool schemas, or audit events.
- [ ] Run `uv run pytest -q tests/unit/runtime/test_mcp_actions.py tests/unit/runtime/test_mcp.py` and verify GREEN.

### Task 2: Verified Action runtime composition

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/actions/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/actions/__init__.py`
- Test: `tests/unit/runtime/actions/test_action_runtime.py`

- [ ] Write RED tests that load definitions only from compiler-attested IR and reject missing/tampered proof or action semantics before preview.
- [ ] Build `RuntimeActionLifecycle` from `RuntimeActionWorkflowExecutor` and `ActionCoordinator`; derive every `CompiledActionDefinition` through `verified_definition()`.
- [ ] Require an operator-owned `DeploymentPolicy`, `ActionStore`, `ApprovalAuthority`, Action audit sink, and audit salt; preserve the existing durable-store and required-audit fail-closed gates.
- [ ] Convert coordinator dataclasses to minimal JSON results with `capability_id`, `status`, `preview/result`, `approval_required`, `expires_at`, and `replayed` only.
- [ ] Run `uv run pytest -q tests/unit/runtime/actions` and verify GREEN.

### Task 3: Gateway multi-user Action wiring

**Files:**
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/models.py`
- Test: `tests/unit/runtime/gateway/test_gateway_runtime.py`
- Test: `tests/integration/runtime/test_gateway_http.py`

- [ ] Write RED tests showing an Action Pack fails startup without explicit Action deployment dependencies.
- [ ] Extend `create_gateway_runtime()` with optional Action deployment dependencies; reject partial configuration and keep a read-only Pack unchanged.
- [ ] Wrap the existing contextual Runtime and Action lifecycle behind one Principal MCP runtime so every lifecycle call resolves the bearer session Principal.
- [ ] Verify A cannot approve, commit, or query B's action handle; logout and expired sessions cannot continue lifecycle calls.
- [ ] Keep production default deny: no automatic `allowed_effects`, no implicit maximum risk widening, and no in-memory Store/Authority in normal Gateway composition.

### Task 4: Official MCP SDK transport verification

**Files:**
- Create: `tests/e2e/test_action_mcp_gateway.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/streamable_http.py` only if a reusable safe helper is required.

- [ ] Create a compiler-valid Action fixture with one read preview and one mutation operation over an httpx MockTransport.
- [ ] Using official `mcp.ClientSession`, execute initialize → tools/list → prepare → external test approval issuance → approve → commit → status.
- [ ] Assert one mutation call, stable idempotent replay, optimistic concurrency propagation, output Schema validation, and Action annotations.
- [ ] Assert cross-session owner rejection, action-handle binding rejection, source 401 behavior, cancellation safety, and absence of business payloads/secrets in traces and audit events.
- [ ] Run `uv run pytest -q tests/e2e/test_action_mcp_gateway.py tests/e2e/test_multi_user_http_gateway.py` and verify GREEN.

### Task 5: Evidence-bound baogao-jin business Actions

**Files:**
- Modify: `/Users/chou/code/baogao-jin-acc/tools/generate_current_project.py`
- Create: `/Users/chou/code/baogao-jin-acc/tests/test_generated_actions.py`
- Regenerate: `/Users/chou/code/baogao-jin-acc/operations/*.yaml`
- Regenerate: `/Users/chou/code/baogao-jin-acc/source-contracts/*.yaml`
- Regenerate: `/Users/chou/code/baogao-jin-acc/capabilities/*.yaml`
- Regenerate: `/Users/chou/code/baogao-jin-acc/capability-quality/*.yaml`
- Regenerate: `/Users/chou/code/baogao-jin-acc/policies/*.yaml`
- Regenerate: `/Users/chou/code/baogao-jin-acc/evals/*.yaml`

- [ ] Select only source routes whose effect, risk, idempotency, concurrency, retry, preview, and status semantics are proven by source implementation or tests.
- [ ] Generate ActionOperation and SourceContract action semantics with exact Evidence digest and authority; do not infer safety solely from POST/PUT/PATCH/DELETE.
- [ ] Generate ActionCapability with read-only preview workflow and exactly one compiler-proven mutation path using `$.prepared.input`/`$.prepared.preview` only.
- [ ] Generate negative Evals for scope denial, missing approval, stale concurrency, cross-principal handle use, and idempotent replay without calling baogao-jin.
- [ ] Keep all unproven mutations excluded with exact reasons.

### Task 6: Final gates and handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/progress.md`
- Modify: `/Users/chou/code/baogao-jin-acc/HANDOFF.md`
- Modify: `/Users/chou/code/baogao-jin-acc/test-report.json`
- Modify: `/Users/chou/code/baogao-jin-acc/risk-report.json`

- [ ] Run focused Action unit/integration/E2E tests, then full Ruff format/check and mypy for changed packages.
- [ ] Run `uv run pytest -q` and record the exact result.
- [ ] Run baogao-jin ACC validate, compile, coverage, contract, runtime, and E2E tests without starting or mutating the source system.
- [ ] Build two Packs and assert byte-identical SHA-256 digests.
- [ ] Scan Pack/project output for credentials and re-check `/Users/chou/code/baogao-jin` status.
- [ ] Commit only ACC repository changes with a narrow Chinese Conventional Commit; do not push.
