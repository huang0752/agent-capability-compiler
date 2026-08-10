# Runtime Schema, Live Verification, and Scope Callability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make MCP schema projection correct for full JSON Schema resources, make Gateway verification truthful, and expose deployment-scope callability without broadening authorization.

**Architecture:** Core derives path-aware scope alternatives; Runtime owns a transport-neutral schema projector and callability analyzer; Testkit drives the official MCP SDK through a real Gateway. CLI reports the same structured diagnostics before serving.

**Tech Stack:** Python 3.12, Pydantic v2, jsonschema Draft 2020-12, official MCP Python SDK 1.x, httpx, pytest, Typer.

---

### Task 1: Add a resource-preserving MCP schema projector

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/mcp/schema_projection.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/server.py`
- Modify: `packages/acc-runtime/src/acc_runtime/mcp/__init__.py`
- Test: `tests/unit/runtime/test_mcp_schema_projection.py`

- [ ] **Step 1: Write failing projection tests**

Test no-ref wire compatibility, root `$defs`, `#/properties`, recursive refs, combinators, escaped pointers, nested/existing `$id`, and external relative refs. The public API exercised by every test is:

```python
projected = project_mcp_output_schema("crm.tree", source_schema)
Draft202012Validator.check_schema(projected)
Draft202012Validator(projected).validate({"result": instance})
```

- [ ] **Step 2: Verify RED**

Run: `uv run pytest -q tests/unit/runtime/test_mcp_schema_projection.py`

Expected: collection or import failure because `project_mcp_output_schema` does not exist.

- [ ] **Step 3: Implement the projector**

Implement one public function and private self-containment checks:

```python
def project_mcp_output_schema(tool_id: str, schema: Mapping[str, object]) -> dict[str, object]:
    embedded = copy.deepcopy(dict(schema))
    if _uses_root_relative_reference(embedded) and "$id" not in embedded:
        digest = hashlib.sha256(canonical_json_bytes(embedded)).hexdigest()
        embedded["$id"] = f"urn:acc:mcp-output:{quote(tool_id, safe='')}:{digest}"
    _reject_unresolved_external_relative_references(embedded)
    projected = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["result"],
        "properties": {"result": embedded},
    }
    Draft202012Validator.check_schema(projected)
    return projected
```

Do not inject `$id` when the schema has no root-relative refs, preserving simple tools/list snapshots.

- [ ] **Step 4: Route MCP tool translation through the projector**

Replace the inline wrapper in `CapabilityMcpServer._translate_tools()` with `project_mcp_output_schema(capability_id, output_schema)`. Both stdio and HTTP already use this server and therefore share the implementation.

- [ ] **Step 5: Verify GREEN and regressions**

Run:

```bash
uv run pytest -q tests/unit/runtime/test_mcp_schema_projection.py tests/unit/runtime/test_mcp.py tests/unit/runtime/gateway/test_mcp_context.py
```

Expected: all selected tests pass.

### Task 2: Verify projected schemas through official MCP clients

**Files:**
- Modify: `tests/integration/runtime/test_gateway_http.py`
- Create: `tests/e2e/test_mcp_schema_resources.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/stdio.py`
- Modify: `packages/acc-testkit/src/acc_testkit/mcp_client/streamable_http.py`

- [ ] **Step 1: Add failing stdio and Streamable HTTP cases**

Build the same recursive capability twice, call `list_tools()` and `call_tool()`, and assert the official SDK accepts structured content in both transports. The fixture must include `$defs`, a recursive child and an `anyOf` leaf.

- [ ] **Step 2: Verify RED against the pre-projector behavior**

Run: `uv run pytest -q tests/e2e/test_mcp_schema_resources.py`

Expected: the historical wrapper cannot resolve the root-local reference.

- [ ] **Step 3: Add Testkit output-schema validation helper**

Expose a helper that validates the result returned by the SDK against the exact schema returned by tools/list; it must not implement a second schema rewriting path.

- [ ] **Step 4: Verify both transports**

Run:

```bash
uv run pytest -q tests/e2e/test_mcp_schema_resources.py tests/integration/runtime/test_gateway_http.py
```

Expected: all selected tests pass.

### Task 3: Derive path-aware capability scope alternatives

**Files:**
- Create: `packages/acc-core/src/acc_core/compiler/scope_requirements.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/compiler/__init__.py`
- Test: `tests/unit/compiler/test_scope_requirements.py`

- [ ] **Step 1: Write failing analyzer tests**

Cover policy-only, operation-only, sequential union, parallel union, branch alternatives, nested branches and foreach. Assert antichain reduction removes strict supersets.

- [ ] **Step 2: Verify RED**

Run: `uv run pytest -q tests/unit/compiler/test_scope_requirements.py`

Expected: import failure for `analyze_scope_requirements`.

- [ ] **Step 3: Implement immutable requirements**

```python
@dataclass(frozen=True)
class ScopeRequirements:
    policy_always_required: frozenset[str]
    alternatives: tuple[frozenset[str], ...]
    all_referenced_scopes: frozenset[str]


def analyze_scope_requirements(
    capability: Capability,
    policy: Policy,
    operations: Mapping[str, Operation],
) -> ScopeRequirements:
    alternatives = _workflow_alternatives(capability.workflow, operations)
    alternatives = tuple(policy.required_scopes_set | item for item in alternatives)
    return ScopeRequirements(
        policy_always_required=frozenset(policy.required_scopes),
        alternatives=_minimal_antichain(alternatives),
        all_referenced_scopes=frozenset().union(*alternatives),
    )
```

Represent a potentially empty foreach conservatively instead of claiming its Operation scope is always required.

- [ ] **Step 4: Compile optional derived metadata**

Add stable `scope_requirements` to new IR output while retaining Runtime fallback calculation for old packs.

- [ ] **Step 5: Verify GREEN**

Run: `uv run pytest -q tests/unit/compiler/test_scope_requirements.py tests/unit/compiler/test_compiler.py`

Expected: all selected tests pass and golden output changes are intentional.

### Task 4: Add deployment callability diagnostics

**Files:**
- Create: `packages/acc-runtime/src/acc_runtime/callability.py`
- Modify: `packages/acc-runtime/src/acc_runtime/gateway/runtime.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/runtime/test_callability.py`
- Test: `tests/unit/core/test_cli.py`

- [ ] **Step 1: Write failing callability tests**

Expected states are `callable`, `conditional`, `denied`, and `unknown_until_login`. Assert deployment ceiling and user source-scope state remain separate.

- [ ] **Step 2: Verify RED**

Run: `uv run pytest -q tests/unit/runtime/test_callability.py`

Expected: missing callability module.

- [ ] **Step 3: Implement the pure analyzer**

```python
@dataclass(frozen=True)
class CapabilityCallability:
    capability_id: str
    deployment_status: Literal["callable", "conditional", "denied"]
    user_status: Literal["unknown_until_login", "callable", "denied"]
    required_scope_alternatives: tuple[tuple[str, ...], ...]
    missing_from_ceiling: tuple[str, ...]
```

The analyzer must never infer source scopes before login and must not mutate the ceiling.

- [ ] **Step 4: Add CLI diagnostics and strict mode**

Add `--strict-scope` and explicit `--scope-ceiling-from-pack`. The latter is mutually exclusive with `--scope`. JSON output includes `scope_analysis`; non-JSON service mode prints warnings before `uvicorn.run`. Strict mode maps definite uncallability to a stable configuration error.

- [ ] **Step 5: Verify GREEN and CLI compatibility**

Run:

```bash
uv run pytest -q tests/unit/runtime/test_callability.py tests/unit/core/test_cli.py
```

Expected: all selected tests pass; default no-scope behavior remains deny, now with diagnostics.

### Task 5: Add truthful Gateway live-test orchestration

**Files:**
- Create: `packages/acc-testkit/src/acc_testkit/live/models.py`
- Create: `packages/acc-testkit/src/acc_testkit/live/runner.py`
- Create: `packages/acc-testkit/src/acc_testkit/live/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `packages/acc-core/src/acc_core/evals/results.py`
- Test: `tests/unit/testkit/test_live_runner.py`
- Test: `tests/e2e/test_live_gateway_cli.py`

- [ ] **Step 1: Write failing profile and report tests**

Profile fields are account aliases with SecretRef names, required protocol probes and project-specific cases with non-secret inputs. Reports contain planned/executed/passed/failed/skipped counts, transport, pack fingerprint and validation level.

- [ ] **Step 2: Verify RED**

Run: `uv run pytest -q tests/unit/testkit/test_live_runner.py tests/e2e/test_live_gateway_cli.py`

Expected: missing live package and CLI command.

- [ ] **Step 3: Implement `LiveGatewayRunner`**

Reuse `McpStreamableHttpTestClient`; do not construct JSON-RPC manually. Mandatory probes cover session login, initialize, list, call, two-session isolation, cross-session 404 and logout 401. Unprovisioned source error scenarios remain skipped.

- [ ] **Step 4: Implement `acc test live`**

Require `--allow-source-connect`; default allow only loopback. Password values are read through SecretRef or secure prompt and must not appear in process arguments, repr, report or traceback.

- [ ] **Step 5: Verify GREEN**

Run:

```bash
uv run pytest -q tests/unit/testkit/test_live_runner.py tests/e2e/test_live_gateway_cli.py tests/e2e/test_multi_user_http_gateway.py
```

Expected: all selected tests pass and reports distinguish offline, Gateway-offline and source-connected levels.

### Task 6: Document and migrate verification labels

**Files:**
- Modify: `README.md`
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Test: `tests/unit/skill/test_skill_structure.py`

- [ ] **Step 1: Add failing structure assertions for the four validation levels**
- [ ] **Step 2: Run `uv run pytest -q tests/unit/skill/test_skill_structure.py` and confirm RED**
- [ ] **Step 3: Update Skill and templates to consume structured CLI results instead of handwritten claims**
- [ ] **Step 4: Re-run the focused test and confirm GREEN**
- [ ] **Step 5: Run package gates**

```bash
uv run ruff format --check packages/acc-core packages/acc-runtime packages/acc-testkit tests
uv run ruff check packages/acc-core packages/acc-runtime packages/acc-testkit tests
uv run mypy packages/acc-core/src packages/acc-runtime/src packages/acc-testkit/src
```

Expected: all commands exit 0.
