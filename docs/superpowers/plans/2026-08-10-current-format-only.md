# ACC Current-Format-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every legacy ACC v1 execution and compatibility path so all top-level artifacts, IR, Packs, validation, compilation, coverage, runtime, examples, and skills use format `2` only.

**Architecture:** Format `2` remains the sole wire identifier and is not renamed. Read and Action remain discriminated current-format types; normal MCP exposes Read only, while Action continues through prepare, approve, commit, and status. Legacy input is rejected at the first trust boundary with stable diagnostics, never migrated or interpreted heuristically.

**Tech Stack:** Python 3.11+, Pydantic v2, JSON Schema 2020-12, pytest, Ruff, mypy, MCP SDK.

---

### Task 1: Establish the single-format contract

**Files:**
- Modify: `packages/acc-core/src/acc_core/models/__init__.py`
- Modify: `packages/acc-core/src/acc_core/models/v2.py`
- Modify: `packages/acc-core/src/acc_core/io.py`
- Test: `tests/unit/core/test_models.py`
- Test: `tests/unit/core/test_project_v2_models.py`

- [x] Add failing tests proving every top-level current artifact requires `schema_version: "2"`, `ProjectDocument` accepts only the current project, and version `1` receives a stable unsupported-version error.
- [x] Run the focused model tests and confirm failure comes from existing v1 acceptance.
- [x] Remove the legacy Project/Operation/Capability dispatch and expose the current Read/Action document union as the canonical public API.
- [x] Run the focused tests and adjacent model tests to green.

### Task 2: Make validation and compilation current-format-only

**Files:**
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Modify: `packages/acc-core/src/acc_core/compiler/actions.py`
- Test: `tests/unit/core/test_project_validation.py`
- Test: `tests/unit/core/test_project_v2_validation.py`
- Test: `tests/unit/compiler/test_compiler.py`

- [x] Add failing tests requiring one SourceContract per Operation, one CapabilityQuality per Capability, format-2 Policy/Eval documents, and IR version `2` only.
- [x] Confirm legacy projects no longer fall through to v1 validation or compilation.
- [x] Delete v1 branches and compile only the current discriminated Read/Action models.
- [x] Run validation/compiler tests to green and confirm deterministic IR.

### Task 3: Remove legacy Pack and Runtime loading

**Files:**
- Modify: `packages/acc-core/src/acc_core/packaging/pack.py`
- Modify: `packages/acc-runtime/src/acc_runtime/loader/__init__.py`
- Modify: `packages/acc-runtime/src/acc_runtime/runtime.py`
- Modify: `packages/acc-runtime/src/acc_runtime/callability.py`
- Modify: `packages/acc-runtime/src/acc_runtime/providers/http.py`
- Test: `tests/integration/pack/test_pack.py`
- Test: `tests/unit/runtime/test_loader_credentials.py`
- Test: `tests/unit/runtime/test_runtime.py`
- Test: `tests/unit/runtime/test_runtime_v2.py`

- [x] Add failing tests proving manifest/lock/IR version `1` are rejected before runtime construction.
- [x] Remove loader, runtime, provider, and callability fallbacks for v1 definitions.
- [x] Keep Read on the normal tool surface and keep Action hidden outside its lifecycle coordinator.
- [x] Run pack/runtime/action tests to green.

### Task 4: Make Coverage and CLI single-version

**Files:**
- Modify: `packages/acc-core/src/acc_core/coverage/analyze.py`
- Modify: `packages/acc-core/src/acc_core/coverage/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/compiler/test_analysis_tools.py`
- Test: `tests/unit/core/test_cli.py`
- Test: `tests/integration/test_cli_milestone2.py`

- [x] Add failing tests proving Coverage has only the nine-axis report and `acc coverage --version ...` is an invalid argument.
- [x] Delete Coverage v1 APIs, compatibility output, and CLI version selection.
- [x] Make `acc coverage` require the typed scope inventory and always return the current multi-axis report.
- [x] Run Coverage and CLI tests to green.

### Task 5: Regenerate public schemas and convert examples

**Files:**
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Modify: `schemas/*.schema.json`
- Modify: `examples/fastapi-crm/acc-project/**`
- Modify: `skills/acc-engineer/templates/**`
- Test: `tests/unit/core/test_cli.py`
- Test: `tests/e2e/test_quality_profiles.py`

- [x] Add failing schema-export assertions that legacy schema names are absent and canonical schemas require version `2`.
- [x] Export only current schemas under canonical names and remove v1 schema artifacts.
- [x] Convert the maintained CRM example and engineering templates to complete current-format projects, including SourceContracts and CapabilityQuality sidecars.
- [x] Validate, compile, cover, and pack the example twice with identical digest.

### Task 6: Remove compatibility language and compatibility tests

**Files:**
- Modify: `README.md`
- Modify: `docs/progress.md`
- Modify: `docs/architecture/adr/007-versioned-quality-and-action-safety.md`
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/*.md`
- Modify: `tests/**`

- [x] Replace v1/v2 migration language with the single current-format contract and stable rejection boundary.
- [x] Remove tests whose only purpose is legacy compatibility; convert behavioral Read tests to current fixtures instead of deleting coverage.
- [x] Add a repository scan test that blocks executable code, schemas, examples, and templates from reintroducing top-level version `1` or Coverage v1.
- [x] Run skill, documentation, and converted behavior tests to green.

### Task 7: Full release verification and commit

**Files:**
- Verify: repository-wide tracked files except `.understand-anything/`

- [x] Run `uv lock --check`.
- [x] Run `uv run --frozen ruff format --check .` and `uv run --frozen ruff check .`.
- [x] Run `uv run --frozen mypy packages tests skills/acc-engineer/scripts`.
- [x] Run `uv run --frozen pytest -q`.
- [x] Regenerate schemas into a temporary directory and compare with `schemas/`.
- [x] Validate/compile/coverage/pack the current example and compare two Pack SHA-256 digests.
- [x] Scan for legacy executable references and verify remaining historical mentions are confined to archived design history, if retained.
- [x] Commit only ACC changes; do not add `.understand-anything/` and do not push.
