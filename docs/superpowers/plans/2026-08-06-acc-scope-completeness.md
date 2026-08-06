# ACC Engineer Scope Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a machine-audited source-scope denominator so ACC Engineer defaults to complete read-only system analysis unless the user explicitly authorizes a pilot or bounded domain.

**Architecture:** Add a planning-only `scope-inventory.yaml` and a deterministic `scope_audit.py` that validates range mode, route dispositions, recomputed counts, and cross-artifact references before ACC validation. Keep ACC core schemas unchanged; extend the Skill templates, guides, and handoff rules, and add a separate deterministic manifest helper for non-Git ACC projects.

**Tech Stack:** Python 3.12, PyYAML, JSON, pytest, Ruff, mypy, existing ACC Skill JSON envelope helpers.

---

## File map

- Create `skills/acc-engineer/templates/scope-inventory.yaml`: canonical explicit default-scope template.
- Create `skills/acc-engineer/scripts/scope_audit.py`: safe YAML/JSON loading and deterministic scope/cross-artifact audit.
- Create `skills/acc-engineer/scripts/artifact_manifest.py`: deterministic non-Git handoff manifest.
- Create `tests/unit/skill/test_scope_audit.py`: mode, route, count, and cross-artifact regression tests.
- Create `tests/unit/skill/test_artifact_manifest.py`: manifest safety and determinism tests.
- Modify `skills/acc-engineer/scripts/verify_read_only_workspace.py`: allow diagnostics to carry JSON pointers.
- Modify `tests/unit/skill/test_verify_read_only_workspace.py`: protect backward-compatible pointer diagnostics.
- Modify `tests/unit/skill/test_skill_structure.py`: require new templates/helpers and scope language.
- Modify `skills/acc-engineer/templates/coverage-baseline.json`: add source-scope denominator.
- Modify `skills/acc-engineer/templates/system-map.yaml`: link candidate operations to scope route IDs.
- Modify `skills/acc-engineer/templates/capability-plan.yaml`: declare scope mode and disposition coverage.
- Modify `skills/acc-engineer/SKILL.md`, `HARNESS.md`, and `guides/01-preflight.md` through `guides/09-handoff.md`: make the new range semantics operational.

### Task 1: Add pointer-aware Skill diagnostics

**Files:**
- Modify: `tests/unit/skill/test_verify_read_only_workspace.py`
- Modify: `skills/acc-engineer/scripts/verify_read_only_workspace.py:52-60`

- [ ] **Step 1: Write the failing diagnostic-pointer test**

Append:

```python
def test_diagnostic_optionally_includes_a_json_pointer() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_read_only_workspace", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.diagnostic("ACC_SCOPE_INVALID", "invalid", path="scope.yaml") == {
        "code": "ACC_SCOPE_INVALID",
        "severity": "error",
        "message": "invalid",
        "path": "scope.yaml",
    }
    assert (
        module.diagnostic(
            "ACC_SCOPE_INVALID",
            "invalid",
            path="scope.yaml",
            pointer="/routes/0/disposition",
        )["pointer"]
        == "/routes/0/disposition"
    )
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
uv run pytest -q tests/unit/skill/test_verify_read_only_workspace.py::test_diagnostic_optionally_includes_a_json_pointer
```

Expected: FAIL with `unexpected keyword argument 'pointer'`.

- [ ] **Step 3: Add the optional pointer field**

Change the helper signature and body to:

```python
def diagnostic(
    code: str,
    message: str,
    *,
    path: str | None = None,
    pointer: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "code": code,
        "severity": "error",
        "message": message,
    }
    if path is not None:
        value["path"] = path
    if pointer is not None:
        value["pointer"] = pointer
    return value
```

- [ ] **Step 4: Verify GREEN and existing helper tests**

Run:

```bash
uv run pytest -q tests/unit/skill/test_verify_read_only_workspace.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit the shared diagnostic change**

```bash
git commit --only -m 'feat(skill): 支持范围诊断指针' -- \
  skills/acc-engineer/scripts/verify_read_only_workspace.py \
  tests/unit/skill/test_verify_read_only_workspace.py
```

### Task 2: Add the explicit scope inventory contract

**Files:**
- Create: `skills/acc-engineer/templates/scope-inventory.yaml`
- Modify: `skills/acc-engineer/templates/coverage-baseline.json`
- Modify: `skills/acc-engineer/templates/system-map.yaml`
- Modify: `skills/acc-engineer/templates/capability-plan.yaml`
- Modify: `tests/unit/skill/test_skill_structure.py`

- [ ] **Step 1: Write failing template assertions**

Extend `test_templates_track_current_strict_public_models` with:

```python
scope = _yaml(SKILL / "templates" / "scope-inventory.yaml")
assert scope["scope"] == {
    "mode": "system_readonly_complete",
    "user_confirmation": None,
    "selected_domains": [],
}
route = scope["routes"][0]
assert set(route) == {
    "id",
    "domain",
    "method",
    "path",
    "evidence_sources",
    "eligibility",
    "disposition",
    "operation_id",
    "capability_ids",
    "reason",
}
baseline = json.loads((SKILL / "templates" / "coverage-baseline.json").read_text(encoding="utf-8"))
assert baseline["scope_mode"] == "system_readonly_complete"
assert set(baseline["source_scope"]) == {
    "eligible_read_routes",
    "planned_or_composed",
    "excluded",
    "blocked_on_evidence",
    "unresolved",
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest -q tests/unit/skill/test_skill_structure.py::test_templates_track_current_strict_public_models
```

Expected: FAIL because `scope-inventory.yaml` does not exist.

- [ ] **Step 3: Create the scope template**

Use a syntactically valid example whose top-level shape is:

```yaml
schema_version: "1"
scope:
  mode: system_readonly_complete
  user_confirmation: null
  selected_domains: []
discovery:
  source_commit: "git:0123456789abcdef"
  methods: [GET, HEAD]
  include_paths: [backend/app/api]
  evidence_sources: [api-router]
domains:
  - id: customer
    status: selected
routes:
  - id: customer.search
    domain: customer
    method: GET
    path: /api/customers/search
    evidence_sources: [customer-routes]
    eligibility: eligible
    disposition: planned
    operation_id: customer.search
    capability_ids: [search_customers]
    reason: null
summary:
  discovered_routes: 1
  eligible_read_routes: 1
  planned: 1
  composed: 0
  excluded: 0
  blocked_on_evidence: 0
  out_of_scope: 0
  unresolved: 0
```

Update `coverage-baseline.json` with:

```json
"scope_mode": "system_readonly_complete",
"source_scope": {
  "eligible_read_routes": 0,
  "planned_or_composed": 0,
  "excluded": 0,
  "blocked_on_evidence": 0,
  "unresolved": 0
}
```

Add `scope_route_ids` to candidate operations in `system-map.yaml`; add `scope_mode` and `route_dispositions` under coverage in `capability-plan.yaml`.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
uv run pytest -q tests/unit/skill/test_skill_structure.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit templates**

```bash
git add skills/acc-engineer/templates/scope-inventory.yaml
git commit --only -m 'feat(skill): 定义只读范围清单' -- \
  skills/acc-engineer/templates/scope-inventory.yaml \
  skills/acc-engineer/templates/coverage-baseline.json \
  skills/acc-engineer/templates/system-map.yaml \
  skills/acc-engineer/templates/capability-plan.yaml \
  tests/unit/skill/test_skill_structure.py
```

### Task 3: Implement inventory-mode and route-disposition audit

**Files:**
- Create: `tests/unit/skill/test_scope_audit.py`
- Create: `skills/acc-engineer/scripts/scope_audit.py`

- [ ] **Step 1: Add the subprocess harness and failing mode tests**

Create the test file with a `_write_project` fixture that writes four planning artifacts and a `_run` helper matching other Skill script tests. Add these cases:

```python
def test_system_complete_accepts_a_fully_disposed_inventory(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="system_readonly_complete")
    completed, payload = _run(project)
    assert completed.returncode == 0
    assert payload["ok"] is True
    assert payload["result"]["scope_mode"] == "system_readonly_complete"


def test_pilot_requires_explicit_user_confirmation(tmp_path: Path) -> None:
    project = _write_project(tmp_path, mode="pilot", user_confirmation=None)
    completed, payload = _run(project)
    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_CONFIRMATION_REQUIRED"
    assert payload["diagnostics"][0]["pointer"] == "/scope/user_confirmation"


def test_system_complete_rejects_out_of_scope_and_evidence_blockers(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        routes=[
            _route("customer.search", disposition="out_of_scope", reason="not selected"),
            _route("report.get", disposition="blocked_on_evidence", reason="scope unknown"),
        ],
    )
    completed, payload = _run(project)
    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
        "ACC_SCOPE_EVIDENCE_BLOCKED",
    }
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest -q tests/unit/skill/test_scope_audit.py
```

Expected: collection succeeds and subprocess cases fail because `scope_audit.py` is missing.

- [ ] **Step 3: Implement safe loading and inventory validation**

Implement these public units in `scope_audit.py`:

```python
SCOPE_MODES = {"pilot", "domain_complete", "system_readonly_complete"}
DISPOSITIONS = {
    "planned",
    "composed",
    "excluded",
    "blocked_on_evidence",
    "out_of_scope",
}
TERMINAL_COMPLETE = {"planned", "composed", "excluded"}


def load_document(path: Path) -> dict[str, object]:
    metadata = path.stat()
    raw = read_file_bytes(path, metadata, DEFAULT_MAX_FILE_BYTES, path.name)
    value = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise SafePathError(
            "ACC_SCOPE_DOCUMENT_INVALID", "document must be an object", path=path.name
        )
    return value


def audit_inventory(
    document: Mapping[str, object], *, path: str
) -> tuple[dict[str, object], list[dict[str, object]]]:
    diagnostics: list[dict[str, object]] = []
    scope = document.get("scope")
    routes = document.get("routes")
    summary = document.get("summary")
    if not isinstance(scope, Mapping):
        diagnostics.append(
            diagnostic(
                "ACC_SCOPE_DOCUMENT_INVALID", "scope must be an object", path=path, pointer="/scope"
            )
        )
        return {}, diagnostics
    if not isinstance(routes, list) or not isinstance(summary, Mapping):
        diagnostics.append(
            diagnostic("ACC_SCOPE_DOCUMENT_INVALID", "routes and summary are required", path=path)
        )
        return {}, diagnostics

    mode = scope.get("mode")
    confirmation = scope.get("user_confirmation")
    selected_domains = scope.get("selected_domains")
    if mode not in SCOPE_MODES:
        diagnostics.append(
            diagnostic(
                "ACC_SCOPE_MODE_INVALID", "scope mode is invalid", path=path, pointer="/scope/mode"
            )
        )
    if mode == "pilot" and (not isinstance(confirmation, str) or not confirmation.strip()):
        diagnostics.append(
            diagnostic(
                "ACC_SCOPE_CONFIRMATION_REQUIRED",
                "pilot requires explicit user confirmation",
                path=path,
                pointer="/scope/user_confirmation",
            )
        )
    if mode == "domain_complete" and (
        not isinstance(selected_domains, list) or not selected_domains
    ):
        diagnostics.append(
            diagnostic(
                "ACC_SCOPE_DOMAIN_REQUIRED",
                "domain_complete requires selected domains",
                path=path,
                pointer="/scope/selected_domains",
            )
        )

    seen: set[str] = set()
    operation_ids: set[str] = set()
    counters = {
        name: 0
        for name in (
            "discovered_routes",
            "eligible_read_routes",
            "planned",
            "composed",
            "excluded",
            "blocked_on_evidence",
            "out_of_scope",
            "unresolved",
        )
    }
    for index, raw_route in enumerate(routes):
        counters["discovered_routes"] += 1
        pointer = f"/routes/{index}"
        if not isinstance(raw_route, Mapping):
            counters["unresolved"] += 1
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_ROUTE_INVALID", "route must be an object", path=path, pointer=pointer
                )
            )
            continue
        route_id = raw_route.get("id")
        if not isinstance(route_id, str) or not route_id:
            counters["unresolved"] += 1
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_ROUTE_INVALID",
                    "route id is required",
                    path=path,
                    pointer=f"{pointer}/id",
                )
            )
        elif route_id in seen:
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_ROUTE_DUPLICATE",
                    "route id must be unique",
                    path=path,
                    pointer=f"{pointer}/id",
                )
            )
        else:
            seen.add(route_id)
        if raw_route.get("method") not in {"GET", "HEAD"}:
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_METHOD_INVALID",
                    "scope inventory permits GET or HEAD",
                    path=path,
                    pointer=f"{pointer}/method",
                )
            )
        evidence = raw_route.get("evidence_sources")
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(isinstance(item, str) and item for item in evidence)
        ):
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_EVIDENCE_REQUIRED",
                    "route evidence is required",
                    path=path,
                    pointer=f"{pointer}/evidence_sources",
                )
            )

        eligibility = raw_route.get("eligibility")
        disposition = raw_route.get("disposition")
        if eligibility == "eligible":
            counters["eligible_read_routes"] += 1
        if disposition not in DISPOSITIONS:
            counters["unresolved"] += 1
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_DISPOSITION_INVALID",
                    "route disposition is invalid",
                    path=path,
                    pointer=f"{pointer}/disposition",
                )
            )
            continue
        counters[str(disposition)] += 1
        reason = raw_route.get("reason")
        if disposition in {"excluded", "blocked_on_evidence", "out_of_scope"} and (
            not isinstance(reason, str) or not reason.strip()
        ):
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_REASON_REQUIRED",
                    "route disposition requires a reason",
                    path=path,
                    pointer=f"{pointer}/reason",
                )
            )
        operation_id = raw_route.get("operation_id")
        if disposition in {"planned", "composed"}:
            if not isinstance(operation_id, str) or not operation_id:
                diagnostics.append(
                    diagnostic(
                        "ACC_SCOPE_OPERATION_REQUIRED",
                        "planned route requires an operation",
                        path=path,
                        pointer=f"{pointer}/operation_id",
                    )
                )
            else:
                operation_ids.add(operation_id)
        if mode == "system_readonly_complete" and disposition == "out_of_scope":
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_OUT_OF_SCOPE_FORBIDDEN",
                    "system scope cannot omit an eligible route",
                    path=path,
                    pointer=f"{pointer}/disposition",
                )
            )
        if mode == "system_readonly_complete" and disposition == "blocked_on_evidence":
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_EVIDENCE_BLOCKED",
                    "system scope has unresolved evidence",
                    path=path,
                    pointer=f"{pointer}/disposition",
                )
            )

    for name, actual in counters.items():
        if summary.get(name) != actual:
            diagnostics.append(
                diagnostic(
                    "ACC_SCOPE_SUMMARY_MISMATCH",
                    "declared scope summary does not match routes",
                    path=path,
                    pointer=f"/summary/{name}",
                )
            )
    result: dict[str, object] = {
        "scope_mode": mode,
        "selected_domains": sorted(
            item
            for item in (selected_domains if isinstance(selected_domains, list) else [])
            if isinstance(item, str)
        ),
        "operation_ids": sorted(operation_ids),
        "source_scope": counters,
    }
    return result, diagnostics
```

Use small helpers `mapping_at`, `string_at`, `string_list_at`, and `add_issue` so every diagnostic has a stable code, artifact path, and RFC 6901 pointer. `main()` must emit one JSON envelope and return `0` on success, `3` on audit failure, and `2` on path/usage failure.

- [ ] **Step 4: Add route-level edge cases**

Add tests for a missing mode, a valid confirmed pilot, duplicate IDs, non-GET/HEAD methods, missing Evidence, missing reason, missing operation ID, summary mismatch, and a diagnostic input containing `production-secret-never-output`. Assert the secret string is absent from stdout and assert stable codes:

```python
{
    "ACC_SCOPE_ROUTE_DUPLICATE",
    "ACC_SCOPE_METHOD_INVALID",
    "ACC_SCOPE_EVIDENCE_REQUIRED",
    "ACC_SCOPE_REASON_REQUIRED",
    "ACC_SCOPE_OPERATION_REQUIRED",
    "ACC_SCOPE_SUMMARY_MISMATCH",
}
```

- [ ] **Step 5: Run and verify GREEN**

Run:

```bash
uv run pytest -q tests/unit/skill/test_scope_audit.py
uv run ruff check skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
uv run mypy skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
```

Expected: all commands pass.

- [ ] **Step 6: Commit inventory audit**

```bash
git add skills/acc-engineer/scripts/scope_audit.py tests/unit/skill/test_scope_audit.py
git commit -m 'feat(skill): 审计系统只读范围完整性'
```

### Task 4: Add cross-artifact scope consistency

**Files:**
- Modify: `tests/unit/skill/test_scope_audit.py`
- Modify: `skills/acc-engineer/scripts/scope_audit.py`

- [ ] **Step 1: Write failing cross-artifact tests**

Add tests proving:

```python
def test_planned_routes_must_exist_in_system_map_and_capability_plan(tmp_path: Path) -> None:
    project = _write_project(tmp_path, system_operations=[], plan_dependencies=[])
    completed, payload = _run(project)
    assert completed.returncode == 3
    assert {item["code"] for item in payload["diagnostics"]} == {
        "ACC_SCOPE_SYSTEM_MAP_MISSING_OPERATION",
        "ACC_SCOPE_PLAN_MISSING_OPERATION",
    }


def test_coverage_baseline_must_match_inventory_denominator(tmp_path: Path) -> None:
    project = _write_project(tmp_path, baseline_eligible=99)
    completed, payload = _run(project)
    assert completed.returncode == 3
    assert payload["diagnostics"][0]["code"] == "ACC_SCOPE_COVERAGE_MISMATCH"


def test_domain_complete_requires_selected_domains_and_disposes_each_selected_route(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path, mode="domain_complete", selected_domains=["customer"])
    completed, payload = _run(project)
    assert completed.returncode == 0
    assert payload["result"]["selected_domains"] == ["customer"]
```

- [ ] **Step 2: Run and verify RED**

Run the three tests directly. Expected: FAIL because cross-artifact references are not audited.

- [ ] **Step 3: Implement cross-artifact indexes**

Add:

```python
def system_operation_ids(document: Mapping[str, object]) -> set[str]:
    return {
        str(item["id"])
        for item in document.get("candidate_operations", [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }


def plan_operation_ids(document: Mapping[str, object]) -> set[str]:
    result: set[str] = set()
    for capability in document.get("capabilities", []):
        if isinstance(capability, Mapping):
            dependencies = capability.get("operation_dependencies", [])
            if isinstance(dependencies, list):
                result.update(item for item in dependencies if isinstance(item, str))
    return result
```

Compare every planned/composed `operation_id` against both indexes. Recompute `source_scope` and compare it with coverage baseline. For `domain_complete`, require non-empty selected domains, reject unknown selected domains, and require every eligible selected-domain route to use a complete disposition.

- [ ] **Step 4: Verify all scope audit tests**

Run:

```bash
uv run pytest -q tests/unit/skill/test_scope_audit.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit cross-artifact checks**

```bash
git commit --only -m 'feat(skill): 校验范围与能力计划一致性' -- \
  skills/acc-engineer/scripts/scope_audit.py \
  tests/unit/skill/test_scope_audit.py
```

### Task 5: Generate a deterministic non-Git artifact manifest

**Files:**
- Create: `tests/unit/skill/test_artifact_manifest.py`
- Create: `skills/acc-engineer/scripts/artifact_manifest.py`

- [ ] **Step 1: Write failing determinism and safety tests**

Create tests that run the helper twice against a temporary ACC project and assert:

```python
assert first_payload["result"]["files"] == second_payload["result"]["files"]
assert first_payload["result"]["digest"] == second_payload["result"]["digest"]
assert [item["path"] for item in first_payload["result"]["files"]] == [
    "capabilities/read.yaml",
    "project.yaml",
]
```

Add cases rejecting symlinks, sensitive filenames, output outside the project, and files above the byte bound without outputting their content.

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest -q tests/unit/skill/test_artifact_manifest.py
```

Expected: FAIL because the helper is missing.

- [ ] **Step 3: Implement the manifest helper**

Use the existing safe walk/hash helpers. The manifest result must be:

```python
{
    "algorithm": "sha256",
    "digest": overall_digest,
    "files": [
        {"path": relative, "size": metadata.st_size, "sha256": file_digest}
        for relative, path, metadata in iter_workspace(project)
        if path is not None and relative != output_relative
    ],
}
```

Hash the canonical JSON serialization of `files` for `overall_digest`. Write atomically only when `--output` is supplied and resolves inside the ACC project. Reject symlinks, sensitive paths, nested source workspaces, and oversized files using stable Skill codes.

- [ ] **Step 4: Verify GREEN**

Run pytest, Ruff, and mypy for the new helper and tests. Expected: all pass.

- [ ] **Step 5: Commit the manifest helper**

```bash
git add skills/acc-engineer/scripts/artifact_manifest.py tests/unit/skill/test_artifact_manifest.py
git commit -m 'feat(skill): 生成非 Git 交付清单'
```

### Task 6: Wire scope semantics through the Skill workflow

**Files:**
- Modify: `tests/unit/skill/test_skill_structure.py`
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/guides/01-preflight.md`
- Modify: `skills/acc-engineer/guides/02-analyze.md`
- Modify: `skills/acc-engineer/guides/03-model.md`
- Modify: `skills/acc-engineer/guides/04-plan.md`
- Modify: `skills/acc-engineer/guides/05-implement.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/08-refine.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`

- [ ] **Step 1: Write failing workflow-language assertions**

Add a test that requires:

```python
def test_skill_requires_explicit_scope_audit_and_validation_level() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    guides = "\n".join(path.read_text(encoding="utf-8") for path in (SKILL / "guides").glob("*.md"))

    assert "system_readonly_complete" in skill
    assert "只有用户明确" in skill
    assert "scope_audit.py" in skill
    assert "浅层全局发现" in harness
    assert "source_scope" in guides
    assert "offline_candidate" in guides
    assert "source_connected_verified" in guides
    assert "artifact-manifest.json" in guides
```

- [ ] **Step 2: Run and verify RED**

Run the new test. Expected: FAIL on missing `system_readonly_complete`.

- [ ] **Step 3: Update concise core routing rules**

Add to `SKILL.md`:

- Default unspecified existing-system work to `system_readonly_complete`.
- Permit `pilot` only with explicit user MVP wording and recorded confirmation.
- Require shallow global discovery before bounded Evidence includes.
- Require `scope_audit.py` before ACC validate.
- Distinguish `offline_candidate` from `source_connected_verified`.
- Add `scope-audit-report.json` and `artifact-manifest.json` to completion outputs.

Keep SKILL under 500 lines and route details to phase guides.

- [ ] **Step 4: Update each phase without duplication**

Make these exact semantic changes:

- Preflight: declare and record scope mode; do not treat `--include` as discovery denominator.
- Analyze: perform shallow global discovery and produce `scope-inventory.yaml`.
- Model: add `scope_route_ids` to each candidate Operation.
- Plan: assign every eligible route a disposition and reconcile source-scope baseline.
- Implement: implement only `planned`/`composed` routes.
- Validate: run scope audit before ACC commands and retain its JSON.
- Test: define Fake Runtime/E2E as offline; source connection needs explicit local/test authorization.
- Refine: compare source, operation, and Eval coverage independently.
- Handoff: state scope mode and validation level; select diff for Git or manifest for non-Git.

- [ ] **Step 5: Verify structure tests and Skill Creator validation**

Run:

```bash
uv run pytest -q tests/unit/skill/test_skill_structure.py
uv run python /Users/chou/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/acc-engineer
```

Expected: tests pass and validator prints `Skill is valid!`.

- [ ] **Step 6: Commit workflow documentation**

```bash
git commit --only -m 'docs(skill): 强制审计 MCP 范围完整性' -- \
  skills/acc-engineer/SKILL.md \
  skills/acc-engineer/HARNESS.md \
  skills/acc-engineer/guides/01-preflight.md \
  skills/acc-engineer/guides/02-analyze.md \
  skills/acc-engineer/guides/03-model.md \
  skills/acc-engineer/guides/04-plan.md \
  skills/acc-engineer/guides/05-implement.md \
  skills/acc-engineer/guides/06-validate.md \
  skills/acc-engineer/guides/07-test.md \
  skills/acc-engineer/guides/08-refine.md \
  skills/acc-engineer/guides/09-handoff.md \
  tests/unit/skill/test_skill_structure.py
```

### Task 7: Full verification and review bundle

**Files:**
- Review: all files changed since `d4f92b2`

- [ ] **Step 1: Run focused Skill tests**

```bash
uv run pytest -q tests/unit/skill
```

Expected: all Skill unit tests pass.

- [ ] **Step 2: Run the complete repository suite**

```bash
uv run pytest -q
uv run ruff check .
uv run mypy packages tests skills/acc-engineer/scripts
```

Expected: all commands exit zero with no failures or diagnostics.

- [ ] **Step 3: Validate the skill package**

```bash
uv run python /Users/chou/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/acc-engineer
```

Expected: `Skill is valid!`.

- [ ] **Step 4: Verify branch scope and user-owned files**

```bash
git diff --check main...HEAD
git status --short
git diff --stat main...HEAD
```

Expected: only the design, plan, Skill, helper, template, and test paths are changed; `.understand-anything/` remains untracked and untouched.

- [ ] **Step 5: Review the final commits**

```bash
git log --oneline main..HEAD
```

Expected: small Chinese commits for diagnostics, templates, scope audit, cross-artifact checks, manifest, and Skill workflow documentation.
