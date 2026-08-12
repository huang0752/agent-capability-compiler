# ACC Real-Project Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the platform gaps exposed by the baogao-jin system-complete run into typed, fail-closed ACC behavior without weakening evidence, authorization, or Action safety.

**Architecture:** Keep route closure, executable release readiness, test provisioning, static output bounds, and verification maturity as separate typed facts. A system-complete inventory may be discovery-complete while blocked routes remain non-executable, but release readiness still fails when any selected executable route lacks evidence. CLI test reports distinguish failed execution from unavailable runners. Output-bound inference accepts only schema- or deterministic-projection proof, never observations.

**Tech Stack:** Python 3.12, Pydantic v2, argparse CLI, JSON/YAML, pytest, Ruff, mypy.

---

### Task 1: Separate discovery closure from executable release readiness

**Files:**
- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Modify: `skills/acc-engineer/HARNESS.md`
- Modify: `skills/acc-engineer/SKILL.md`
- Modify: `skills/acc-engineer/guides/06-validate.md`
- Test: `tests/unit/skill/test_scope_audit.py`
- Test: `tests/unit/skill/test_skill_structure.py`

- [ ] Add a failing system-complete regression showing that a known, classified, explicitly blocked non-executable route contributes to a deterministic `limited` readiness summary rather than a denominator-closure error.
- [ ] Preserve errors for missing routes, unknown/unclassified routes, smuggled executable traces, accepted/planned blocked candidates, invalid exclusions, and mismatched plans.
- [ ] Emit separate structured counts for `discovery_complete`, `executable_ready`, `blocked`, and `unknown`; keep `ok=false` when an executable release is requested with unresolved selected routes.
- [ ] Update the Skill/HARNESS to require exact denominator closure while describing limited handoff truthfully; run focused scope and structure tests.

### Task 2: Represent unavailable runtime and E2E runners as not provisioned

**Files:**
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify or create: `packages/acc-core/src/acc_core/testing/` test-result model module if needed
- Test: `tests/unit/core/test_cli.py`
- Test: `tests/integration/test_cli_milestone2.py`

- [ ] Add failing CLI regressions for fixtures that require a project-specific runner and for a malformed fixture.
- [ ] Return a typed `not_provisioned` suite state with exact case IDs and zero calls when the required runner/fixture adapter is absent; retain `failed` for malformed data or an available runner that executes unsuccessfully.
- [ ] Add an explicit project runner adapter boundary without importing arbitrary project code or reading credentials.
- [ ] Preserve contract-test behavior and JSON diagnostic stability; run focused CLI and integration tests.

### Task 3: Improve static output-bound proof without inventing limits

**Files:**
- Modify: `packages/acc-core/src/acc_core/quality/output_size.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py` or the existing caller only if proof context must be threaded
- Test: `tests/unit/compiler/test_output_size.py`
- Test: `tests/unit/compiler/test_compiler.py`

- [ ] Add failing tests for bounded pagination schemas, locally referenced schemas, deterministic projection/truncation, and unbounded objects.
- [ ] Resolve local `$ref`, `allOf`, bounded arrays/strings/numbers, and deterministic projected subsets only when every reachable branch is bounded.
- [ ] Keep source observations, example payloads, page-size names without schema maxima, `additionalProperties: true`, and binary bodies unknown.
- [ ] Run focused compiler/output-size tests and prove warning counts change only for newly proven schemas.

### Task 4: Publish typed Action safety and verification maturity reports

**Files:**
- Create: `packages/acc-core/src/acc_core/domains/action_report.py`
- Modify: `packages/acc-core/src/acc_core/domains/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/domains.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Test: `tests/unit/compiler/test_action_report.py`
- Test: `tests/unit/core/test_domain_cli.py`
- Test: `tests/unit/core/test_cli.py`

- [ ] Add RED tests for an exact Action denominator and independent effect, risk, approval, authorization, idempotency, concurrency, retry, outcome, lifecycle, and verification axes.
- [ ] Derive the report only from the typed candidate ledger, selected decision, SourceContract/Operation/Capability proof, Evidence registry, and live verification artifacts; never accept caller-authored aggregate booleans.
- [ ] Add `acc domains actions` JSON/readable output with stable IDs and blockers, plus verification levels `discovered`, `semantics_evidenced`, `contract_ready`, `offline_verified`, `gateway_offline_verified`, `source_connected_verified`, `user_accepted`, and `production_ready` as independent evidence-bound projections.
- [ ] Export the public schema and run exact schema-export tests.

### Task 5: Integrate, document, and verify against baogao-jin

**Files:**
- Modify: `README.md`
- Modify: `skills/acc-engineer/guides/07-test.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Test: relevant Core, Compiler, Skill, Runtime, and integration suites

- [ ] Run all focused RED-to-GREEN suites, Ruff, formatting, mypy, schema byte-exact export, and `git diff --check`.
- [ ] Re-run the fixed behavior against `/Users/chou/code/baogao-jin-acc` without modifying `/Users/chou/code/baogao-jin` and record discovery/readiness, provisioning, output-bound, and Action-report deltas.
- [ ] Run an independent read-only security review for release bypass, evidence self-certification, runner injection, authorization widening, and hidden route loss.
- [ ] Update documentation with the exact distinction between discovery-complete, limited/offline release, real MCP verification, user acceptance, and production readiness.
