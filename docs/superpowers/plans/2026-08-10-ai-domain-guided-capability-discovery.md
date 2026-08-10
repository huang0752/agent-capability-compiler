# AI Domain-Guided Capability Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a platform-neutral, domain-by-domain AI onboarding workflow in which every capability candidate remains in a typed denominator, users confirm business goals rather than routes, Core derives readiness, and source-system JWT authorization remains authoritative.

**Architecture:** Core gains optional typed domain, candidate, decision, and change-request sidecars plus deterministic analyzers and Coverage axes. The ACC Engineer Skill performs AI discovery and user dialogue; Runtime remains LLM-free. Action safety expands through evidence-bound strategy unions rather than project-specific exceptions, while the source API continues to make every user/resource authorization decision.

**Tech Stack:** Python 3.12+, Pydantic v2, JSON Schema Draft 2020-12, PyYAML, argparse CLI, pytest, Ruff, mypy, official MCP SDK for Action regression tests.

---

## Delivery decomposition

The design spans four independently testable subsystems. Implement them in this order:

1. deterministic domain/candidate foundation;
2. evidence-bound Action strategy expansion;
3. ACC Engineer domain wizard and user decisions;
4. incremental rescans and cross-industry acceptance.

No task adds an LLM client to Core or Runtime. The installed Coding Agent follows the Skill and writes typed artifacts; Core only validates facts and derives diagnostics.

### Task 1: Domain, candidate, decision, and change-request models

**Files:**
- Create: `packages/acc-core/src/acc_core/domains/models.py`
- Create: `packages/acc-core/src/acc_core/domains/__init__.py`
- Test: `tests/unit/core/test_domain_models.py`

- [x] **Step 1: Write failing strict-model tests**

```python
import pytest
from pydantic import ValidationError

from acc_core.domains import (
    CapabilityCandidateLedger,
    DomainChangeRequest,
    DomainDecision,
    DomainMap,
)


def test_domain_map_requires_every_candidate_to_be_classified_or_unclassified() -> None:
    document = DomainMap.model_validate(
        {
            "schema_version": "2",
            "domains": [
                {
                    "id": "orders",
                    "title": "Orders",
                    "status": "not_started",
                    "candidate_ids": ["orders.cancel"],
                    "dependency_domain_ids": [],
                    "evidence_refs": ["orders-router"],
                }
            ],
            "unclassified_candidate_ids": [],
        }
    )
    assert document.domains[0].candidate_ids == ["orders.cancel"]


def test_candidate_keeps_evidence_gap_separate_from_user_disposition() -> None:
    ledger = CapabilityCandidateLedger.model_validate(
        {
            "schema_version": "2",
            "candidates": [
                {
                    "id": "orders.cancel",
                    "domain_id": "orders",
                    "business_intent": "cancel_order",
                    "route_ids": ["POST /api/orders/{order_id}/cancel"],
                    "interaction_ids": [],
                    "kind_claim": "action",
                    "effect_claim": "transition",
                    "claims": {
                        "schema": {"status": "proven", "evidence_refs": ["orders-schema"]},
                        "authorization_boundary": {
                            "status": "upstream_authoritative",
                            "evidence_refs": ["orders-auth"],
                        },
                        "conflict_control": {"status": "missing", "evidence_refs": []},
                    },
                    "user_disposition": "undecided",
                    "verification_level": "action_discovered",
                    "gaps": ["conflict_control"],
                }
            ],
        }
    )
    assert ledger.candidates[0].user_disposition == "undecided"
    assert ledger.candidates[0].gaps == ["conflict_control"]


def test_completed_decision_rejects_blocked_candidates() -> None:
    with pytest.raises(ValidationError):
        DomainDecision.model_validate(
            {
                "schema_version": "2",
                "domain_id": "orders",
                "revision": 1,
                "status": "completed",
                "policy": {"allowed_effects": ["read", "transition"], "maximum_risk": "high"},
                "accepted_capability_ids": [],
                "deferred_candidate_ids": [],
                "rejected_candidate_ids": [],
                "blocked_candidate_ids": ["orders.cancel"],
                "unresolved_questions": [],
                "dependency_snapshot_digest": "sha256:" + "a" * 64,
                "evidence_digest": "sha256:" + "b" * 64,
                "user_confirmation": {
                    "text": "Complete orders",
                    "confirmed_at": "2026-08-10T00:00:00Z",
                },
            }
        )
```

- [x] **Step 2: Run the new test and verify RED**

Run: `uv run --frozen pytest -q tests/unit/core/test_domain_models.py`

Expected: collection fails with `ModuleNotFoundError: No module named 'acc_core.domains'`.

- [x] **Step 3: Implement frozen strict models and sorted-reference validators**

```python
class CandidateClaim(StrictModel):
    status: Literal[
        "unknown",
        "missing",
        "candidate",
        "proven",
        "upstream_authoritative",
        "identity_binding_proven",
        "context_isolation_proven",
    ]
    evidence_refs: list[NonEmptyString] = Field(default_factory=list)


class CapabilityCandidate(StrictModel):
    id: NonEmptyString
    domain_id: NonEmptyString
    business_intent: NonEmptyString
    route_ids: list[NonEmptyString]
    interaction_ids: list[NonEmptyString]
    kind_claim: Literal["unknown", "read", "action"]
    effect_claim: Literal["unknown", "read", "create", "update", "delete", "transition", "execute"]
    claims: dict[NonEmptyString, CandidateClaim]
    user_disposition: Literal["undecided", "accepted", "deferred", "rejected"]
    verification_level: Literal[
        "discovered",
        "action_discovered",
        "semantics_evidenced",
        "contract_ready",
        "offline_verified",
        "sandbox_verified",
        "source_connected_verified",
        "deployment_ready",
    ]
    gaps: list[NonEmptyString]
    ineligibility_claim: CandidateClaim | None = None


class DomainDecision(StrictModel):
    schema_version: Literal["2"]
    domain_id: NonEmptyString
    revision: PositiveInt
    status: Literal["ready_for_review", "completed", "stale"]
    policy: DomainPolicy
    accepted_capability_ids: list[NonEmptyString]
    deferred_candidate_ids: list[NonEmptyString]
    rejected_candidate_ids: list[NonEmptyString]
    blocked_candidate_ids: list[NonEmptyString]
    unresolved_questions: list[NonEmptyString]
    dependency_snapshot_digest: Sha256Digest
    evidence_digest: Sha256Digest
    user_confirmation: UserConfirmation | None

    @model_validator(mode="after")
    def completed_is_closed(self) -> Self:
        if self.status == "completed" and (
            self.blocked_candidate_ids
            or self.unresolved_questions
            or self.user_confirmation is None
        ):
            raise ValueError("completed domain decisions must be closed and confirmed")
        return self
```

Implement `DomainMap`, `DomainPolicy`, `CapabilityCandidateLedger`, `UserConfirmation`, and `DomainChangeRequest` in the same module. All identifier lists must be sorted and unique; domain dependencies must reject self-reference; a candidate ID may occur at most once across domains plus `unclassified_candidate_ids`. Task 2 project validation proves exact closure against the separate Candidate Ledger.

- [x] **Step 4: Run model tests and adjacent model regression**

Run: `uv run --frozen pytest -q tests/unit/core/test_domain_models.py tests/unit/core/test_scope_models.py tests/unit/core/test_models.py`

Expected: all tests pass.

- [x] **Step 5: Commit the model slice**

```bash
git add packages/acc-core/src/acc_core/domains tests/unit/core/test_domain_models.py
git commit -m "feat(core): 定义领域能力候选与决策合同"
```

### Task 2: Public schemas and project sidecar loading

**Files:**
- Modify: `packages/acc-core/src/acc_core/schemas/export.py`
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Modify: `packages/acc-core/src/acc_core/packaging/pack.py`
- Create: `schemas/domain-map.schema.json`
- Create: `schemas/capability-candidates.schema.json`
- Create: `schemas/domain-decision.schema.json`
- Create: `schemas/domain-change-request.schema.json`
- Test: `tests/unit/core/test_project_domain_validation.py`
- Test: `tests/integration/pack/test_pack.py`

- [x] **Step 1: Write RED tests for optional sidecars and exact closure**

```python
def test_domain_sidecars_load_as_typed_documents(current_project: Path) -> None:
    _write_domain_map(current_project, candidate_ids=["crm.search"])
    _write_candidate_ledger(current_project, candidate_ids=["crm.search"])
    _write_domain_decision(current_project, domain_id="crm", revision=1)

    report = validate_project(current_project)

    assert report.ok
    assert report.domain_map is not None
    assert list(report.capability_candidates.candidates)[0].id == "crm.search"
    assert report.domain_decisions["crm"].revision == 1


def test_domain_map_rejects_missing_and_orphan_candidates(current_project: Path) -> None:
    _write_domain_map(current_project, candidate_ids=["crm.missing"])
    _write_candidate_ledger(current_project, candidate_ids=["crm.orphan"])

    report = validate_project(current_project)

    assert {diagnostic.code for diagnostic in report.diagnostics} >= {
        "ACC_DOMAIN_CANDIDATE_MISSING",
        "ACC_DOMAIN_CANDIDATE_ORPHAN",
    }
```

Also assert that a project with none of the four sidecar families retains current validation output, while declaring any one of `domain-map.yaml` or `capability-candidates.yaml` requires the other.

- [x] **Step 2: Run the focused test and verify missing report fields**

Run: `uv run --frozen pytest -q tests/unit/core/test_project_domain_validation.py`

Expected: tests fail because `ValidationReport` has no domain fields and schemas are not exported.

- [x] **Step 3: Add typed paths and loaders to ValidationReport**

```python
@dataclass(slots=True)
class ValidationReport:
    # existing fields remain unchanged
    domain_map: DomainMap | None = None
    domain_map_path: str | None = None
    capability_candidates: CapabilityCandidateLedger | None = None
    capability_candidates_path: str | None = None
    domain_decisions: dict[str, DomainDecision] = field(default_factory=dict)
    domain_decision_paths: dict[str, str] = field(default_factory=dict)
    domain_change_requests: dict[str, DomainChangeRequest] = field(default_factory=dict)
    domain_change_request_paths: dict[str, str] = field(default_factory=dict)
```

Load fixed files `domain-map.yaml` and `capability-candidates.yaml`, plus strict collections under `domain-decisions/` and `domain-change-requests/`. Reject duplicate IDs, mismatched filename/document IDs, symlinks, oversized files, missing candidate references, orphan candidates, unknown decision domains, and multiple revisions for the same domain in the active project.

- [x] **Step 4: Export four schemas and allow sidecars in Pack format 2**

Add schema registry entries with canonical names `domain-map`, `capability-candidates`, `domain-decision`, and `domain-change-request`. Extend the format-2 Pack member allowlist to the fixed files and directories. Do not make sidecars Runtime requirements; Runtime ignores them except for their compiler-produced summaries added in later tasks.

- [x] **Step 5: Run validation, schema, and Pack tests**

Run: `uv run --frozen pytest -q tests/unit/core/test_project_domain_validation.py tests/unit/core/test_cli.py tests/integration/pack/test_pack.py`

Expected: all tests pass and two builds containing domain sidecars are byte-identical.

- [x] **Step 6: Commit schema and loading support**

```bash
git add packages/acc-core/src/acc_core/schemas/export.py packages/acc-core/src/acc_core/validation/project.py packages/acc-core/src/acc_core/cli/main.py packages/acc-core/src/acc_core/packaging/pack.py schemas tests/unit/core/test_project_domain_validation.py tests/integration/pack/test_pack.py
git commit -m "feat(core): 加载领域向导项目合同"
```

### Task 3: Tri-state source discovery and candidate trace closure

**Files:**
- Modify: `packages/acc-core/src/acc_core/scope/models.py`
- Modify: `skills/acc-engineer/scripts/scope_audit.py`
- Modify: `skills/acc-engineer/templates/scope-inventory.yaml`
- Test: `tests/unit/core/test_scope_models.py`
- Test: `tests/unit/skill/test_scope_audit.py`

- [x] **Step 1: Write RED tests proving missing Action evidence cannot become ineligible**

```python
def test_unknown_candidate_is_blocked_instead_of_ineligible() -> None:
    route = _route(
        method="POST",
        kind="unknown",
        effect="unknown",
        eligibility="undetermined",
        disposition="blocked_on_evidence",
        candidate_id="orders.cancel",
        reason="Business effect is not yet evidenced.",
    )
    inventory = ScopeInventory.model_validate(_inventory(routes=[route]))
    assert inventory.summary.blocked_on_evidence == 1


def test_action_candidate_cannot_use_ineligible_for_missing_safety_evidence(
    tmp_path: Path,
) -> None:
    project = _scope_project(
        tmp_path,
        route=_route(
            method="POST",
            kind="action",
            effect="transition",
            eligibility="ineligible",
            disposition="excluded",
            candidate_id="orders.cancel",
            reason="Concurrency evidence is incomplete.",
        ),
        candidate=_candidate(id="orders.cancel", gaps=["conflict_control"]),
    )
    report = run_scope_audit(project)
    assert "ACC_SCOPE_ACTION_GAP_MISCLASSIFIED" in diagnostic_codes(report)
```

- [x] **Step 2: Run focused Scope tests and verify enum/model failures**

Run: `uv run --frozen pytest -q tests/unit/core/test_scope_models.py tests/unit/skill/test_scope_audit.py -k 'unknown or action_gap or candidate'`

Expected: tests fail because `unknown`, `undetermined`, and `candidate_id` are unsupported.

- [x] **Step 3: Extend ScopeRoute without weakening compiled Operations**

```python
class ScopeRoute(StrictModel):
    # existing fields remain
    kind: Literal["unknown", "read", "action"]
    effect: Literal["unknown", "read", "create", "update", "delete", "transition", "execute"]
    eligibility: Literal["undetermined", "eligible", "ineligible"]
    candidate_id: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_discovery_state(self) -> Self:
        if self.kind == "unknown" and (
            self.effect != "unknown"
            or self.eligibility != "undetermined"
            or self.disposition != "blocked_on_evidence"
            or self.candidate_id is None
        ):
            raise ValueError("unknown routes must remain candidate-linked and blocked")
        if self.kind == "read" and self.effect != "read":
            raise ValueError("read routes require effect=read")
        if self.kind == "action" and self.effect in {"unknown", "read"}:
            raise ValueError("action routes require a mutation effect")
        return self
```

Keep `Operation` models strict and unchanged: only discovery artifacts accept unknown states.

- [x] **Step 4: Add auditor rules against denominator distortion**

The auditor must load the candidate ledger through Core. Require every `unknown` or `action` route to reference a candidate. When candidate gaps contain semantics, authorization boundary, conflict control, idempotency, lifecycle, or outcome resolution, require `eligibility=undetermined` plus `disposition=blocked_on_evidence` unless the candidate has an objective, evidence-backed `ineligibility_claim`. Add diagnostics:

- `ACC_SCOPE_CANDIDATE_REFERENCE_REQUIRED`
- `ACC_SCOPE_CANDIDATE_ROUTE_MISMATCH`
- `ACC_SCOPE_ACTION_GAP_MISCLASSIFIED`
- `ACC_SCOPE_ACTION_INELIGIBILITY_UNPROVEN`

- [x] **Step 5: Run full Scope model/auditor tests**

Run: `uv run --frozen pytest -q tests/unit/core/test_scope_models.py tests/unit/skill/test_scope_audit.py`

Expected: all tests pass; existing read-only inventories remain valid.

- [x] **Step 6: Commit the tri-state denominator**

```bash
git add packages/acc-core/src/acc_core/scope/models.py skills/acc-engineer/scripts/scope_audit.py skills/acc-engineer/templates/scope-inventory.yaml tests/unit/core/test_scope_models.py tests/unit/skill/test_scope_audit.py
git commit -m "feat(scope): 保留未决业务能力候选"
```

### Task 4: Deterministic domain readiness analyzer

**Files:**
- Create: `packages/acc-core/src/acc_core/domains/analyze.py`
- Modify: `packages/acc-core/src/acc_core/domains/__init__.py`
- Modify: `packages/acc-core/src/acc_core/validation/project.py`
- Test: `tests/unit/compiler/test_domain_readiness.py`

- [x] **Step 1: Write RED readiness tests**

```python
def test_domain_readiness_separates_evidence_gaps_from_user_deferral() -> None:
    report = analyze_domain_readiness(
        domain=_domain("orders", ["orders.search", "orders.cancel", "orders.delete"]),
        candidates={
            "orders.search": _candidate(verification="contract_ready", disposition="accepted"),
            "orders.cancel": _candidate(gaps=["conflict_control"], disposition="undecided"),
            "orders.delete": _candidate(gaps=[], disposition="deferred"),
        },
        decision=None,
    )
    assert report.status == "awaiting_user"
    assert report.blocked_candidate_ids == ("orders.cancel",)
    assert report.deferred_candidate_ids == ("orders.delete",)


def test_upstream_authoritative_permission_is_not_a_readiness_gap() -> None:
    candidate = _candidate(
        claims={
            "authorization_boundary": _claim("upstream_authoritative", ["orders-auth"]),
            "identity_binding": _claim("proven", ["gateway-session"]),
        },
        gaps=[],
    )
    assert analyze_candidate_readiness(candidate).authorization_status == "source_final"
```

- [x] **Step 2: Run focused tests and verify missing analyzer**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_readiness.py`

Expected: collection fails because `analyze_domain_readiness` is not defined.

- [x] **Step 3: Implement pure readiness functions and stable diagnostics**

```python
@dataclass(frozen=True, slots=True)
class DomainReadiness:
    domain_id: str
    status: Literal[
        "not_started",
        "in_progress",
        "awaiting_user",
        "validation_failed",
        "ready_for_review",
        "completed",
        "stale",
    ]
    accepted_candidate_ids: tuple[str, ...]
    blocked_candidate_ids: tuple[str, ...]
    deferred_candidate_ids: tuple[str, ...]
    rejected_candidate_ids: tuple[str, ...]
    question_ids: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]


def analyze_candidate_readiness(candidate: CapabilityCandidate) -> CandidateReadiness:
    source_final = candidate.claims.get("authorization_boundary")
    identity = candidate.claims.get("identity_binding")
    authorization_status = (
        "source_final"
        if (
            source_final is not None
            and source_final.status == "upstream_authoritative"
            and identity is not None
            and identity.status in {"proven", "identity_binding_proven"}
        )
        else "unknown"
    )
    blocking = tuple(sorted(set(candidate.gaps)))
    return CandidateReadiness(
        candidate_id=candidate.id,
        blocking_gaps=blocking,
        authorization_status=authorization_status,
    )
```

The analyzer must never treat missing source permission lists as a gap when identity binding and upstream final authorization are evidenced. It must error if ACC claims it can grant source permission, if a completed decision digest is stale, or if accepted candidates retain blocking gaps.

- [x] **Step 4: Merge analyzer diagnostics into project validation**

When domain sidecars exist, call the analyzer after Scope, Operations, Capabilities, interactions, and SourceContracts are loaded. Preserve exact sidecar paths in diagnostics. Add stable codes:

- `ACC_DOMAIN_CANDIDATE_BLOCKED`
- `ACC_DOMAIN_DECISION_STALE`
- `ACC_DOMAIN_DECISION_UNCONFIRMED`
- `ACC_DOMAIN_SOURCE_AUTHORITY_OVERRIDDEN`
- `ACC_DOMAIN_DEPENDENCY_UNRESOLVED`

- [x] **Step 5: Run analyzer and project-validation regression**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_readiness.py tests/unit/core/test_project_domain_validation.py tests/unit/core/test_project_validation.py`

Expected: all tests pass.

- [x] **Step 6: Commit readiness analysis**

```bash
git add packages/acc-core/src/acc_core/domains packages/acc-core/src/acc_core/validation/project.py tests/unit/compiler/test_domain_readiness.py tests/unit/core/test_project_domain_validation.py
git commit -m "feat(core): 派生领域候选就绪状态"
```

### Task 5: Domain and Action Coverage axes

**Files:**
- Create: `packages/acc-core/src/acc_core/coverage/domains.py`
- Modify: `packages/acc-core/src/acc_core/coverage/models.py`
- Modify: `packages/acc-core/src/acc_core/coverage/analyze.py`
- Test: `tests/unit/compiler/test_domain_coverage.py`
- Modify: `tests/unit/compiler/test_analysis_tools.py`

- [x] **Step 1: Write RED tests for independent axes and no total score**

```python
def test_action_candidates_cannot_hide_behind_read_route_closure() -> None:
    coverage = analyze_coverage(
        report=_report_with_domains(),
        scope_inventory=_inventory(read_composed=100, action_blocked=20),
    )
    assert coverage.route_disposition.broken_route_ids == []
    assert coverage.domain_disposition.blocked_domain_ids == ["orders"]
    assert coverage.candidate_classification.blocked_candidate_ids == [
        f"orders.action_{index}" for index in range(20)
    ]
    assert not hasattr(coverage, "score")
    assert not hasattr(coverage, "usable")


def test_source_connected_does_not_upgrade_source_authorization_or_action_safety() -> None:
    coverage = analyze_coverage(
        report=_report_with_source_observation(),
        scope_inventory=_inventory(),
    )
    assert coverage.identity_and_upstream_authorization.status == "source_final"
    assert coverage.conflict_control_fidelity.status == "unknown"
```

- [x] **Step 2: Run tests and verify missing fields**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_coverage.py`

Expected: tests fail because domain Coverage axes do not exist.

- [x] **Step 3: Add typed independent axes**

Add these fields to the current Coverage report, using `not_declared` when domain sidecars are absent:

```python
domain_disposition: DomainDispositionCoverage
business_goal_coverage: BusinessGoalCoverage
candidate_classification: CandidateClassificationCoverage
semantics_provenance: SemanticsProvenanceCoverage
identity_and_upstream_authorization: AuthorizationBoundaryCoverage
lifecycle_constructability: LifecycleConstructabilityCoverage
conflict_control_fidelity: StrategyFidelityCoverage
idempotency_fidelity: StrategyFidelityCoverage
outcome_resolution: StrategyFidelityCoverage
verification_level: VerificationLevelCoverage
cross_domain_dependencies: CrossDomainDependencyCoverage
user_decision_trace: UserDecisionTraceCoverage
```

Do not add a combined status, score, percentage, or usable field.

- [x] **Step 4: Implement deterministic axis analysis**

Consume `ValidationReport.domain_map`, candidate ledger, decisions, Scope links, Operations, Capabilities, and diagnostics. A route can be structurally closed while its candidate remains blocked. User-deferred candidates appear only in the user decision axis and do not count as rejected or verified.

- [x] **Step 5: Run Coverage regression**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_coverage.py tests/unit/compiler/test_analysis_tools.py tests/integration/test_cli_milestone2.py -k 'coverage'`

Expected: all tests pass; existing projects serialize the new axes as `not_declared` without changing prior axis semantics.

- [x] **Step 6: Commit domain Coverage**

```bash
git add packages/acc-core/src/acc_core/coverage tests/unit/compiler/test_domain_coverage.py tests/unit/compiler/test_analysis_tools.py tests/integration/test_cli_milestone2.py
git commit -m "feat(coverage): 报告领域与 Action 候选覆盖"
```

### Task 6: Deterministic domain workflow CLI

**Files:**
- Create: `packages/acc-core/src/acc_core/cli/domains.py`
- Modify: `packages/acc-core/src/acc_core/cli/main.py`
- Test: `tests/unit/core/test_domain_cli.py`
- Test: `tests/integration/test_cli_milestone2.py`

- [x] **Step 1: Write RED CLI tests**

```python
def test_domains_status_recommends_one_next_domain(current_project: Path) -> None:
    result = run_cli("domains", "status", str(current_project), "--json")
    assert result.exit_code == 0
    assert result.envelope["result"]["next_domain"] == {
        "id": "identity",
        "reason": "required_by:orders",
    }


def test_domains_review_never_accepts_route_ids_as_user_choices(
    current_project: Path,
    tmp_path: Path,
) -> None:
    decision = tmp_path / "orders-decision.json"
    decision.write_text(
        json.dumps(
            _decision_document(accepted_capability_ids=["POST /api/orders/{order_id}/cancel"])
        ),
        encoding="utf-8",
    )
    result = run_cli(
        "domains",
        "review",
        str(current_project),
        "--domain",
        "orders",
        "--decision",
        str(decision),
        "--check",
        "--json",
    )
    assert result.exit_code == EXIT_INPUT
    assert result.envelope["error"]["code"] == "ACC_DOMAIN_BUSINESS_GOAL_REQUIRED"
```

- [x] **Step 2: Run tests and verify parser failure**

Run: `uv run --frozen pytest -q tests/unit/core/test_domain_cli.py`

Expected: argparse rejects the unknown `domains` command.

- [x] **Step 3: Add non-interactive structured commands**

Add:

```text
acc domains status PROJECT --json
acc domains show PROJECT --domain DOMAIN_ID --json
acc domains review PROJECT --domain DOMAIN_ID --decision DECISION_FILE --check --json
acc domains impact PROJECT --changed-evidence CHANGED_EVIDENCE_FILE --json
```

`status` and `show` are read-only. `review --check` validates a proposed DomainDecision but does not write. A later explicit `--write` may atomically install a validated decision; it must reject route IDs where business goal or candidate IDs are required. No command calls an LLM.

- [x] **Step 4: Implement next-domain ordering**

Use topological dependency order first, then domain risk and stable ID. A user-provided `preferred_order` in DomainMap can reorder only nodes whose dependencies are already complete. Cycles return `ACC_DOMAIN_DEPENDENCY_CYCLE` with exact domain IDs.

- [x] **Step 5: Run CLI tests and help snapshot**

Run: `uv run --frozen pytest -q tests/unit/core/test_domain_cli.py tests/unit/core/test_cli.py tests/integration/test_cli_milestone2.py`

Expected: all tests pass and `acc domains --help` lists only deterministic commands.

- [x] **Step 6: Commit the domain CLI**

```bash
git add packages/acc-core/src/acc_core/cli tests/unit/core/test_domain_cli.py tests/unit/core/test_cli.py tests/integration/test_cli_milestone2.py
git commit -m "feat(cli): 提供领域向导确定性状态命令"
```

### Task 7: Evidence-bound Action conflict and idempotency strategies

**Files:**
- Modify: `packages/acc-core/src/acc_core/models/actions.py`
- Modify: `packages/acc-core/src/acc_core/contracts/models.py`
- Modify: `packages/acc-core/src/acc_core/compiler/actions.py`
- Modify: `packages/acc-core/src/acc_core/compiler/ir.py`
- Test: `tests/unit/core/test_action_models.py`
- Test: `tests/unit/compiler/test_action_compiler.py`

- [x] **Step 1: Write RED tests for non-optimistic but evidenced source safety**

```python
def test_server_serialized_transition_requires_state_predicate_and_status_query() -> None:
    operation = _action_operation(
        effect="transition",
        retry={"mode": "never"},
        idempotency={
            "mode": "state_idempotent",
            "state_pointer": "/data/status",
            "terminal_values": ["cancelled"],
        },
        concurrency={
            "mode": "server_serialized_state_predicate",
            "state_pointer": "/data/status",
            "allowed_values": ["queued", "running"],
        },
    )
    proof = prove_action_capability(
        _action_capability(preview="jobs.status", commit="jobs.cancel", status="jobs.status"),
        {"jobs.status": _read_operation(), "jobs.cancel": operation},
    )
    assert proof.ok
    assert proof.approval_required


def test_server_serialized_transition_rejects_retry_or_missing_implementation_claim() -> None:
    proof = prove_action_capability(
        _action_capability(preview="jobs.status", commit="jobs.cancel", status="jobs.status"),
        {
            "jobs.status": _read_operation(),
            "jobs.cancel": _server_serialized_operation(retry="idempotent_only"),
        },
    )
    assert "ACC_COMPILE_ACTION_SERVER_SERIALIZED_RETRY_FORBIDDEN" in proof.codes
```

- [x] **Step 2: Run Action model/compiler tests and verify enum failures**

Run: `uv run --frozen pytest -q tests/unit/core/test_action_models.py tests/unit/compiler/test_action_compiler.py -k 'server_serialized or state_idempotent'`

Expected: model validation rejects the new strategy modes.

- [x] **Step 3: Replace two-mode contracts with discriminated strategy unions**

```python
class OptimisticTokenConcurrency(StrictModel):
    # Keep the current wire discriminator. It already means optimistic token
    # capture plus Runtime-owned precondition injection.
    mode: Literal["required"]
    token: ConcurrencyTokenSourceV2
    precondition: RuntimeInjectionTargetV2


class ServerSerializedStatePredicate(StrictModel):
    mode: Literal["server_serialized_state_predicate"]
    state_pointer: JsonPointer
    allowed_values: list[JsonValue] = Field(min_length=1)


class UnsupportedConcurrency(StrictModel):
    mode: Literal["not_supported"]


type ConcurrencyContractV2 = Annotated[
    OptimisticTokenConcurrency | ServerSerializedStatePredicate | UnsupportedConcurrency,
    Field(discriminator="mode"),
]


class StateIdempotency(StrictModel):
    mode: Literal["state_idempotent"]
    state_pointer: JsonPointer
    terminal_values: list[JsonValue] = Field(min_length=1)


class UnsupportedIdempotency(StrictModel):
    mode: Literal["unsupported", "runtime_deduplicate"]


class SourceKeyIdempotency(StrictModel):
    mode: Literal["source_key"]
    target: RuntimeInjectionTargetV2


type IdempotencyContractV2 = Annotated[
    UnsupportedIdempotency | SourceKeyIdempotency | StateIdempotency,
    Field(discriminator="mode"),
]
```

Keep existing source-key behavior under `mode: source_key`. Retain `unsupported` for honestly unsupported cases. The existing `concurrency.mode: required` wire shape remains byte-for-byte valid and is modeled internally as the optimistic-token branch; do not rename its discriminator. Do not implement `compensating_transaction` or saga execution in this slice.

- [x] **Step 4: Add field-level ActionSemantics provenance**

Replace the single authority claim with sorted claims for `effect`, `risk`, `reversibility`, `retry`, `idempotency`, `conflict_control`, and `outcome_resolution`. Each claim references existing Evidence and an `evidence_pointer`. Only `implementation`, `contract`, or `test` authority can prove safety; observation cannot.

- [x] **Step 5: Implement the exact compiler matrix**

Rules:

- `concurrency.mode: required` optimistic token: preserve current update/delete/transition behavior;
- server-serialized predicate: allow transition/delete only, require `retry=never`, explicit approval, a preview read, a status read, and implementation/test claims for conflict control plus state idempotency;
- state-idempotent transition: terminal values must be disjoint from allowed source states;
- create/execute: continue requiring source-key idempotency in this slice;
- unsupported conflict control: continue rejecting update/delete/transition.

- [x] **Step 6: Run complete Core Action regression**

Run: `uv run --frozen pytest -q tests/unit/core/test_action_models.py tests/unit/core/test_source_contract_models.py tests/unit/compiler/test_action_compiler.py tests/unit/compiler/test_compiler.py`

Expected: all tests pass; existing optimistic-token projects compile without semantic changes.

- [x] **Step 7: Commit strategy expansion**

```bash
git add packages/acc-core/src/acc_core/models/actions.py packages/acc-core/src/acc_core/contracts/models.py packages/acc-core/src/acc_core/compiler/actions.py packages/acc-core/src/acc_core/compiler/ir.py tests/unit/core/test_action_models.py tests/unit/core/test_source_contract_models.py tests/unit/compiler/test_action_compiler.py tests/unit/compiler/test_compiler.py
git commit -m "feat(actions): 支持证据化服务端状态并发策略"
```

### Task 8: Runtime enforcement for expanded Action strategies

**Files:**
- Modify: `packages/acc-runtime/src/acc_runtime/actions/runtime_executor.py`
- Modify: `packages/acc-runtime/src/acc_runtime/providers/http.py`
- Modify: `packages/acc-runtime/src/acc_runtime/actions/coordinator.py`
- Test: `tests/unit/runtime/actions/test_runtime_executor.py`
- Test: `tests/unit/runtime/test_http_action_provider.py`
- Test: `tests/integration/runtime/test_action_mcp_gateway.py`

- [x] **Step 1: Write RED tests for server-serialized execution**

```python
@pytest.mark.anyio
async def test_server_serialized_transition_never_replays_an_ambiguous_source_call() -> None:
    provider = _provider(
        preview={"data": {"status": "running"}},
        mutation_error=HttpUnauthorizedError(),
    )
    coordinator = _coordinator(_server_serialized_ir(), provider=provider)
    prepared = await coordinator.prepare("jobs.cancel", {"job_id": "job-1"}, _principal())
    approved = await _approve(coordinator, prepared, _principal())

    with pytest.raises(ActionStateConflictError, match="outcome is unknown"):
        await coordinator.commit(approved.action_handle, _principal())

    assert provider.mutation_calls == 1
    assert (
        await coordinator.status(approved.action_handle, _principal())
    ).status == "outcome_unknown"
```

- [x] **Step 2: Run runtime tests and verify unsupported strategy failure**

Run: `uv run --frozen pytest -q tests/unit/runtime/actions/test_runtime_executor.py tests/unit/runtime/test_http_action_provider.py -k 'server_serialized'`

Expected: Runtime rejects the compiled strategy as invalid.

- [x] **Step 3: Enforce each strategy without weakening identity or approval**

For existing `concurrency.mode: required`, continue optimistic-token capture/injection. For `server_serialized_state_predicate`, validate preview status against `allowed_values`, inject no fake version, require approval, call the mutation once, and perform the declared status read after a definitive response. On timeout, disconnect, 401, or undecodable ambiguous response, store `outcome_unknown` and never automatically replay.

- [x] **Step 4: Preserve source authorization as final**

Do not add RBAC evaluation. Continue sending the current Principal source authentication on every read/mutation. Source 401/403/404 map to stable errors; only 401 marks the current Gateway session for reauthentication. No source permission response can expand DeploymentPolicy or effective scopes.

- [x] **Step 5: Run official SDK Action regression**

Run: `uv run --frozen pytest -q tests/unit/runtime/actions tests/unit/runtime/test_http_action_provider.py tests/integration/runtime/test_action_mcp_gateway.py tests/e2e/test_multi_user_http_gateway.py`

Expected: all tests pass; A/B isolation, approval, one mutation, status, logout, and secret scans remain green.

- [x] **Step 6: Commit Runtime strategy support**

```bash
git add packages/acc-runtime/src/acc_runtime/actions packages/acc-runtime/src/acc_runtime/providers/http.py tests/unit/runtime/actions tests/unit/runtime/test_http_action_provider.py tests/integration/runtime/test_action_mcp_gateway.py tests/e2e/test_multi_user_http_gateway.py
git commit -m "feat(runtime): 执行服务端状态保护的 Action"
```

### Task 9: ACC Engineer domain wizard and Action templates

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
- Modify: `skills/acc-engineer/guides/08-refine.md`
- Modify: `skills/acc-engineer/guides/09-handoff.md`
- Create: `skills/acc-engineer/templates/domain-map.yaml`
- Create: `skills/acc-engineer/templates/capability-candidates.yaml`
- Create: `skills/acc-engineer/templates/domain-decision.yaml`
- Create: `skills/acc-engineer/templates/action-operation.yaml`
- Create: `skills/acc-engineer/templates/action-capability.yaml`
- Create: `skills/acc-engineer/references/examples/server-serialized-transition.yaml`
- Modify: `tests/unit/skill/test_skill_structure.py`

- [x] **Step 1: Write RED Skill structure assertions**

```python
def test_skill_requires_domain_start_exception_and_end_confirmation() -> None:
    text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "confirm domain policy" in text
    assert "ask only evidence conflicts or business decisions" in text
    assert "confirm the domain decision" in text
    assert "never present the complete route list for selection" in text


def test_skill_ships_platform_neutral_action_templates() -> None:
    action = load_yaml(SKILL_ROOT / "templates/action-operation.yaml")
    assert action["kind"] == "action"
    assert set(action["http"]["safety"]) == {
        "effect",
        "risk",
        "reversibility",
        "retry",
        "idempotency",
        "concurrency",
    }
```

- [x] **Step 2: Run Skill tests and verify missing templates/text**

Run: `uv run --frozen pytest -q tests/unit/skill/test_skill_structure.py`

Expected: tests fail for missing domain and Action templates.

- [x] **Step 3: Rewrite the Skill phases around the domain wizard**

Required flow:

1. global shallow discovery;
2. propose DomainMap and recommended order;
3. activate exactly one domain;
4. ask the user to confirm business goals and DomainPolicy;
5. deep scan the active domain;
6. automatically model evidence-clear candidates;
7. ask one question at a time only for evidence conflicts, business ambiguity, high-risk policy, or missing user-controlled test boundaries;
8. present independent domain axes and confirm DomainDecision;
9. proceed to the next dependency-ready domain.

The Skill must state that upstream JWT authorization is final, Scope only narrows, and Action approval confirms this execution rather than granting source permission.

- [x] **Step 4: Add complete platform-neutral templates**

Templates must use neutral IDs such as `orders.cancel`, conspicuous non-secret sentinel Evidence values that fail validation until replaced, and both optimistic-token and server-serialized examples. They must not contain any project path, permission string, or entity from an existing integration.

- [x] **Step 5: Validate Skill and templates**

Run: `uv run --frozen pytest -q tests/unit/skill && uv run --frozen python /Users/chou/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/acc-engineer`

Expected: all Skill tests pass and quick validation prints `Skill is valid!`.

- [x] **Step 6: Commit the domain wizard Skill**

```bash
git add skills/acc-engineer tests/unit/skill/test_skill_structure.py
git commit -m "feat(skill): 按业务领域引导能力确认"
```

### Task 10: Incremental evidence impact and versioned change requests

**Files:**
- Create: `packages/acc-core/src/acc_core/domains/impact.py`
- Modify: `packages/acc-core/src/acc_core/domains/__init__.py`
- Modify: `packages/acc-core/src/acc_core/cli/domains.py`
- Test: `tests/unit/compiler/test_domain_impact.py`
- Test: `tests/unit/core/test_domain_cli.py`

- [x] **Step 1: Write RED impact tests**

```python
def test_changed_evidence_marks_only_dependent_domains_stale() -> None:
    impact = analyze_domain_impact(
        domain_map=_domain_map(identity_to_orders=True, unrelated="content"),
        candidates=_candidate_ledger(),
        decisions=_completed_decisions(),
        changed_evidence_ids={"orders-service"},
    )
    assert impact.stale_domain_ids == ("orders",)
    assert impact.unaffected_domain_ids == ("content", "identity")


def test_security_change_produces_fail_closed_change_request() -> None:
    request = build_change_request(
        impact=_security_impact("orders.cancel"),
        previous_decision=_completed_order_decision(),
    )
    assert request.deployment_effect == "disable_affected_capabilities"
    assert request.affected_capability_ids == ["orders.cancel"]
```

- [x] **Step 2: Run impact tests and verify missing module**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_impact.py`

Expected: collection fails because `acc_core.domains.impact` is missing.

- [x] **Step 3: Implement evidence-to-candidate-to-domain graph traversal**

The pure analyzer accepts changed Evidence IDs or digests; it does not run Git. Traverse exact candidate claims, domain dependencies, Capability/Operation Evidence, and Interaction claims. Security-relevant changes include identity binding, context isolation, effect, risk, authorization boundary, conflict control, idempotency, approval, and outcome resolution.

- [x] **Step 4: Emit deterministic DomainChangeRequest documents**

Requests contain old decision revision, affected candidate/capability IDs, changed evidence, security classification, recommended next status, and exact impact. Security changes set `deployment_effect=disable_affected_capabilities`; descriptive-only changes set `deployment_effect=audit_warning`.

- [x] **Step 5: Connect `acc domains impact` to JSON input**

The command reads a bounded JSON file containing changed Evidence IDs/digests and prints impact plus a canonical proposed change request. `--write` atomically writes under `domain-change-requests/`; it never invokes Git or an LLM.

- [x] **Step 6: Run impact and CLI regression**

Run: `uv run --frozen pytest -q tests/unit/compiler/test_domain_impact.py tests/unit/core/test_domain_cli.py tests/unit/core/test_project_domain_validation.py`

Expected: all tests pass.

- [x] **Step 7: Commit incremental impact support**

```bash
git add packages/acc-core/src/acc_core/domains packages/acc-core/src/acc_core/cli/domains.py tests/unit/compiler/test_domain_impact.py tests/unit/core/test_domain_cli.py tests/unit/core/test_project_domain_validation.py
git commit -m "feat(core): 追踪领域证据变更影响"
```

### Task 11: Cross-industry end-to-end fixtures

**Files:**
- Create: `tests/fixtures/domains/crm/`
- Create: `tests/fixtures/domains/erp/`
- Create: `tests/fixtures/domains/finance/`
- Create: `tests/fixtures/domains/content/`
- Create: `tests/fixtures/domains/jobs/`
- Create: `tests/fixtures/domains/permissions/`
- Create: `tests/fixtures/domains/mobile/`
- Create: `tests/e2e/test_domain_guided_projects.py`

- [x] **Step 1: Write the parameterized RED E2E test**

```python
@pytest.mark.parametrize(
    ("fixture", "expected_domain", "expected_fact"),
    [
        ("crm", "customer_management", "search_to_detail"),
        ("erp", "order_fulfillment", "cross_module_workflow"),
        ("finance", "financial_controls", "optimistic_high_risk_action"),
        ("content", "content_publication", "server_serialized_transition"),
        ("jobs", "job_operations", "outcome_resolution"),
        ("permissions", "access_governance", "upstream_authoritative"),
        ("mobile", "mobile_experience", "client_only_candidate"),
    ],
)
def test_domain_fixture_validates_compiles_and_reports_independent_axes(
    fixture: str,
    expected_domain: str,
    expected_fact: str,
) -> None:
    root = FIXTURES / fixture
    report = validate_project(root)
    assert report.ok
    compilation = compile_project(root)
    assert compilation.ok
    coverage = analyze_coverage(report, report.scope_inventory)
    assert expected_domain in coverage.domain_disposition.completed_domain_ids
    assert expected_fact in load_expected_facts(root)
```

- [x] **Step 2: Run E2E and verify fixtures are absent**

Run: `uv run --frozen pytest -q tests/e2e/test_domain_guided_projects.py`

Expected: seven failures because fixture projects do not exist.

- [x] **Step 3: Create complete current-format fixture projects**

Each fixture contains Project, ScopeInventory, DomainMap, Candidate Ledger, DomainDecision, Operations, Capabilities, SourceContracts, CapabilityQuality, Policies, Evals, Evidence, and expected facts. Permission fixture must prove source JWT final authorization without ACC RBAC. Finance and content fixtures exercise the two supported conflict strategies. Mobile includes a client-only candidate with no fabricated route.

- [x] **Step 4: Add malicious negative fixtures**

Cover AI-reported eligible Action with missing claims, source permission incorrectly promoted to ACC grant, candidate hidden as ineligible, stale completed decision, cross-domain dependency cycle, and project-specific strategy enum injection. Assert stable Core diagnostics and no compiled Pack.

- [x] **Step 5: Run E2E, compiler, Skill, Runtime, and Pack regression**

Run: `uv run --frozen pytest -q tests/e2e/test_domain_guided_projects.py tests/unit/compiler tests/unit/skill tests/unit/runtime tests/integration/pack`

Expected: all tests pass.

- [x] **Step 6: Commit cross-industry acceptance**

```bash
git add tests/fixtures/domains tests/e2e/test_domain_guided_projects.py
git commit -m "test(domains): 验证跨行业领域向导合同"
```

### Task 12: Documentation, schema reproducibility, and release gates

**Files:**
- Modify: `README.md`
- Modify: `docs/progress.md`
- Create: `docs/architecture/adr/008-ai-domain-guided-discovery.md`
- Modify: `docs/architecture/adr/006-evidence-bound-operations.md`
- Modify: `docs/architecture/adr/007-versioned-quality-and-action-safety.md`
- Test: `tests/unit/skill/test_skill_structure.py`

- [x] **Step 1: Write RED documentation assertions**

Assert public docs contain: business-goal selection instead of route selection; source JWT final authorization; ACC Scope only narrows; unknown candidates cannot disappear as ineligible; domain decisions are versioned; Action Coverage is independent; Runtime has no LLM.

- [x] **Step 2: Run documentation tests and verify missing public wording**

Run: `uv run --frozen pytest -q tests/unit/skill/test_skill_structure.py -k 'domain or authorization'`

Expected: new assertions fail until docs are updated.

- [x] **Step 3: Update public architecture and progress truthfully**

ADR 008 records the domain-wizard decision and AI/Core boundary. ADR 006 clarifies typed candidate evidence. ADR 007 records expanded Action strategies and source authorization finality. README shows the global-scan/domain-loop flow and verification levels. Do not claim production AI scanning or source-connected Action verification unless those exact paths passed.

- [x] **Step 4: Regenerate schemas twice and compare**

Run:

```bash
first=$(mktemp -d /tmp/acc-domain-schema-first.XXXXXX)
second=$(mktemp -d /tmp/acc-domain-schema-second.XXXXXX)
uv run --frozen acc schema --output "$first" --json
uv run --frozen acc schema --output "$second" --json
diff -ru "$first" "$second"
diff -ru schemas "$first"
```

Expected: both diffs are empty.

- [x] **Step 5: Run full release gates**

Run:

```bash
uv lock --check
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy packages tests skills/acc-engineer/scripts
uv run --frozen pytest -q
git diff --check
```

Expected: all commands exit 0; only explicitly documented pre-existing warnings may remain.

- [x] **Step 6: Perform deterministic Pack checks for one Read-only and two Action fixtures**

Build each selected fixture twice inside its project `build/` directory, compare SHA-256, inspect archive members, and scan for JWT-like values, Bearer values, private keys, raw user confirmations, and unredacted Evidence contents. Expected: each pair is byte-identical and secret scans return zero.

- [x] **Step 7: Commit documentation and release evidence**

```bash
git add README.md docs schemas tests/unit/skill/test_skill_structure.py
git commit -m "docs(domains): 交付领域向导能力发现流程"
```

## Final acceptance checklist

- [x] Every discovered route/interaction candidate is classified, explicitly unclassified, or blocked; none disappears through a generic ineligible reason.
- [x] The user confirms one domain policy, then only exception questions, then one versioned domain decision.
- [x] User decisions reference business goals/candidate IDs, never raw route selection.
- [x] Source JWT and source APIs remain the final user/resource authorization authority.
- [x] ACC Scope, DeploymentPolicy, and Action approval only narrow authority.
- [x] Existing optimistic-token Actions remain valid.
- [x] Server-serialized state transitions are accepted only with implementation/test claims, preview/status reads, retry never, state idempotency, and approval.
- [x] Coverage reports independent domain and Action axes without score or usable.
- [x] Evidence drift creates explicit stale decisions and change requests.
- [x] Cross-industry fixtures contain no project-specific branches in production code.
- [x] Full tests, Ruff, mypy, schema reproducibility, deterministic Packs, and secret scans pass.
