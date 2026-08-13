from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import TypeAdapter, ValidationError

from acc_core.models import Capability, Eval, Operation, Policy

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "acc-engineer"


def _readme_mermaid_blocks() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return [section.split("```", maxsplit=1)[0] for section in readme.split("```mermaid\n")[1:]]


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_readme_opens_with_an_end_to_end_mermaid_architecture() -> None:
    blocks = _readme_mermaid_blocks()
    assert blocks
    overview = blocks[0]
    for label in (
        "已有系统（只读发现）",  # noqa: RUF001
        "编译期：AI 辅助",  # noqa: RUF001
        "ACC 确定性工具链",
        "Capability Pack",
        "运行期：无 LLM",  # noqa: RUF001
        "源 API<br/>最终鉴权",
    ):
        assert label in overview
    assert "```text\n已有系统源码" not in (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_has_compile_and_runtime_architecture_details() -> None:
    blocks = _readme_mermaid_blocks()
    assert len(blocks) == 4
    compile_time, runtime = blocks[2:]
    for label in (
        "Evidence / Scope Inventory",
        "DomainMap / Candidate Ledger",
        "一次处理一个领域",
        "DomainDecision",
        "Schema / Closure / Action Safety",
        "Capability IR",
        "Evidence 缺口 / 冲突",
    ):
        assert label in compile_time
    for label in (
        "MCP stdio",
        "streamable HTTP Gateway",
        "PrincipalContext",
        "CapabilityMcpServer",
        "PrincipalCapabilityMcpServer",
        "ActionRuntimeDependencies",
        "ActionCoordinator",
        "RuntimeActionWorkflowExecutor",
        "Read tool call",
        "prepare",
        "approve",
        "commit",
        "status",
        "DeploymentPolicy",
        "源 JWT / 源 API 最终鉴权",
    ):
        assert label in runtime

    assert 'VALIDATE -->|"通过"| IR --> PACK_BUILD' in compile_time
    assert 'VALIDATE -.->|"独立报告"| ANALYZE' in compile_time
    assert 'PACK_BUILD -.->|"发布 / 验收输入"| ANALYZE' in compile_time
    assert "ANALYZE --> IR" not in compile_time
    assert "ANALYZE --> PACK_BUILD" not in compile_time

    for edge in (
        "STDIO --> STDIO_SERVER --> RUNTIME_CORE",
        "GATEWAY --> PRINCIPAL --> PRINCIPAL_SERVER",
        "PACK_LOAD --> RUNTIME_CORE",
        "PACK_LOAD --> ACTION_EXEC",
        "ACTION_DEPS --> COORDINATOR",
        "ACTION_EXEC --> COORDINATOR",
        'PRINCIPAL_SERVER -->|"Read"| RUNTIME_CORE',
        "PRINCIPAL_SERVER --> ACTION_TOOLS --> COORDINATOR",
        'WORKFLOW -->|"HttpProvider"| PROVIDER',
        'ACTION_EXEC -->|"同一 HttpProvider"| PROVIDER',
        'PREPARE -->|"proof 要求审批"| APPROVE --> COMMIT',
        'PREPARE -->|"无需审批, Store 自动 approved"| COMMIT',
        "COORDINATOR --> STATUS",
        "COORDINATOR <--> STATE",
    ):
        assert edge in runtime
    assert "PACK_LOAD --> PRINCIPAL_SERVER" not in runtime
    assert "PACK_LOAD --> STDIO_SERVER" not in runtime
    assert "STDIO --> RUNTIME_CORE" not in runtime
    assert "STATUS --> PROVIDER" not in runtime


def test_readme_mermaid_source_has_stable_structure_smoke() -> None:
    blocks = _readme_mermaid_blocks()
    assert len(blocks) == 4
    for block in blocks:
        assert block.startswith("flowchart ")
        assert block.count("subgraph ") == sum(line.strip() == "end" for line in block.splitlines())
        node_ids = re.findall(r"^\s*([A-Z][A-Z0-9_]*)\[", block, flags=re.MULTILINE)
        assert node_ids
        assert len(node_ids) == len(set(node_ids))
    assert "baogao" not in "\n".join(blocks).lower()


def test_readme_does_not_describe_action_approval_or_status_as_fixed_steps() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for stale_statement in (
        "并通过 `approve → commit → status`",
        "Read tool 不能绕过 `prepare → approve → commit → status`",
        "Scope、审批、幂等和并发门禁",
        "Action 使用显式 `prepare → approve → commit → status` 状态机",
        "专用 `prepare → approve → commit → status` 工具",
    ):
        assert stale_statement not in readme


def test_skill_has_required_platform_neutral_structure_without_placeholders() -> None:
    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert skill_text.startswith("---\nname: acc-engineer\n")
    assert "TODO" not in skill_text
    assert len(skill_text.splitlines()) < 500
    assert not (SKILL / "README.md").exists()
    assert (SKILL / "HARNESS.md").is_file()
    assert (SKILL / "agents" / "openai.yaml").is_file()

    required_guides = [
        f"{index:02d}-{name}.md"
        for index, name in enumerate(
            (
                "preflight",
                "analyze",
                "model",
                "plan",
                "implement",
                "validate",
                "test",
                "refine",
                "handoff",
            ),
            start=1,
        )
    ]
    assert sorted(path.name for path in (SKILL / "guides").glob("*.md")) == required_guides
    for guide in required_guides:
        text = (SKILL / "guides" / guide).read_text(encoding="utf-8")
        for heading in ("## 输入", "## 动作", "## 门禁", "## 输出", "## 停止条件"):
            assert heading in text


def test_skill_requires_explicit_scope_audit_and_validation_level() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    guides = "\n".join(path.read_text(encoding="utf-8") for path in (SKILL / "guides").glob("*.md"))

    assert "system_complete" in skill
    assert "只有用户明确" in skill
    assert "scope_audit.py" in skill
    assert "浅层全局发现" in harness
    assert "source_scope" in guides
    assert "offline_candidate" in guides
    assert "source_connected_verified" in guides
    assert "artifact-manifest.json" in guides
    assert (SKILL / "scripts" / "scope_audit.py").is_file()
    assert (SKILL / "scripts" / "artifact_manifest.py").is_file()


def test_system_complete_contract_cannot_collapse_to_read_only() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    preflight = (SKILL / "guides" / "01-preflight.md").read_text(encoding="utf-8")
    validate = (SKILL / "guides" / "06-validate.md").read_text(encoding="utf-8")
    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")
    scope_audit = (SKILL / "scripts" / "scope_audit.py").read_text(encoding="utf-8")
    public = (ROOT / "README.md").read_text(encoding="utf-8")
    contract = "\n".join((skill, harness, preflight, validate, handoff, public))

    for surface in (
        "Read",
        "Create",
        "Update",
        "Delete",
        "transition",
        "execute",
        "composite",
    ):
        assert surface in contract
    for gate in (
        "blocked_on_evidence",
        "write-sandbox",
        "idempotency",
        "concurrency",
        "approval",
        "system_complete",
    ):
        assert gate in skill + harness
    assert "Read-only subset" in skill + harness
    assert "eligible Action intent cannot be completed by exclusion" in harness
    assert "只有用户明确要求 Action 时" not in preflight
    assert "blocked_on_evidence=0" in validate
    assert "不能使用 complete 措辞" in handoff
    assert "ACC_SCOPE_ACTION_EXCLUSION_FORBIDDEN" in scope_audit


def test_guides_reserve_mvp_language_for_explicit_pilot_scope() -> None:
    guides = "\n".join(path.read_text(encoding="utf-8") for path in (SKILL / "guides").glob("*.md"))
    for stale in (
        "新需求超出只读 MVP",
        "候选仍符合只读 MVP",
        "MVP 候选仅使用",
    ):
        assert stale not in guides

    for name in ("04-plan.md", "08-refine.md", "09-handoff.md"):
        assert "MVP" not in (SKILL / "guides" / name).read_text(encoding="utf-8")

    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")
    output = handoff.split("## 输出", maxsplit=1)[1].split("## 停止条件", maxsplit=1)[0]
    assert "scope-audit-report.json" in output


def test_openai_metadata_and_platform_wrappers_delegate_to_the_single_harness() -> None:
    metadata = _yaml(SKILL / "agents" / "openai.yaml")
    interface = metadata["interface"]
    assert interface["display_name"] == "ACC Engineer"
    assert 25 <= len(interface["short_description"]) <= 64
    assert "read-only" not in interface["short_description"]
    assert "$acc-engineer" in interface["default_prompt"]

    command_files = sorted((ROOT / "integrations" / "claude-code" / "commands").glob("*.md"))
    assert [path.name for path in command_files] == [
        "acc-onboard.md",
        "acc-refine.md",
        "acc-test.md",
    ]
    for command in command_files:
        text = command.read_text(encoding="utf-8")
        assert "skills/acc-engineer/SKILL.md" in text
        assert "HARNESS.md" in text
        assert len(text.splitlines()) <= 6


def test_templates_track_current_strict_public_models() -> None:
    digest = f"sha256:{hashlib.sha256(b'captured evidence').hexdigest()}"
    operation = _yaml(SKILL / "templates" / "operation.yaml")
    assert "credential_ref" not in operation["http"]
    operation["evidence"][0]["digest"] = digest
    TypeAdapter(Operation).validate_python(operation)
    TypeAdapter(Capability).validate_python(_yaml(SKILL / "templates" / "capability.yaml"))
    Policy.model_validate(_yaml(SKILL / "templates" / "policy.yaml"))
    Eval.model_validate(_yaml(SKILL / "templates" / "eval.yaml"))
    Eval.model_validate(_yaml(SKILL / "references" / "examples" / "permission-negative-eval.yaml"))
    assert isinstance(_yaml(SKILL / "templates" / "system-map.yaml"), dict)
    plan = _yaml(SKILL / "templates" / "capability-plan.yaml")
    assert isinstance(plan, dict)
    assert plan["capabilities"][0]["runtime_only_inputs"] == [
        "base_url_ref",
        "provider_auth",
    ]
    scope = _yaml(SKILL / "templates" / "scope-inventory.yaml")
    assert scope["scope"] == {
        "mode": "system_complete",
        "user_confirmation": None,
        "selected_domains": [],
        "exclusion_approval": {
            "approved_route_ids": [],
            "approval_text": None,
        },
    }
    assert scope["exclusion_rules"] == []
    route = scope["routes"][0]
    assert set(route) == {
        "id",
        "domain",
        "method",
        "kind",
        "effect",
        "path",
        "evidence_sources",
        "eligibility",
        "disposition",
        "operation_id",
        "capability_ids",
        "reason",
        "usage_evidence_sources",
        "interaction_ids",
        "exclusion_rule_id",
        "exclusion_decision",
    }
    assert "domain" in route
    assert "domain_id" not in route
    assert route["usage_evidence_sources"] == []
    assert route["interaction_ids"] == []
    assert route["exclusion_rule_id"] is None
    assert route["exclusion_decision"] is None
    operation = _yaml(SKILL / "templates" / "system-map.yaml")["candidate_operations"][0]
    assert operation["scope_route_ids"]
    assert plan["coverage"]["scope_inventory"] == "scope-inventory.yaml"
    assert plan["coverage"]["exclusion_decision_refs"] == []
    assert "deliberately_excluded" not in plan["coverage"]
    assert set(plan["coverage"]["route_dispositions"]) == {
        "planned",
        "composed",
        "excluded",
        "blocked_on_evidence",
        "out_of_scope",
    }
    baseline = json.loads(
        (SKILL / "templates" / "coverage-baseline.json").read_text(encoding="utf-8")
    )
    assert baseline["scope_mode"] == "system_complete"
    assert set(baseline["source_scope"]) == {
        "eligible_routes",
        "planned_or_composed",
        "excluded",
        "blocked_on_evidence",
        "unresolved",
    }
    for name in ("preflight-report.json", "coverage-baseline.json"):
        value = json.loads((SKILL / "templates" / name).read_text(encoding="utf-8"))
        assert isinstance(value, dict)


def test_planning_templates_form_a_scope_audit_positive_fixture(tmp_path: Path) -> None:
    project = tmp_path / "acc-project"
    project.mkdir()
    for name in (
        "scope-inventory.yaml",
        "system-map.yaml",
        "capability-plan.yaml",
        "coverage-baseline.json",
    ):
        shutil.copyfile(SKILL / "templates" / name, project / name)

    completed = subprocess.run(
        [
            sys.executable,
            str(SKILL / "scripts" / "scope_audit.py"),
            "--project",
            str(project),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(completed.stdout)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert payload["ok"] is True
    assert payload["diagnostics"] == []


def test_scope_governance_guides_define_each_phase_contract() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    analyze = (SKILL / "guides" / "02-analyze.md").read_text(encoding="utf-8")
    model = (SKILL / "guides" / "03-model.md").read_text(encoding="utf-8")
    plan = (SKILL / "guides" / "04-plan.md").read_text(encoding="utf-8")
    validate = (SKILL / "guides" / "06-validate.md").read_text(encoding="utf-8")
    refine = (SKILL / "guides" / "08-refine.md").read_text(encoding="utf-8")
    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")

    assert "usage_evidence_sources" in analyze
    assert "不解析或执行任何客户端框架源码" in analyze
    for framework_name in ("Vue", "React", "Angular", "Flutter"):
        assert framework_name not in skill + harness + analyze
    assert "planned` 或 `composed" in model
    for contract in (
        "exclusion_rules",
        "exclusion_decision",
        "exclusion_approval",
        "blocked_on_evidence",
        "ineligible",
    ):
        assert contract in plan
    assert "不再要求 `reason`" in plan
    assert "pilot/domain" in plan
    assert "精确一致" in plan
    assert "/routes/{index}/exclusion_decision" in plan
    assert "coverage.scope_mode" in plan
    assert "coverage.scope_inventory" in plan
    assert "warning" in validate
    assert "不阻断" in validate
    for risk in ("重复 decision", "整域零能力", "高排除率", ">= 10", ">= 70%"):
        assert risk in refine
    assert "risk-report.json" in handoff
    assert "HANDOFF.md" in handoff
    assert "全部 warning" in handoff
    assert "offline_candidate" in handoff
    assert "source_connected_verified" in handoff
    assert "前端" in skill + harness
    assert "未精确批准" in skill + harness
    assert len(skill.splitlines()) < 500


def test_public_docs_explain_generic_auth_context_and_validation_boundaries() -> None:
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    example_readme = (ROOT / "examples" / "fastapi-crm" / "README.md").read_text(encoding="utf-8")
    adr = (ROOT / "docs" / "architecture" / "adr" / "003-generic-runtime.md").read_text(
        encoding="utf-8"
    )
    progress = (ROOT / "docs" / "progress.md").read_text(encoding="utf-8")
    combined = "\n".join((root_readme, example_readme, adr, progress))

    for contract in (
        "none",
        "bearer_secret",
        "password_bearer",
        "PrincipalContext",
        "context_bindings",
        "streamable_http",
        "offline_candidate",
        "source_connected_verified",
    ):
        assert contract in combined

    assert "Provider" in root_readme
    assert "credential_ref: CRM_USER_TOKEN" not in root_readme
    assert "baogao-jin 源码或在线源已验证" not in combined


def test_skill_workflow_enforces_provider_auth_and_trusted_context_contracts() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    implement = (SKILL / "guides" / "05-implement.md").read_text(encoding="utf-8")
    test_guide = (SKILL / "guides" / "07-test.md").read_text(encoding="utf-8")
    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")
    schema_index = (SKILL / "references" / "schemas" / "index.md").read_text(encoding="utf-8")
    workflow = "\n".join((skill, harness, implement, test_guide, handoff, schema_index))

    for contract in (
        "provider.auth",
        "none",
        "bearer_secret",
        "password_bearer",
        "PrincipalContext",
        "context_bindings",
        "stdio",
        "streamable_http",
        "environment_secret",
        "gateway_session",
    ):
        assert contract in workflow

    assert "Operation 不得保存 `credential_ref`" in workflow
    assert "Agent 输入" in workflow


def test_skill_requires_evidence_backed_quality_contracts_without_tool_count_bias() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    analyze = (SKILL / "guides" / "02-analyze.md").read_text(encoding="utf-8")
    implement = (SKILL / "guides" / "05-implement.md").read_text(encoding="utf-8")
    refine = (SKILL / "guides" / "08-refine.md").read_text(encoding="utf-8")
    workflow = "\n".join((skill, harness, analyze, implement, refine))

    for contract in (
        "SourceContract",
        "provenance",
        "request_schema",
        "response_schema",
        "Operation 输入",
        "Operation 输出",
        "Capability 输出",
        "可证明",
    ):
        assert contract in workflow

    assert "一接口一工具不是天然缺陷" in workflow
    assert "工具数量" in refine


def test_plan_requires_constructible_selectors_empty_paths_failure_isolation_and_budgets() -> None:
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    plan_guide = (SKILL / "guides" / "04-plan.md").read_text(encoding="utf-8")
    plan = _yaml(SKILL / "templates" / "capability-plan.yaml")
    workflow = "\n".join((harness, plan_guide))

    for contract in (
        "selector acquisition",
        "empty success path",
        "failure isolation",
        "output budget",
    ):
        assert contract in workflow

    quality = plan["capabilities"][0]["quality"]
    assert quality["selector_acquisition"] == {
        "resource_id": {
            "kind": "resource_selector",
            "acquisition": "caller",
            "resource_type": "REPLACE_WITH_RESOURCE_TYPE",
            "producers": [],
        }
    }
    assert quality["empty_success_path"] == "not_applicable"
    assert quality["failure_isolation"] == "fail_fast"
    assert quality["output_budget"] == {
        "max_bytes": 65536,
        "long_text_disclosures": [],
    }


def test_coverage_and_validation_guidance_use_independent_v2_axes_and_three_levels() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    validate = (SKILL / "guides" / "06-validate.md").read_text(encoding="utf-8")
    test_guide = (SKILL / "guides" / "07-test.md").read_text(encoding="utf-8")
    refine = (SKILL / "guides" / "08-refine.md").read_text(encoding="utf-8")
    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")
    coverage = "\n".join((validate, refine, handoff))
    validation = "\n".join((test_guide, handoff))

    for axis in (
        "route_disposition",
        "operation_trace",
        "scenario_coverage",
        "constructability",
        "discoverability_graph",
        "composition",
        "schema_fidelity",
        "output_budget",
        "live_observations",
    ):
        assert axis in coverage
    assert "不生成总分" in coverage
    assert "acc coverage --json" in skill
    for level in (
        "offline_candidate",
        "gateway_offline_verified",
        "source_connected_verified",
    ):
        assert level in validation


def test_skill_requires_explicit_read_effects_and_action_lifecycle() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    plan = (SKILL / "guides" / "04-plan.md").read_text(encoding="utf-8")
    implement = (SKILL / "guides" / "05-implement.md").read_text(encoding="utf-8")
    test_guide = (SKILL / "guides" / "07-test.md").read_text(encoding="utf-8")
    workflow = "\n".join((skill, harness, plan, implement, test_guide))

    assert "Read Operation" in workflow and "`read` effect" in workflow
    assert "prepare → approve → commit → status" in workflow
    assert "不得简单放开 POST" in workflow
    assert "隔离沙箱" in workflow


def test_skill_runs_a_single_domain_wizard_instead_of_asking_users_to_classify_routes() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    guides = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((SKILL / "guides").glob("*.md"))
    }
    workflow = "\n".join((skill, harness, *guides.values()))

    for contract in (
        "全局浅扫",
        "DomainMap",
        "一次只激活一个",
        "DomainPolicy",
        "证据清晰",
        "一次只问一个",
        "独立轴",
        "DomainDecision",
        "依赖已就绪",
    ):
        assert contract in workflow
    assert "绝不把全部 route 交给用户选择" in workflow
    assert "源 JWT" in workflow and "最终裁决" in workflow
    assert "Scope 只能收窄" in workflow
    assert "approval 不是授权" in workflow
    for guide, text in guides.items():
        assert "领域" in text, guide


def test_public_docs_define_domain_discovery_and_authorization_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    progress = (ROOT / "docs" / "progress.md").read_text(encoding="utf-8")
    adr_root = ROOT / "docs" / "architecture" / "adr"
    adr_006 = (adr_root / "006-evidence-bound-operations.md").read_text(encoding="utf-8")
    adr_007 = (adr_root / "007-versioned-quality-and-action-safety.md").read_text(encoding="utf-8")
    adr_008_path = adr_root / "008-ai-domain-guided-discovery.md"
    adr_008 = adr_008_path.read_text(encoding="utf-8") if adr_008_path.is_file() else ""
    public_docs = "\n".join((readme, progress, adr_006, adr_007, adr_008))

    assert "确认业务目标与策略" in readme
    assert "不逐条选择 route" in readme
    assert "全局 AI 扫描由 ACC Engineer Skill 所在的 Coding Agent 执行" in public_docs
    assert "ACC Core 与 Runtime 都不调用 LLM" in public_docs
    assert "源 JWT 与源 API 是最终授权者" in public_docs
    assert "ACC Scope 只能收窄" in public_docs
    assert "unknown 候选不能被伪装为 ineligible 或消失" in public_docs
    assert "版本化的 `DomainDecision`" in public_docs
    assert "十二个相互独立的领域与 Action Coverage 轴" in public_docs
    assert "Runtime 不调用 LLM" in readme
    assert adr_008.startswith("# ADR 008:")

    for unsupported_claim in (
        "当前已完成生产 AI 扫描验证",
        "当前已完成生产源 Action 连接验证",
        "ACC Scope 可以授予源系统权限",
    ):
        assert unsupported_claim not in public_docs


def test_skill_ships_platform_neutral_domain_and_action_templates() -> None:
    required = {
        "domain-map.yaml",
        "capability-candidates.yaml",
        "domain-decision.yaml",
        "action-operation.yaml",
        "action-capability.yaml",
    }
    assert required <= {path.name for path in (SKILL / "templates").glob("*.yaml")}
    example_path = SKILL / "references" / "examples" / "server-serialized-transition.yaml"
    assert example_path.is_file()

    action = _yaml(SKILL / "templates" / "action-operation.yaml")
    assert action["kind"] == "action"
    assert set(action["http"]["safety"]) == {
        "effect",
        "risk",
        "reversibility",
        "retry",
        "idempotency",
        "concurrency",
    }
    assert action["http"]["safety"]["concurrency"]["mode"] == "required"
    with pytest.raises(ValidationError):
        TypeAdapter(Operation).validate_python(action)
    action["evidence"][0]["digest"] = "sha256:" + "a" * 64
    TypeAdapter(Operation).validate_python(action)

    capability = _yaml(SKILL / "templates" / "action-capability.yaml")
    assert capability["kind"] == "action"
    assert set(capability) >= {"action", "preview_workflow", "commit_workflow"}
    TypeAdapter(Capability).validate_python(capability)

    server_serialized = _yaml(example_path)
    safety = server_serialized["operation"]["http"]["safety"]
    assert safety["concurrency"]["mode"] == "server_serialized_state_predicate"
    assert safety["retry"] == {"mode": "never"}
    assert server_serialized["action_semantics"]["outcome_resolution"]["mode"] == ("status_query")

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [*(SKILL / "templates").glob("*.yaml"), example_path]
    ).casefold()
    for forbidden in ("baogao", "jin", "src/api/", "app/api/", "orders.write"):
        assert forbidden not in combined
    assert "replace_with_captured_evidence_digest" in combined


def test_domain_and_server_serialized_templates_preserve_cross_document_closure() -> None:
    candidates = _yaml(SKILL / "templates" / "capability-candidates.yaml")
    decision = _yaml(SKILL / "templates" / "domain-decision.yaml")
    candidate = candidates["candidates"][0]

    assert decision["policy"]["goals"] == [candidate["business_intent"]]
    assert decision["policy"]["approval_required_for"] == [candidate["business_intent"]]
    assert decision["candidate_dispositions"][0]["candidate_id"] == candidate["id"]

    example = _yaml(SKILL / "references" / "examples" / "server-serialized-transition.yaml")
    commit = example["capability"]["commit_workflow"]
    calls = [step["call"]["operation"] for step in commit if "call" in step]
    assert calls == [example["operation"]["id"]]
    assert commit[-1] == {"emit": {"value": "$.steps.cancelled"}}


def test_skill_treats_client_interactions_as_independent_platform_neutral_evidence() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    analyze = (SKILL / "guides" / "02-analyze.md").read_text(encoding="utf-8")
    model = (SKILL / "guides" / "03-model.md").read_text(encoding="utf-8")
    plan = (SKILL / "guides" / "04-plan.md").read_text(encoding="utf-8")
    implement = (SKILL / "guides" / "05-implement.md").read_text(encoding="utf-8")
    validate = (SKILL / "guides" / "06-validate.md").read_text(encoding="utf-8")
    test_guide = (SKILL / "guides" / "07-test.md").read_text(encoding="utf-8")
    refine = (SKILL / "guides" / "08-refine.md").read_text(encoding="utf-8")
    handoff = (SKILL / "guides" / "09-handoff.md").read_text(encoding="utf-8")
    metadata = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
    workflow = "\n".join(
        (
            skill,
            harness,
            analyze,
            model,
            plan,
            implement,
            validate,
            test_guide,
            refine,
            handoff,
            metadata,
        )
    )

    for contract in (
        "ui-interaction-inventory.yaml",
        "InteractionContract",
        "interaction_audit.py",
        "surfaces",
        "events",
        "bindings",
        "defaults",
        "options",
        "conditions",
        "related data",
        "states",
        "unknowns",
    ):
        assert contract in workflow

    assert "hidden/disabled" in workflow
    assert "不是授权" in workflow
    assert "前端默认值" in workflow and "SourceContract" in workflow
    assert "前端条件" in workflow and "SourceContract" in workflow
    assert "只分析已有 `GET`/`HEAD`" not in analyze
    assert "且效果为只读" not in model
    assert "能力需要写操作/生产访问" not in plan
    assert "使用写接口或伪造 Evidence" not in implement
    assert "新需求超出已声明只读范围" not in refine

    for axis in (
        "surface_disposition",
        "interaction_trace",
        "input_binding_fidelity",
        "default_provenance",
        "option_resolution",
        "condition_coverage",
        "related_data_graph",
        "state_scenarios",
        "presentation_projection",
        "client_adapter_evidence",
    ):
        assert axis in validate + refine + handoff
    assert "不生成总分" in validate + refine + handoff

    for level in (
        "headless_verified",
        "source_connected_verified",
        "client_adapter_verified",
    ):
        assert level in test_guide + handoff
    assert "source_connected_verified` 不代表 `client_adapter_verified" in handoff


def test_installers_copy_thin_integrations_and_refuse_overwrite(tmp_path: Path) -> None:
    codex_root = tmp_path / "codex-skills"
    codex = ROOT / "integrations" / "codex" / "install.sh"
    first = subprocess.run(
        ["sh", str(codex), str(codex_root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    second = subprocess.run(
        ["sh", str(codex), str(codex_root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0
    assert (codex_root / "acc-engineer" / "HARNESS.md").is_file()
    assert second.returncode == 1
    assert "Refusing to overwrite" in second.stderr

    commands_root = tmp_path / "claude-commands"
    claude = ROOT / "integrations" / "claude-code" / "install.sh"
    first = subprocess.run(
        ["sh", str(claude), str(commands_root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    second = subprocess.run(
        ["sh", str(claude), str(commands_root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0
    assert sorted(path.name for path in commands_root.glob("*.md")) == [
        "acc-onboard.md",
        "acc-refine.md",
        "acc-test.md",
    ]
    assert second.returncode == 1
    assert "Refusing to overwrite" in second.stderr
