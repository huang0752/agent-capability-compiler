from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import TypeAdapter

from acc_core.models import Capability, Eval, Operation, Policy

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "acc-engineer"


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


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
