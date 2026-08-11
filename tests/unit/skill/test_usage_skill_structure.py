from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "acc-usage-engineer"


def test_usage_skill_is_bounded_platform_neutral_and_release_gated() -> None:
    documents = [
        (SKILL / "SKILL.md").read_text(encoding="utf-8"),
        (SKILL / "HARNESS.md").read_text(encoding="utf-8"),
        *((path.read_text(encoding="utf-8")) for path in sorted((SKILL / "guides").glob("*.md"))),
    ]
    skill = documents[0]
    combined = "\n".join(documents)

    assert skill.startswith("---\nname: acc-usage-engineer\n")
    assert "TODO" not in combined
    for root in ("source_workspace", "acc_project", "usage_project"):
        assert root in combined
    assert "三者必须互不重叠" in combined
    assert "mcp-release-acceptance.yaml" in combined
    assert "accepted MCP digest" in combined
    assert combined.index("accepted MCP digest") < combined.index("扫描源码")
    assert "一个选定领域" in combined
    assert "直接依赖" in combined
    for source_layer in ("client", "service", "test", "mcp", "runtime_observation"):
        assert f"usage-evidence/{source_layer}" in combined
    for client_surface in ("web", "mobile", "desktop", "cli", "automation", "other"):
        assert client_surface in combined
    assert "源工程零写入" in combined
    assert "平台中立" in combined
    assert "Codex" not in skill
    assert "Claude" not in skill


def test_usage_scan_manifest_is_sorted_and_has_only_bounded_domain_inputs() -> None:
    manifest_path = SKILL / "templates" / "usage-scan-manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert list(manifest) == [
        "domain_id",
        "direct_dependency_domain_ids",
        "client_include_paths",
        "service_include_paths",
        "test_include_paths",
        "mcp_domain_decision_refs",
        "runtime_observation_refs",
    ]
    assert manifest == {
        "domain_id": "generic-domain",
        "direct_dependency_domain_ids": [],
        "client_include_paths": [],
        "service_include_paths": [],
        "test_include_paths": [],
        "mcp_domain_decision_refs": [],
        "runtime_observation_refs": [],
    }


def test_usage_skill_has_complete_b0_to_b9_workflow_and_templates() -> None:
    assert sorted(path.name for path in (SKILL / "guides").glob("*.md")) == [
        "01-preflight.md",
        "02-scan-domain.md",
        "03-model.md",
        "04-review.md",
        "05-build.md",
        "06-test.md",
        "07-impact.md",
        "08-release.md",
        "09-handoff.md",
    ]
    assert (SKILL / "scripts" / "usage_evidence_capture.py").is_file()
    assert sorted(path.name for path in (SKILL / "templates").glob("*.yaml")) == [
        "domain-usage-contract.yaml",
        "usage-domain-decision.yaml",
        "usage-scan-manifest.yaml",
        "usage-scenario.yaml",
    ]
    assert not (SKILL / "README.md").exists()

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            SKILL / "SKILL.md",
            SKILL / "HARNESS.md",
            *sorted((SKILL / "guides").glob("*.md")),
        ]
    )
    for phase in range(10):
        assert f"B{phase}" in combined
    for concept in (
        "business_goal",
        "tool_route",
        "input_binding",
        "default",
        "option_source",
        "condition",
        "related_data",
        "result_consumption",
        "error_branch",
        "action_lifecycle",
    ):
        assert concept in combined
    assert "Headless" in combined
    assert "real MCP" in combined
    assert "用户接受" in combined
    assert "不生成总分" in combined
    assert "source JWT" in combined
    assert "Change Request" in combined
    assert "Git" in combined and "停止" in combined


def test_usage_skill_automates_clear_facts_and_groups_only_required_questions() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            SKILL / "SKILL.md",
            SKILL / "HARNESS.md",
            *sorted((SKILL / "guides").glob("*.md")),
        ]
    )
    assert "证据清晰" in combined and "自动" in combined
    for boundary in ("scope", "conflict", "high-risk", "real-test"):
        assert boundary in combined
    for axis in (
        "source_usage_traced",
        "usage_contract_verified",
        "headless_agent_verified",
        "host_adapter_verified",
        "real_mcp_verified",
        "user_accepted",
    ):
        assert axis in combined
    assert "适配器" in combined and "可选" in combined
    assert "不能授予权限" in combined


def test_usage_templates_are_generic_and_intentionally_unrenderable() -> None:
    templates = {
        path.name: path.read_text(encoding="utf-8")
        for path in (SKILL / "templates").glob("*.yaml")
    }
    combined = "\n".join(templates.values())
    assert "<replace-with-sha256>" in combined
    assert "search" in combined and "detail" in combined
    assert "default" in combined and "condition" in combined
    assert "prepare" in combined and "approve" in combined and "commit" in combined
    for project_specific in ("baogao", "finance", "invoice"):
        assert project_specific not in combined.lower()
