from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "acc-usage-engineer"


def test_usage_skill_is_bounded_platform_neutral_and_release_gated() -> None:
    skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    harness = (SKILL / "HARNESS.md").read_text(encoding="utf-8")
    preflight = (SKILL / "guides" / "01-preflight.md").read_text(encoding="utf-8")
    scan = (SKILL / "guides" / "02-scan-domain.md").read_text(encoding="utf-8")
    combined = "\n".join((skill, harness, preflight, scan))

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
    for classification in (
        "usage-evidence/frontend",
        "usage-evidence/backend",
        "usage-evidence/tests",
    ):
        assert classification in combined
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
        "frontend_include_paths",
        "backend_include_paths",
        "test_include_paths",
        "mcp_domain_decision_refs",
    ]
    assert manifest == {
        "domain_id": "finance",
        "direct_dependency_domain_ids": [],
        "frontend_include_paths": [],
        "backend_include_paths": [],
        "test_include_paths": [],
        "mcp_domain_decision_refs": [],
    }


def test_usage_skill_has_only_the_initial_bounded_scan_guides() -> None:
    assert sorted(path.name for path in (SKILL / "guides").glob("*.md")) == [
        "01-preflight.md",
        "02-scan-domain.md",
    ]
    assert (SKILL / "scripts" / "usage_evidence_capture.py").is_file()
    assert not (SKILL / "README.md").exists()
