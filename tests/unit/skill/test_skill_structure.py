from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

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

    assert "system_readonly_complete" in skill
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
    Operation.model_validate(operation)
    Capability.model_validate(_yaml(SKILL / "templates" / "capability.yaml"))
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
    baseline = json.loads(
        (SKILL / "templates" / "coverage-baseline.json").read_text(encoding="utf-8")
    )
    assert baseline["scope_mode"] == "system_readonly_complete"
    assert set(baseline["source_scope"]) == {
        "eligible_read_routes",
        "planned_or_composed",
        "excluded",
        "blocked_on_evidence",
        "unresolved",
    }
    for name in ("preflight-report.json", "coverage-baseline.json"):
        value = json.loads((SKILL / "templates" / name).read_text(encoding="utf-8"))
        assert isinstance(value, dict)


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

    assert "Operation 级 `credential_ref` 只用于 legacy `stdio`" in workflow
    assert "Agent 输入" in workflow


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
