from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from mcp.types import Tool

import acc_core.usage.acceptance as acceptance_module
from acc_core.packaging import build_pack, verify_pack
from acc_core.usage.acceptance import (
    McpReleaseAcceptanceVerification,
    verify_mcp_release_acceptance,
)
from acc_core.usage.models import McpReleaseAcceptance
from acc_runtime.mcp import listed_tools_sha256


def test_hand_authored_acceptance_verification_is_not_trusted() -> None:
    forged = McpReleaseAcceptanceVerification(
        ok=True,
        code="ACC_USAGE_ACCEPTANCE_VERIFIED",
        message="verified",
    )
    assert not forged.trusted


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _pack(tmp_path: Path, *, compiled_project_id: str = "example-crm") -> tuple[Path, bytes]:
    project = tmp_path / "acc-project"
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "2",
            "project": {"id": "example-crm", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
            "quality": {"profile": "standard"},
        },
    )
    _write_yaml(
        project / "domain-map.yaml",
        {
            "schema_version": "2",
            "domains": [
                {
                    "id": "customers",
                    "title": "Customers",
                    "status": "in_progress",
                    "candidate_ids": [],
                    "route_ids": [],
                    "interaction_ids": [],
                    "dependency_domain_ids": [],
                    "evidence_refs": [],
                    "active_decision_ref": None,
                }
            ],
            "unclassified_candidate_ids": [],
            "preferred_order": ["customers"],
        },
    )
    compiled = {
        "ir_version": "2",
        "project": {
            "schema_version": "2",
            "project": {"id": compiled_project_id, "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
            "quality": {"profile": "standard"},
        },
        "interaction_sha256": "c" * 64,
        "capabilities": {},
        "operations": {},
        "policies": {},
        "evals": {},
    }
    path = tmp_path / "release.accpkg"
    build_pack(project, path, compiled_ir=compiled)
    with zipfile.ZipFile(path) as archive:
        ir_bytes = archive.read("compiled/ir.json")
    return path, ir_bytes


def _tools() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "get_customer",
                "inputSchema": {
                    "type": "object",
                    "properties": {"customer_id": {"type": "string"}},
                    "required": ["customer_id"],
                    "additionalProperties": False,
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                    "additionalProperties": False,
                },
            }
        ]
    }


def _tool_digest(snapshot: dict[str, Any]) -> str:
    tools = [Tool.model_validate(value) for value in snapshot["tools"]]
    return listed_tools_sha256(tools)


def _acceptance(
    *, pack: Path, ir_bytes: bytes, tools: dict[str, Any], report: Path
) -> McpReleaseAcceptance:
    return McpReleaseAcceptance.model_validate(
        {
            "schema_version": "2",
            "release_id": "mcp-release-2026-08-11",
            "pack_digest": "sha256:" + hashlib.sha256(pack.read_bytes()).hexdigest(),
            "ir_digest": "sha256:" + hashlib.sha256(ir_bytes).hexdigest(),
            "tool_schema_digest": "sha256:" + _tool_digest(tools),
            "accepted_domain_ids": ["customers"],
            "test_report_digest": "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest(),
            "known_limitations": [],
            "accepted_by": "reviewer-ref",
            "accepted_at": "2026-08-11T00:00:00Z",
        }
    )


def _runtime_info(pack: Path, tools: dict[str, Any]) -> dict[str, object]:
    return {
        "pack_sha256": hashlib.sha256(pack.read_bytes()).hexdigest(),
        "project_id": "example-crm",
        "project_version": "2.0.0",
        "interaction_sha256": "c" * 64,
        "tool_schema_sha256": _tool_digest(tools),
        "transport": "streamable_http",
    }


def _fixture(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], Path, McpReleaseAcceptance, dict[str, object]]:
    pack, ir_bytes = _pack(tmp_path)
    tools = _tools()
    report = tmp_path / "test-report.json"
    report.write_text('{"passed":true}\n', encoding="utf-8")
    acceptance = _acceptance(pack=pack, ir_bytes=ir_bytes, tools=tools, report=report)
    return pack, tools, report, acceptance, _runtime_info(pack, tools)


def test_usage_acceptance_verifies_exact_release_artifacts(tmp_path: Path) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.ok
    assert result.trusted
    assert not replace(result).trusted
    assert result.code == "ACC_USAGE_ACCEPTANCE_VERIFIED"
    assert result.compiled_ir is not None
    assert result.compiled_ir["ir_version"] == "2"
    assert result.accepted_domain_ids == ("customers",)
    assert result.runtime_attested is True


def test_usage_acceptance_allows_stdio_without_fabricated_runtime_attestation(
    tmp_path: Path,
) -> None:
    pack, tools, report, acceptance, _ = _fixture(tmp_path)

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        test_report_path=report,
    )

    assert result.ok
    assert result.runtime_attested is False


def test_usage_acceptance_rejects_fabricated_stdio_runtime_info(tmp_path: Path) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    runtime_info["transport"] = "stdio"

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_ARTIFACT_INVALID"


def test_usage_acceptance_returns_recursively_read_only_artifacts(tmp_path: Path) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )
    compiled_ir = cast(Any, result.compiled_ir)
    frozen_tools = cast(Any, result.tool_snapshot)

    with pytest.raises(TypeError):
        compiled_ir["project"]["project"]["id"] = "mutated"
    with pytest.raises(TypeError):
        frozen_tools["tools"][0]["inputSchema"]["properties"]["new"] = {"type": "string"}


@pytest.mark.parametrize("artifact", ["pack", "ir", "tools", "report", "runtime"])
def test_usage_acceptance_rejects_any_digest_or_attestation_drift(
    tmp_path: Path, artifact: str
) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    if artifact == "pack":
        acceptance = acceptance.model_copy(update={"pack_digest": "sha256:" + "0" * 64})
    elif artifact == "ir":
        acceptance = acceptance.model_copy(update={"ir_digest": "sha256:" + "0" * 64})
    elif artifact == "tools":
        changed_tools = json.loads(json.dumps(tools))
        changed_tools["tools"][0]["inputSchema"]["properties"]["changed"] = {"type": "boolean"}
        tools = changed_tools
    elif artifact == "report":
        report.write_text('{"passed":false}\n', encoding="utf-8")
    else:
        runtime_info["project_version"] = "2.0.1"

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert not result.ok
    assert result.code == "ACC_USAGE_DIGEST_MISMATCH"
    assert result.compiled_ir is None


def test_usage_acceptance_rejects_unknown_tool_snapshot_fields(tmp_path: Path) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    tools["tools"][0]["description"] = "presentation drift"

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_TOOL_SNAPSHOT_INVALID"


def test_usage_acceptance_rejects_unknown_domain_and_project_mismatch(tmp_path: Path) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    acceptance = acceptance.model_copy(update={"accepted_domain_ids": ["unknown"]})

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_RELEASE_MISMATCH"


def test_usage_acceptance_rejects_compiled_project_identity_mismatch(tmp_path: Path) -> None:
    pack, ir_bytes = _pack(tmp_path, compiled_project_id="another-project")
    tools = _tools()
    report = tmp_path / "test-report.json"
    report.write_text('{"passed":true}\n', encoding="utf-8")
    acceptance = _acceptance(pack=pack, ir_bytes=ir_bytes, tools=tools, report=report)
    runtime_info = _runtime_info(pack, tools)
    runtime_info["project_id"] = "another-project"

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_RELEASE_MISMATCH"


def test_usage_acceptance_rejects_pack_changed_during_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    real_verify_pack = verify_pack

    def mutate_after_verification(snapshot: Path) -> object:
        verification = real_verify_pack(snapshot)
        pack.write_bytes(pack.read_bytes() + b"drift")
        return verification

    monkeypatch.setattr(acceptance_module, "verify_pack", mutate_after_verification)

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_ARTIFACT_INVALID"


def test_usage_acceptance_rejects_symlinked_report_without_leaking_target(
    tmp_path: Path,
) -> None:
    pack, tools, report, acceptance, runtime_info = _fixture(tmp_path)
    secret = "Bearer super-secret-token"
    target = tmp_path / secret
    target.write_text("private", encoding="utf-8")
    report.unlink()
    report.symlink_to(target)

    result = verify_mcp_release_acceptance(
        acceptance=acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        runtime_info=runtime_info,
        test_report_path=report,
    )

    assert result.code == "ACC_USAGE_ARTIFACT_INVALID"
    assert secret not in result.message


def test_usage_acceptance_tool_digest_matches_public_runtime_api(tmp_path: Path) -> None:
    _, tools, _, _, _ = _fixture(tmp_path)
    reordered = {"tools": list(reversed(tools["tools"]))}

    from acc_core.usage.acceptance import listed_tool_snapshot_sha256

    assert listed_tool_snapshot_sha256(reordered) == _tool_digest(tools)
