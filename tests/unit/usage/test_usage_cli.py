from __future__ import annotations

import json
import shutil
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import yaml

import acc_core.cli.usage as usage_cli
from acc_core.cli.main import EXIT_INPUT, EXIT_SUCCESS, main
from acc_core.cli.usage import handle_usage_command
from acc_core.usage.models import DomainUsageIndex
from acc_core.usage.project import UsageProjectReport
from fs_links import create_link

FIXTURE = Path(__file__).parents[2] / "fixtures" / "usage" / "finance"


def _copy_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "usage-project"
    shutil.copytree(FIXTURE, target)
    return target


def _payload(capsys: object) -> dict[str, object]:
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert captured.err == ""
    return cast(dict[str, object], json.loads(captured.out))


def _file_snapshot(project: Path) -> list[tuple[str, int]]:
    return sorted(
        (path.relative_to(project).as_posix(), path.stat().st_mtime_ns)
        for path in project.rglob("*")
        if path.is_file()
    )


def test_usage_init_creates_only_empty_usage_directories(tmp_path: Path, capsys: object) -> None:
    target = tmp_path / "new-usage"

    assert main(["usage", "init", str(target), "--json"]) == EXIT_SUCCESS

    payload = _payload(capsys)
    assert payload["command"] == "usage init"
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*")) == [
        "domain-decisions",
        "domain-usage-contracts",
        "releases",
        "scenarios",
        "usage-evidence",
        "usage-evidence/client",
        "usage-evidence/mcp",
        "usage-evidence/runtime_observation",
        "usage-evidence/service",
        "usage-evidence/test",
    ]
    assert not (target / "mcp-release-acceptance.yaml").exists()
    assert not any(path.is_file() for path in target.rglob("*"))


def test_usage_init_rejects_nonempty_and_symlink_destinations(
    tmp_path: Path, capsys: object
) -> None:
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "owned.txt").write_text("keep", encoding="utf-8")
    assert main(["usage", "init", str(nonempty), "--json"]) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_PROJECT_EXISTS"  # type: ignore[index]
    assert (nonempty / "owned.txt").read_text(encoding="utf-8") == "keep"

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    create_link(linked, real, target_is_directory=True)
    assert main(["usage", "init", str(linked), "--json"]) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_PROJECT_SYMLINK"  # type: ignore[index]


def test_usage_status_derives_release_closure_and_one_next_domain(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)

    assert main(["usage", "status", str(project), "--json"]) == EXIT_SUCCESS
    result = _payload(capsys)["result"]
    assert result == {
        "domains": [{"dependency_ready": True, "domain_id": "finance", "state": "released"}],
        "next_domain": None,
    }

    index_path = project / "domain-index.yaml"
    index = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    index["published_releases"] = []
    index_path.write_text(yaml.safe_dump(index, sort_keys=False), encoding="utf-8")

    assert main(["usage", "status", str(project), "--json"]) == EXIT_SUCCESS
    result = _payload(capsys)["result"]
    assert result == {
        "domains": [{"dependency_ready": True, "domain_id": "finance", "state": "reviewed"}],
        "next_domain": "finance",
    }


def test_usage_status_fails_closed_when_project_has_real_diagnostics(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    release_path = project / "releases" / "finance-1.yaml"
    release = yaml.safe_load(release_path.read_text(encoding="utf-8"))
    release["decision_digest"] = "sha256:" + "0" * 64
    release_path.write_text(yaml.safe_dump(release, sort_keys=False), encoding="utf-8")

    assert main(["usage", "status", str(project), "--json"]) == EXIT_INPUT
    payload = _payload(capsys)
    assert payload["diagnostics"][0]["code"] == "ACC_USAGE_STATUS_PROJECT_INVALID"  # type: ignore[index]
    assert payload["result"] is None


def test_usage_status_uses_declared_dependencies_not_positional_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    index = DomainUsageIndex.model_validate(
        {
            "schema_version": "2",
            "mcp_release_id": "mcp-1",
            "pack_digest": digest,
            "ir_digest": digest,
            "tool_schema_digest": digest,
            "test_report_digest": digest,
            "source_snapshot_digest": digest,
            "domains": [
                {"id": "a-independent", "dependency_domain_ids": []},
                {"id": "b-blocked", "dependency_domain_ids": ["z-dependency"]},
                {"id": "z-dependency", "dependency_domain_ids": []},
            ],
            "preferred_order": ["b-blocked", "a-independent", "z-dependency"],
            "published_releases": [],
        }
    )
    released: set[str] = set()
    monkeypatch.setattr(usage_cli, "_release_closure", lambda _report, domain: domain in released)
    monkeypatch.setattr(usage_cli, "_review_closure", lambda _report, _domain: None)
    report = cast(
        UsageProjectReport,
        SimpleNamespace(domain_index=index, domain_contracts={}),
    )

    result = usage_cli.status_usage_domains(report)
    assert result["next_domain"] == "a-independent"
    assert result["domains"] == [
        {"dependency_ready": False, "domain_id": "b-blocked", "state": "pending"},
        {"dependency_ready": True, "domain_id": "a-independent", "state": "pending"},
        {"dependency_ready": True, "domain_id": "z-dependency", "state": "pending"},
    ]

    released.add("z-dependency")
    assert usage_cli.status_usage_domains(report)["next_domain"] == "b-blocked"


def test_usage_scan_check_validates_prerequisites_and_manifest_without_writing(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    manifest = {
        "domain_id": "finance",
        "direct_dependency_domain_ids": [],
        "client_include_paths": ["frontend/finance"],
        "service_include_paths": ["backend/finance"],
        "test_include_paths": ["tests/finance"],
        "mcp_evidence_refs": ["mcp:finance-invoice-list"],
        "runtime_observation_refs": [],
    }
    (project / "usage-scan-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    before = _file_snapshot(project)

    assert (
        main(
            [
                "usage",
                "scan",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--check",
                "--json",
            ]
        )
        == EXIT_SUCCESS
    )
    result = _payload(capsys)["result"]
    assert result == {"domain_id": "finance", "manifest_valid": True, "ready": True}
    after = _file_snapshot(project)
    assert after == before

    create_link(
        project / "usage-evidence" / "client" / "broken.json",
        project / "missing-evidence.json",
    )
    assert (
        main(
            [
                "usage",
                "scan",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--check",
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_SCAN_PROJECT_INVALID"  # type: ignore[index]
    (project / "usage-evidence" / "client" / "broken.json").unlink()

    manifest["domain_id"] = "other"
    (project / "usage-scan-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    scan_arguments = [
        "usage",
        "scan",
        "--domain",
        "finance",
        "--project",
        str(project),
        "--check",
        "--json",
    ]
    assert main(scan_arguments) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_SCAN_MANIFEST_INVALID"  # type: ignore[index]

    manifest["domain_id"] = "finance"
    manifest["direct_dependency_domain_ids"] = []
    manifest["mcp_evidence_refs"] = ["Bearer: abcdefghijklmnopqrstuvwxyz"]
    (project / "usage-scan-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    assert main(scan_arguments) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_SCAN_MANIFEST_INVALID"  # type: ignore[index]

    manifest["direct_dependency_domain_ids"] = ["other"]
    (project / "usage-scan-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    assert main(scan_arguments) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_SCAN_MANIFEST_INVALID"  # type: ignore[index]


def test_usage_review_check_requires_typed_decision_without_requiring_a_release(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)

    review_arguments = [
        "usage",
        "review",
        "--domain",
        "finance",
        "--project",
        str(project),
        "--check",
        "--json",
    ]
    assert main(review_arguments) == EXIT_SUCCESS
    assert _payload(capsys)["result"] == {
        "decision_valid": True,
        "domain_id": "finance",
        "review_valid": True,
    }

    index_path = project / "domain-index.yaml"
    index = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    index["published_releases"] = []
    index_path.write_text(yaml.safe_dump(index, sort_keys=False), encoding="utf-8")
    assert main(review_arguments) == EXIT_SUCCESS
    result = _payload(capsys)["result"]
    assert result == {
        "decision_valid": True,
        "domain_id": "finance",
        "review_valid": True,
    }


def test_usage_review_rejects_a_decision_that_no_longer_matches_the_contract(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    decision_path = project / "domain-decisions" / "finance-1.yaml"
    decision = yaml.safe_load(decision_path.read_text(encoding="utf-8"))
    decision["included_route_ids"] = ["missing-route"]
    decision_path.write_text(yaml.safe_dump(decision, sort_keys=False), encoding="utf-8")

    assert (
        main(
            [
                "usage",
                "review",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--check",
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    payload = _payload(capsys)
    assert payload["diagnostics"][0]["code"] == "ACC_USAGE_REVIEW_CLOSURE_INVALID"  # type: ignore[index]
    rendered = json.dumps(payload, ensure_ascii=False)
    assert "finance-reviewer" not in rendered
    assert "known_limitations" not in rendered
    assert "statement" not in rendered


def test_usage_commands_require_check_for_read_only_foundation() -> None:
    arguments = Namespace(usage_command="scan", project=".", domain="finance", check=False)
    exit_code, envelope = handle_usage_command(arguments)
    assert exit_code == EXIT_INPUT
    assert envelope.diagnostics[0].code == "ACC_USAGE_CHECK_REQUIRED"


def test_usage_build_refuses_serialized_release_without_live_bundle_and_signer(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    output = project / "artifacts" / "finance.accusage"

    assert (
        main(
            [
                "usage",
                "build",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--output",
                str(output),
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    payload = _payload(capsys)
    assert payload["result"] is None
    assert (
        payload["diagnostics"][0]["code"]  # type: ignore[index]
        == "ACC_USAGE_BUILD_EVIDENCE_NOT_PROVISIONED"
    )
    assert not output.exists()

    unsafe = tmp_path / "outside.accusage"
    assert (
        main(
            [
                "usage",
                "build",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--output",
                str(unsafe),
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_OUTPUT_UNSAFE"  # type: ignore[index]
    assert not unsafe.exists()

    release_path = project / "releases" / "finance-1.yaml"
    release = yaml.safe_load(release_path.read_text(encoding="utf-8"))
    release["verification"]["real_mcp_verified"] = False
    release_path.write_text(yaml.safe_dump(release, sort_keys=False), encoding="utf-8")
    second = project / "artifacts" / "invalid.accusage"
    assert (
        main(
            [
                "usage",
                "build",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--output",
                str(second),
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    assert _payload(capsys)["result"] is None
    assert not second.exists()


def test_usage_build_never_calls_unsigned_packager_without_live_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "usage-project"
    root.mkdir()

    def unexpected_serialized_validation(_root: object) -> object:
        raise AssertionError("serialized release documents cannot authorize package build")

    monkeypatch.setattr(usage_cli, "validate_usage_project", unexpected_serialized_validation)

    exit_code, envelope = handle_usage_command(
        Namespace(
            usage_command="build",
            domain="finance",
            project=root,
            output=root / "artifacts" / "all.accusage",
        )
    )

    assert exit_code == EXIT_INPUT
    assert envelope.result is None
    assert envelope.diagnostics[0].code == "ACC_USAGE_BUILD_EVIDENCE_NOT_PROVISIONED"


def test_usage_test_is_read_only_and_never_infers_live_mcp_evidence(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    before = _file_snapshot(project)

    assert (
        main(
            [
                "usage",
                "test",
                "--domain",
                "finance",
                "--project",
                str(project),
                "--check",
                "--json",
            ]
        )
        == EXIT_SUCCESS
    )
    assert _payload(capsys)["result"] == {
        "domain_id": "finance",
        "headless_agent": "not_provisioned",
        "real_mcp": "not_provisioned",
        "release_claims_real_mcp": True,
        "review_closure": "passed",
    }
    assert _file_snapshot(project) == before


def _impact_snapshot(*, source_digest: str) -> dict[str, object]:
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "2",
        "pack_digest": digest,
        "tool_schema_digest": "sha256:" + "c" * 64,
        "test_report_digest": "sha256:" + "d" * 64,
        "source_snapshot_digest": source_digest,
        "contract_digests": {"finance": "sha256:" + "9" * 64},
        "capability_ids": ["finance.invoice.list"],
        "tool_schemas": {
            "finance_invoice_list": {
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                    "required": ["items"],
                    "additionalProperties": False,
                },
            }
        },
        "evidence_digests": {
            "client:finance-screen": "sha256:" + "4" * 64,
            "mcp:finance-invoice-list": "sha256:" + "5" * 64,
        },
        "action_proof_digests": {},
    }


def test_usage_impact_is_read_only_unless_explicit_safe_output_is_authorized(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    change_set = {
        "schema_version": "2",
        "before": _impact_snapshot(source_digest="sha256:" + "e" * 64),
        "after": _impact_snapshot(source_digest="sha256:" + "f" * 64),
    }
    change_path = project / "change-set.yaml"
    change_path.write_text(yaml.safe_dump(change_set, sort_keys=False), encoding="utf-8")
    before = _file_snapshot(project)

    base = ["usage", "impact", "change-set.yaml", "--project", str(project), "--json"]
    assert main(base) == EXIT_SUCCESS
    result = _payload(capsys)["result"]
    assert result["domains"][0]["domain_id"] == "finance"  # type: ignore[index]
    assert result["domains"][0]["status"] == "revalidate"  # type: ignore[index]
    assert result["output"] is None  # type: ignore[index]
    assert _file_snapshot(project) == before

    assert main([*base[:-1], "--output", "reports/impact.json", "--json"]) == EXIT_SUCCESS
    assert _payload(capsys)["result"]["output"] == "reports/impact.json"  # type: ignore[index]
    written = json.loads((project / "reports" / "impact.json").read_text(encoding="utf-8"))
    assert written["domains"][0]["status"] == "revalidate"

    assert main([*base[:-1], "--output", str(tmp_path / "outside.json"), "--json"]) == EXIT_INPUT
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_OUTPUT_UNSAFE"  # type: ignore[index]


def test_usage_release_check_does_not_trust_serialized_verification_claims(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    arguments = [
        "usage",
        "release",
        "--domain",
        "finance",
        "--project",
        str(project),
        "--check",
        "--json",
    ]
    assert main(arguments) == EXIT_INPUT
    payload = _payload(capsys)
    assert payload["result"] is None
    assert (
        payload["diagnostics"][0]["code"]  # type: ignore[index]
        == "ACC_USAGE_RELEASE_EVIDENCE_NOT_PROVISIONED"
    )
    assert "release_ready" not in json.dumps(payload)

    release_path = project / "releases" / "finance-1.yaml"
    release = yaml.safe_load(release_path.read_text(encoding="utf-8"))
    release["verification"]["headless_agent_verified"] = False
    release_path.write_text(yaml.safe_dump(release, sort_keys=False), encoding="utf-8")
    assert main(arguments) == EXIT_INPUT
    payload = _payload(capsys)
    assert payload["result"] is None
    assert payload["diagnostics"][0]["code"] == "ACC_USAGE_RELEASE_GATES_FAILED"  # type: ignore[index]


def test_usage_export_refuses_unsigned_package_without_explicit_trust_root(
    tmp_path: Path, capsys: object
) -> None:
    project = _copy_fixture(tmp_path)
    package_path = tmp_path / "external-finance.accusage"
    package_path.write_bytes(b"unsigned serialized package claim")
    package_before = package_path.read_bytes()
    before = _file_snapshot(project)
    output = project / "exports" / "finance-agent-guide.md"

    assert (
        main(
            [
                "usage",
                "export",
                "--adapter",
                "generic-markdown",
                "--domain",
                "finance",
                "--package",
                str(package_path),
                "--project",
                str(project),
                "--output",
                str(output),
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    payload = _payload(capsys)
    assert payload["result"] is None
    assert (
        payload["diagnostics"][0]["code"]  # type: ignore[index]
        == "ACC_USAGE_EXPORT_TRUST_NOT_PROVISIONED"
    )
    assert not output.exists()
    assert package_path.read_bytes() == package_before
    assert _file_snapshot(project) == before

    assert (
        main(
            [
                "usage",
                "export",
                "--adapter",
                "unknown",
                "--domain",
                "finance",
                "--package",
                str(package_path),
                "--project",
                str(project),
                "--output",
                str(project / "exports" / "unknown.md"),
                "--json",
            ]
        )
        == EXIT_INPUT
    )
    assert _payload(capsys)["diagnostics"][0]["code"] == "ACC_USAGE_ADAPTER_UNSUPPORTED"  # type: ignore[index]


@pytest.mark.parametrize("command", ["compile", "pack", "run"])
def test_capability_commands_never_enter_usage_validation(
    command: str,
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_usage_validation(_path: object) -> object:
        raise AssertionError("Capability commands must not invoke the Usage pipeline")

    monkeypatch.setattr(usage_cli, "validate_usage_project", unexpected_usage_validation)
    arguments = [command, str(tmp_path / "missing")]
    if command == "run":
        arguments.append("--json")
    else:
        arguments.extend(["--check", "--json"] if command == "compile" else ["--json"])

    assert main(arguments) != EXIT_SUCCESS
    _payload(capsys)
