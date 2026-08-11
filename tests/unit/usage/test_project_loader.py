from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from acc_core.usage import UsageProjectReport, validate_usage_project


def _write_usage_project(root: Path) -> None:
    (root / "project.yaml").write_text(
        json.dumps(
            {
                "schema_version": "2",
                "kind": "agent_usage",
                "project": {"id": "finance-usage", "version": "1.0.0"},
                "source_workspace": {"path": "../finance", "mode": "read_only"},
            }
        ),
        encoding="utf-8",
    )


def test_missing_usage_project_has_stable_diagnostic(tmp_path: Path) -> None:
    report = validate_usage_project(tmp_path)

    assert isinstance(report, UsageProjectReport)
    assert not report.ok
    assert [(item.code, item.path) for item in report.diagnostics] == [
        ("ACC_IO_NOT_FOUND", "project.yaml")
    ]


def test_collection_rejects_broken_directory_symlink(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    os.symlink(tmp_path / "missing", tmp_path / "usage-evidence")

    report = validate_usage_project(tmp_path)

    assert ("ACC_IO_SYMLINK_REJECTED", "usage-evidence") in {
        (item.code, item.path) for item in report.diagnostics
    }


def test_collection_rejects_broken_file_symlink(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    collection = tmp_path / "usage-evidence"
    collection.mkdir()
    client = collection / "client"
    client.mkdir()
    os.symlink(tmp_path / "missing.json", client / "broken.json")

    report = validate_usage_project(tmp_path)

    assert ("ACC_IO_SYMLINK_REJECTED", "usage-evidence/client/broken.json") in {
        (item.code, item.path) for item in report.diagnostics
    }


def test_collection_rejects_nested_and_unknown_documents(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    collection = tmp_path / "scenarios"
    collection.mkdir()
    (collection / "nested").mkdir()
    (collection / "notes.txt").write_text("not a contract", encoding="utf-8")

    report = validate_usage_project(tmp_path)

    assert {
        ("ACC_USAGE_PROJECT_FILE_UNKNOWN", "scenarios/nested"),
        ("ACC_USAGE_PROJECT_FILE_UNKNOWN", "scenarios/notes.txt"),
    } <= {(item.code, item.path) for item in report.diagnostics}


def test_collection_preserves_bounded_reader_diagnostics(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    collection = tmp_path / "usage-evidence"
    collection.mkdir()
    client = collection / "client"
    client.mkdir()
    (client / "oversize.json").write_bytes(b"x" * 1_048_577)
    (client / "non-utf8.json").write_bytes(b"\xff")

    report = validate_usage_project(tmp_path)

    assert {
        ("ACC_IO_FILE_TOO_LARGE", "usage-evidence/client/oversize.json"),
        ("ACC_IO_INVALID_UTF8", "usage-evidence/client/non-utf8.json"),
    } <= {(item.code, item.path) for item in report.diagnostics}


def test_diagnostics_never_echo_document_values(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    collection = tmp_path / "usage-evidence"
    collection.mkdir()
    client = collection / "client"
    client.mkdir()
    (client / "secret.json").write_text(
        json.dumps({"password": "never-echo-this-secret"}),
        encoding="utf-8",
    )

    report = validate_usage_project(tmp_path)

    rendered = "\n".join(item.model_dump_json() for item in report.diagnostics)
    assert "never-echo-this-secret" not in rendered


def test_duplicate_evidence_identity_is_rejected_at_second_path(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    collection = tmp_path / "usage-evidence"
    collection.mkdir()
    client = collection / "client"
    client.mkdir()
    evidence = {
        "source_id": "frontend-default",
        "kind": "content",
        "locator": "embedded-artifact:frontend-default",
        "digest": "sha256:" + "a" * 64,
        "domain_id": "finance",
        "source_layer": "client",
        "client_surface": "web",
        "size_bytes": 12,
    }
    (client / "a.json").write_text(json.dumps(evidence), encoding="utf-8")
    (client / "b.json").write_text(json.dumps(evidence), encoding="utf-8")

    report = validate_usage_project(tmp_path)

    assert ("ACC_USAGE_EVIDENCE_DUPLICATE", "usage-evidence/client/b.json") in {
        (item.code, item.path) for item in report.diagnostics
    }


def test_capability_directories_are_outside_usage_loader_scope(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    operations = tmp_path / "operations"
    operations.mkdir()
    (operations / "malformed.yaml").write_text("password: should-not-be-read", encoding="utf-8")

    report = validate_usage_project(tmp_path)

    assert not any(item.path == "operations/malformed.yaml" for item in report.diagnostics)


def test_report_collections_are_read_only_views(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)

    report = validate_usage_project(tmp_path)

    try:
        report.evidence_registry["injected"] = object()  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("UsageProjectReport mappings must be immutable")


def test_usage_evidence_accepts_only_platform_layer_directories(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    evidence_root = tmp_path / "usage-evidence"
    evidence_root.mkdir()
    client = evidence_root / "client"
    client.mkdir()
    (client / "screen.json").write_text(
        json.dumps(
            {
                "source_id": "client:screen",
                "kind": "content",
                "locator": "embedded-artifact:screen",
                "digest": "sha256:" + "a" * 64,
                "domain_id": "finance",
                "source_layer": "client",
                "client_surface": "web",
                "size_bytes": 120,
            }
        ),
        encoding="utf-8",
    )

    report = validate_usage_project(tmp_path)

    assert "client:screen" in report.evidence_registry
    assert not any(item.path == "usage-evidence/client" for item in report.diagnostics)


def test_usage_evidence_rejects_unknown_layers_and_deeper_nesting(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    evidence_root = tmp_path / "usage-evidence"
    evidence_root.mkdir()
    frontend = evidence_root / "frontend"
    frontend.mkdir()
    client_nested = evidence_root / "client" / "nested"
    client_nested.mkdir(parents=True)

    report = validate_usage_project(tmp_path)

    assert {
        ("ACC_USAGE_EVIDENCE_LAYER_UNKNOWN", "usage-evidence/frontend"),
        ("ACC_USAGE_PROJECT_FILE_UNKNOWN", "usage-evidence/client/nested"),
    } <= {(item.code, item.path) for item in report.diagnostics}


def test_usage_evidence_rejects_secret_like_and_unknown_audit_fields(tmp_path: Path) -> None:
    _write_usage_project(tmp_path)
    client = tmp_path / "usage-evidence" / "client"
    client.mkdir(parents=True)
    base = {
        "source_id": "client:screen",
        "kind": "content",
        "locator": "embedded-artifact:screen",
        "digest": "sha256:" + "a" * 64,
        "domain_id": "finance",
        "source_layer": "client",
        "size_bytes": 10,
    }
    (client / "secret.json").write_text(
        json.dumps({**base, "access_token": "must-not-echo"}),
        encoding="utf-8",
    )
    (client / "unknown.json").write_text(
        json.dumps({**base, "arbitrary_metadata": "not-allowlisted"}),
        encoding="utf-8",
    )

    report = validate_usage_project(tmp_path)

    assert {
        "ACC_USAGE_EVIDENCE_SECRET_REJECTED",
        "ACC_USAGE_EVIDENCE_AUDIT_INVALID",
    } <= {item.code for item in report.diagnostics}
    assert "must-not-echo" not in "\n".join(item.model_dump_json() for item in report.diagnostics)


@pytest.mark.parametrize("failed_level", ["usage-evidence", "client"])
def test_usage_evidence_iterdir_oserror_has_stable_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_level: str,
) -> None:
    _write_usage_project(tmp_path)
    client = tmp_path / "usage-evidence" / "client"
    client.mkdir(parents=True)
    original_iterdir = Path.iterdir

    def failing_iterdir(path: Path) -> Iterator[Path]:
        if path.name == failed_level:
            raise OSError("must-not-leak-host-error")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", failing_iterdir)

    report = validate_usage_project(tmp_path)

    expected_path = (
        "usage-evidence" if failed_level == "usage-evidence" else "usage-evidence/client"
    )
    matches = [
        item
        for item in report.diagnostics
        if item.code == "ACC_IO_ERROR" and item.path == expected_path
    ]
    assert len(matches) == 1
    assert matches[0].message == "Cannot inspect Usage Evidence directory."
    assert "must-not-leak-host-error" not in matches[0].message
