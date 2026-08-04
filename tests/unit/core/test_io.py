from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.io import (
    InvalidProjectPathError,
    ProjectDocumentParseError,
    ProjectDocumentTypeError,
    ProjectFileEncodingError,
    ProjectFileNotFoundError,
    ProjectFileTooLargeError,
    ProjectFileTypeError,
    ProjectSymlinkError,
    UnsupportedProjectDocumentError,
    load_project_object,
    read_project_bytes,
    read_project_text,
    resolve_project_path,
)


def test_diagnostic_has_a_stable_strict_payload() -> None:
    diagnostic = Diagnostic(
        code="ACC_OPERATION_EVIDENCE_MISSING",
        severity="error",
        message="Operation requires at least one evidence reference.",
        path="operations/crm.get_customer.yaml",
        pointer="/evidence",
    )

    assert diagnostic.model_dump(mode="json") == {
        "code": "ACC_OPERATION_EVIDENCE_MISSING",
        "severity": "error",
        "message": "Operation requires at least one evidence reference.",
        "path": "operations/crm.get_customer.yaml",
        "pointer": "/evidence",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("code", "operation_evidence_missing"),
        ("severity", "fatal"),
        ("path", "/tmp/operation.yaml"),
        ("path", "operations/../project.yaml"),
        ("pointer", "evidence/0"),
    ],
)
def test_diagnostic_rejects_invalid_location_fields(field: str, value: str) -> None:
    values: dict[str, object] = {
        "code": "ACC_OPERATION_EVIDENCE_MISSING",
        "severity": "error",
        "message": "Missing evidence.",
        "path": "operations/get.yaml",
        "pointer": "/evidence",
    }
    values[field] = value

    with pytest.raises(ValidationError):
        Diagnostic.model_validate(values)


def test_diagnostic_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Diagnostic.model_validate(
            {
                "code": "ACC_INPUT_INVALID",
                "severity": "error",
                "message": "Invalid input.",
                "path": None,
                "pointer": None,
                "detail": "not part of the public contract",
            }
        )


def test_result_envelope_serializes_success() -> None:
    envelope = ResultEnvelope(
        ok=True,
        command="validate",
        result={"validated": 3},
        diagnostics=[],
    )

    assert envelope.model_dump(mode="json") == {
        "ok": True,
        "command": "validate",
        "result": {"validated": 3},
        "diagnostics": [],
    }


def test_result_envelope_rejects_inconsistent_failure() -> None:
    with pytest.raises(ValidationError):
        ResultEnvelope(
            ok=False,
            command="validate",
            result={"partially_validated": 2},
            diagnostics=[],
        )


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/tmp/project.yaml",
        "operations/../project.yaml",
        "../project.yaml",
        r"C:\project\project.yaml",
        "",
    ],
)
def test_resolve_project_path_rejects_non_relative_or_traversing_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    with pytest.raises(InvalidProjectPathError) as caught:
        resolve_project_path(tmp_path, unsafe_path)

    assert caught.value.code == "ACC_IO_INVALID_PATH"


def test_resolve_project_path_rejects_file_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")
    (tmp_path / "linked.json").symlink_to(outside)

    with pytest.raises(ProjectSymlinkError) as caught:
        resolve_project_path(tmp_path, "linked.json")

    assert caught.value.code == "ACC_IO_SYMLINK_REJECTED"


def test_resolve_project_path_rejects_symlinked_parent_directory(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-directory"
    outside.mkdir()
    (outside / "data.json").write_text("{}", encoding="utf-8")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ProjectSymlinkError):
        resolve_project_path(tmp_path, "linked/data.json")


def test_read_project_bytes_rejects_oversized_file(tmp_path: Path) -> None:
    (tmp_path / "project.yaml").write_bytes(b"12345")

    with pytest.raises(ProjectFileTooLargeError) as caught:
        read_project_bytes(tmp_path, "project.yaml", max_bytes=4)

    assert caught.value.code == "ACC_IO_FILE_TOO_LARGE"
    assert caught.value.path == "project.yaml"


def test_read_project_bytes_accepts_exact_size_limit(tmp_path: Path) -> None:
    (tmp_path / "project.yaml").write_bytes(b"1234")

    assert read_project_bytes(tmp_path, "project.yaml", max_bytes=4) == b"1234"


def test_read_project_text_requires_strict_utf8(tmp_path: Path) -> None:
    (tmp_path / "project.yaml").write_bytes(b"name: \xff")

    with pytest.raises(ProjectFileEncodingError) as caught:
        read_project_text(tmp_path, "project.yaml")

    assert caught.value.code == "ACC_IO_INVALID_UTF8"


def test_read_project_bytes_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ProjectFileNotFoundError) as caught:
        read_project_bytes(tmp_path, "missing.yaml")

    assert caught.value.code == "ACC_IO_NOT_FOUND"


def test_read_project_bytes_rejects_directory(tmp_path: Path) -> None:
    (tmp_path / "operations").mkdir()

    with pytest.raises(ProjectFileTypeError) as caught:
        read_project_bytes(tmp_path, "operations")

    assert caught.value.code == "ACC_IO_NOT_A_FILE"


def test_load_project_object_reads_utf8_yaml_object(tmp_path: Path) -> None:
    (tmp_path / "project.yaml").write_text(
        "schema_version: '1'\nproject:\n  id: 客户能力\n",
        encoding="utf-8",
    )

    loaded = load_project_object(tmp_path, "project.yaml")

    assert loaded == {"schema_version": "1", "project": {"id": "客户能力"}}


def test_load_project_object_reads_utf8_json_object(tmp_path: Path) -> None:
    expected = {"schema_version": "1", "title": "客户能力"}
    (tmp_path / "operation.json").write_text(
        json.dumps(expected, ensure_ascii=False),
        encoding="utf-8",
    )

    assert load_project_object(tmp_path, "operation.json") == expected


@pytest.mark.parametrize(
    ("name", "contents"),
    [
        ("invalid.yaml", "project: [\n"),
        ("invalid.json", '{"project": }'),
    ],
)
def test_load_project_object_reports_parse_errors(
    tmp_path: Path,
    name: str,
    contents: str,
) -> None:
    (tmp_path / name).write_text(contents, encoding="utf-8")

    with pytest.raises(ProjectDocumentParseError) as caught:
        load_project_object(tmp_path, name)

    assert caught.value.code == "ACC_IO_PARSE_ERROR"


@pytest.mark.parametrize(
    ("name", "contents"),
    [
        ("list.yaml", "- one\n- two\n"),
        ("null.json", "null"),
    ],
)
def test_load_project_object_requires_top_level_object(
    tmp_path: Path,
    name: str,
    contents: str,
) -> None:
    (tmp_path / name).write_text(contents, encoding="utf-8")

    with pytest.raises(ProjectDocumentTypeError) as caught:
        load_project_object(tmp_path, name)

    assert caught.value.code == "ACC_IO_OBJECT_REQUIRED"


def test_load_project_object_rejects_unknown_extension(tmp_path: Path) -> None:
    (tmp_path / "project.toml").write_text("name = 'example'", encoding="utf-8")

    with pytest.raises(UnsupportedProjectDocumentError) as caught:
        load_project_object(tmp_path, "project.toml")

    assert caught.value.code == "ACC_IO_UNSUPPORTED_FORMAT"
