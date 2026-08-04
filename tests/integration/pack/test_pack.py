from __future__ import annotations

import hashlib
import json
import stat
import warnings
import zipfile
from pathlib import Path

import pytest
import yaml

from acc_core.packaging import (
    PackChecksumMismatchError,
    PackDuplicateEntryError,
    PackFileTooLargeError,
    PackPathError,
    PackSymlinkError,
    PackUnknownEntryError,
    build_pack,
    load_pack_manifest,
    verify_pack,
)

FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _make_project(root: Path) -> Path:
    project = root / "acc-project"
    _write_yaml(
        project / "project.yaml",
        {
            "schema_version": "1",
            "project": {"id": "example-crm", "version": "0.1.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
        },
    )
    _write_yaml(
        project / "operations" / "crm.get_customer.yaml",
        {"schema_version": "1", "id": "crm.get_customer"},
    )
    _write_yaml(
        project / "capabilities" / "get_customer.yaml",
        {"schema_version": "1", "id": "get_customer"},
    )
    _write_yaml(
        project / "policies" / "crm-read.yaml",
        {"schema_version": "1", "id": "crm-read"},
    )
    _write_yaml(
        project / "evals" / "get-customer.yaml",
        {"schema_version": "1", "id": "get-customer"},
    )
    _write_yaml(
        project / "evidence" / "crm-openapi.yaml",
        {"openapi": "3.1.0", "info": {"title": "CRM", "version": "1"}},
    )
    return project


def _zip_info(name: str, *, mode: int = stat.S_IFREG | 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def _write_archive(path: Path, entries: list[tuple[zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive, warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        for info, contents in entries:
            archive.writestr(info, contents)


def _archive_entries(path: Path) -> list[tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(path) as archive:
        return [(info, archive.read(info)) for info in archive.infolist()]


def test_build_pack_is_byte_reproducible_and_lock_covers_every_payload(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    compiled_ir = {
        "schema_version": "1",
        "project": {"id": "example-crm", "version": "0.1.0"},
        "capabilities": [{"id": "get_customer"}],
    }
    first_path = tmp_path / "first.accpkg"
    second_path = tmp_path / "second.accpkg"

    first = build_pack(project, first_path, compiled_ir=compiled_ir)
    second = build_pack(project, second_path, compiled_ir=compiled_ir)

    assert first.sha256 == second.sha256
    assert hashlib.sha256(first_path.read_bytes()).hexdigest() == first.sha256
    assert first_path.read_bytes() == second_path.read_bytes()
    with zipfile.ZipFile(first_path) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert names == [
            "capabilities/get_customer.yaml",
            "compiled/ir.json",
            "evals/get-customer.yaml",
            "evidence/crm-openapi.yaml",
            "manifest.json",
            "operations/crm.get_customer.yaml",
            "pack.lock",
            "policies/crm-read.yaml",
            "project.yaml",
        ]
        for info in archive.infolist():
            assert info.date_time == FIXED_ZIP_TIME
            assert info.create_system == 3
            assert stat.S_IMODE(info.external_attr >> 16) == 0o644
            assert info.compress_type == zipfile.ZIP_STORED

        lock = json.loads(archive.read("pack.lock"))
        locked_paths = [item["path"] for item in lock["files"]]
        assert locked_paths == sorted(set(names) - {"pack.lock"})
        for item in lock["files"]:
            contents = archive.read(item["path"])
            assert item == {
                "path": item["path"],
                "sha256": hashlib.sha256(contents).hexdigest(),
                "size": len(contents),
            }

    verification = verify_pack(first_path)
    assert verification.manifest.to_dict() == {
        "format": "acc.capability-pack",
        "format_version": 1,
        "project": {"id": "example-crm", "version": "0.1.0"},
    }
    assert load_pack_manifest(first_path) == verification.manifest


def test_build_pack_accepts_only_ir_json_from_a_compiled_directory(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / "ir.json").write_text('{"z": 1, "a": 2}\n', encoding="utf-8")

    build_pack(project, tmp_path / "project.accpkg", compiled_ir=compiled)

    with zipfile.ZipFile(tmp_path / "project.accpkg") as archive:
        assert archive.read("compiled/ir.json") == b'{"a":2,"z":1}\n'

    (compiled / "debug.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PackUnknownEntryError):
        build_pack(project, tmp_path / "unknown.accpkg", compiled_ir=compiled)


def test_build_pack_rejects_project_symlinks(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    outside = tmp_path / "outside.yaml"
    outside.write_text("secret: true\n", encoding="utf-8")
    (project / "operations" / "linked.yaml").symlink_to(outside)

    with pytest.raises(PackSymlinkError):
        build_pack(project, tmp_path / "project.accpkg")


def test_build_pack_rejects_unknown_files_in_allowlisted_directories(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    (project / "operations" / "notes.txt").write_text("not a contract", encoding="utf-8")

    with pytest.raises(PackUnknownEntryError):
        build_pack(project, tmp_path / "project.accpkg")


def test_build_pack_refuses_to_overwrite_a_project_definition(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    operation_path = project / "operations" / "crm.get_customer.yaml"
    original = operation_path.read_bytes()

    with pytest.raises(PackPathError):
        build_pack(project, operation_path)

    assert operation_path.read_bytes() == original


def test_build_pack_rejects_oversized_source_file(tmp_path: Path) -> None:
    project = _make_project(tmp_path)

    with pytest.raises(PackFileTooLargeError):
        build_pack(project, tmp_path / "project.accpkg", max_file_bytes=8)


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../escape.yaml",
        "/absolute.yaml",
        r"operations\evil.yaml",
        "operations/../evil.yaml",
    ],
)
def test_verify_pack_rejects_unsafe_archive_paths(tmp_path: Path, unsafe_name: str) -> None:
    path = tmp_path / "unsafe.accpkg"
    _write_archive(path, [(_zip_info(unsafe_name), b"evil")])

    with pytest.raises(PackPathError):
        verify_pack(path)


def test_verify_pack_rejects_symbolic_link_entries(tmp_path: Path) -> None:
    path = tmp_path / "symlink.accpkg"
    _write_archive(
        path,
        [(_zip_info("operations/linked.yaml", mode=stat.S_IFLNK | 0o777), b"project.yaml")],
    )

    with pytest.raises(PackSymlinkError):
        verify_pack(path)


def test_verify_pack_rejects_duplicate_entries(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.accpkg"
    _write_archive(
        path,
        [
            (_zip_info("project.yaml"), b"one"),
            (_zip_info("project.yaml"), b"two"),
        ],
    )

    with pytest.raises(PackDuplicateEntryError):
        verify_pack(path)


@pytest.mark.parametrize(
    "unknown_name",
    ["README.md", "operations/nested/get.yaml", "operations/get.txt", "compiled/debug.json"],
)
def test_verify_pack_rejects_unknown_entries(tmp_path: Path, unknown_name: str) -> None:
    path = tmp_path / "unknown.accpkg"
    _write_archive(path, [(_zip_info(unknown_name), b"unknown")])

    with pytest.raises(PackUnknownEntryError):
        verify_pack(path)


def test_verify_pack_rejects_checksum_mismatch(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    original = tmp_path / "original.accpkg"
    tampered = tmp_path / "tampered.accpkg"
    build_pack(project, original)
    entries = _archive_entries(original)
    replaced = [
        (info, b"tampered\n" if info.filename == "project.yaml" else contents)
        for info, contents in entries
    ]
    _write_archive(tampered, replaced)

    with pytest.raises(PackChecksumMismatchError):
        verify_pack(tampered)


def test_verify_pack_rejects_oversized_archive_member(tmp_path: Path) -> None:
    path = tmp_path / "oversized.accpkg"
    _write_archive(path, [(_zip_info("project.yaml"), b"12345")])

    with pytest.raises(PackFileTooLargeError):
        verify_pack(path, max_file_bytes=4)
