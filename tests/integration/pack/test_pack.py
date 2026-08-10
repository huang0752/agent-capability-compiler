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
    PackFormatError,
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
            "schema_version": "2",
            "project": {"id": "example-crm", "version": "2.0.0"},
            "source_workspace": {"path": "../system", "mode": "read_only"},
            "runtime": {"transport": ["stdio"]},
            "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
            "quality": {"profile": "standard"},
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


def _add_interaction_documents(project: Path, *, submission: str = "send") -> None:
    _write_yaml(
        project / "ui-interaction-inventory.yaml",
        {
            "schema_version": "2",
            "scope": {"mode": "discovered", "evidence_sources": ["frontend-tree"]},
            "surfaces": [],
            "interactions": [],
            "summary": {"surfaces": 0, "interactions": 0, "unresolved": 0},
        },
    )
    _write_yaml(
        project / "interaction-contracts" / "get_customer.yaml",
        {
            "schema_version": "2",
            "capability_id": "get_customer",
            "interaction_ids": [],
            "public_input_bindings": [],
            "trusted_input_bindings": [],
            "defaults": [{"target_pointer": "/locale", "submission": submission}],
            "option_sources": [],
            "conditions": [],
            "related_data": [],
            "result_consumption": [],
            "required_scenarios": ["get-customer.success"],
            "omissions": [],
        },
    )


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


def _rewrite_json_member(path: Path, member_name: str, value: object) -> None:
    entries = dict((info.filename, contents) for info, contents in _archive_entries(path))
    entries[member_name] = _canonical_json(value)
    if member_name != "pack.lock":
        lock = json.loads(entries["pack.lock"])
        for record in lock["files"]:
            if record["path"] == member_name:
                record["sha256"] = hashlib.sha256(entries[member_name]).hexdigest()
                record["size"] = len(entries[member_name])
        entries["pack.lock"] = _canonical_json(lock)
    _write_archive(
        path, [(_zip_info(name), contents) for name, contents in sorted(entries.items())]
    )


def test_build_pack_is_byte_reproducible_and_lock_covers_every_payload(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    compiled_ir = {
        "ir_version": "2",
        "project": {"id": "example-crm", "version": "2.0.0"},
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
        "format_version": 2,
        "project": {"id": "example-crm", "version": "2.0.0"},
    }
    assert load_pack_manifest(first_path) == verification.manifest


def test_build_pack_attests_interaction_sidecars_deterministically(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    _add_interaction_documents(project)
    compiled_ir = {
        "ir_version": "2",
        "interaction_sha256": "a" * 64,
        "interactions": {
            "schema_version": "2",
            "digest": "a" * 64,
            "inventory": {"status": "declared"},
            "contracts": {},
            "dependencies": [],
        },
    }
    first_path = tmp_path / "first-interactions.accpkg"
    second_path = tmp_path / "second-interactions.accpkg"

    first = build_pack(project, first_path, compiled_ir=compiled_ir)
    second = build_pack(project, second_path, compiled_ir=compiled_ir)

    assert first.sha256 == second.sha256
    with zipfile.ZipFile(first_path) as archive:
        names = archive.namelist()
        assert "ui-interaction-inventory.yaml" in names
        assert "interaction-contracts/get_customer.yaml" in names
        lock = json.loads(archive.read("pack.lock"))
        locked_paths = {record["path"] for record in lock["files"]}
        assert "ui-interaction-inventory.yaml" in locked_paths
        assert "interaction-contracts/get_customer.yaml" in locked_paths
    verify_pack(first_path)


def test_pack_digest_changes_when_interaction_semantics_change(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    _add_interaction_documents(project, submission="send")
    first = build_pack(project, tmp_path / "interaction-first.accpkg")

    _add_interaction_documents(project, submission="send_if_changed")
    second = build_pack(project, tmp_path / "interaction-second.accpkg")

    assert first.sha256 != second.sha256


def test_build_pack_rejects_nested_interaction_contract_paths(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    _add_interaction_documents(project)
    _write_yaml(
        project / "interaction-contracts" / "nested" / "contract.yaml",
        {"schema_version": "2"},
    )

    with pytest.raises(PackUnknownEntryError) as caught:
        build_pack(project, tmp_path / "nested-interactions.accpkg")

    assert caught.value.path == "interaction-contracts/nested"


def test_build_pack_applies_file_bounds_to_interaction_inventory(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    max_file_bytes = (project / "project.yaml").stat().st_size
    (project / "ui-interaction-inventory.yaml").write_text(
        "x" * (max_file_bytes + 1), encoding="utf-8"
    )

    with pytest.raises(PackFileTooLargeError) as caught:
        build_pack(
            project,
            tmp_path / "oversized-interactions.accpkg",
            max_file_bytes=max_file_bytes,
        )

    assert caught.value.path == "ui-interaction-inventory.yaml"


def test_build_pack_accepts_only_ir_json_from_a_compiled_directory(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / "ir.json").write_text('{"ir_version": "2", "z": 1, "a": 2}\n', encoding="utf-8")

    build_pack(project, tmp_path / "project.accpkg", compiled_ir=compiled)

    with zipfile.ZipFile(tmp_path / "project.accpkg") as archive:
        assert archive.read("compiled/ir.json") == b'{"a":2,"ir_version":"2","z":1}\n'

    (compiled / "debug.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PackUnknownEntryError):
        build_pack(project, tmp_path / "unknown.accpkg", compiled_ir=compiled)


def test_build_pack_rejects_a_legacy_project_before_writing_an_archive(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    project_document = yaml.safe_load((project / "project.yaml").read_text(encoding="utf-8"))
    project_document["schema_version"] = "1"
    project_document.pop("quality")
    _write_yaml(project / "project.yaml", project_document)
    output = tmp_path / "legacy.accpkg"

    with pytest.raises(PackFormatError) as caught:
        build_pack(project, output)

    assert caught.value.code == "ACC_PACK_FORMAT_INVALID"
    assert str(caught.value) == "project.yaml declares an unsupported schema version"
    assert not output.exists()


def test_verify_pack_rejects_a_legacy_manifest_before_interpreting_payloads(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "legacy-manifest.accpkg"
    build_pack(_make_project(tmp_path), pack)
    with zipfile.ZipFile(pack) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["format_version"] = 1
    _rewrite_json_member(pack, "manifest.json", manifest)

    with pytest.raises(PackFormatError) as caught:
        verify_pack(pack)

    assert caught.value.path == "manifest.json"
    assert str(caught.value) == "unsupported capability-pack format or version"


def test_verify_pack_rejects_a_legacy_lock_version_with_a_stable_path(tmp_path: Path) -> None:
    pack = tmp_path / "legacy-lock.accpkg"
    build_pack(_make_project(tmp_path), pack)
    with zipfile.ZipFile(pack) as archive:
        lock = json.loads(archive.read("pack.lock"))
    lock["format_version"] = 1
    _rewrite_json_member(pack, "pack.lock", lock)

    with pytest.raises(PackFormatError) as caught:
        verify_pack(pack)

    assert caught.value.path == "pack.lock"
    assert str(caught.value) == "pack.lock has an unsupported algorithm or version"


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
