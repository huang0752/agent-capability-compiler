"""Build and verify deterministic ACC capability packs.

The lock file proves only that members inside one archive are internally
consistent. It is not a signature and does not establish publisher identity or
artifact authenticity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import ClassVar

import yaml
from pydantic import BaseModel, ValidationError

from acc_core.domains import (
    CapabilityCandidateLedger,
    DomainChangeRequest,
    DomainDecision,
    DomainMap,
)
from acc_core.io import (
    DEFAULT_MAX_FILE_BYTES,
    ProjectFileTooLargeError,
    ProjectIOError,
    ProjectSymlinkError,
    read_project_bytes,
)

PACK_FORMAT = "acc.capability-pack"
PACK_FORMAT_VERSION = 2
SUPPORTED_PACK_FORMAT_VERSIONS = frozenset({PACK_FORMAT_VERSION})
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

_DOCUMENT_DIRECTORIES = (
    "capabilities",
    "capability-quality",
    "domain-change-requests",
    "domain-decisions",
    "evals",
    "evidence",
    "interaction-contracts",
    "operations",
    "policies",
    "source-contracts",
)
_FIXED_PROJECT_DOCUMENTS = (
    "capability-candidates.yaml",
    "domain-map.yaml",
    "ui-interaction-inventory.yaml",
)
_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}
_REQUIRED_ENTRIES = {"manifest.json", "pack.lock", "project.yaml"}
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_DOMAIN_DOCUMENT_MODELS: dict[str, type[BaseModel]] = {
    "capability-candidates.yaml": CapabilityCandidateLedger,
    "domain-map.yaml": DomainMap,
    "domain-change-requests": DomainChangeRequest,
    "domain-decisions": DomainDecision,
}


class CapabilityPackError(Exception):
    """Base class for stable capability-pack failures."""

    code: ClassVar[str] = "ACC_PACK_ERROR"

    def __init__(self, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.path = path


class PackPathError(CapabilityPackError, ValueError):
    """A source or archive path is unsafe."""

    code = "ACC_PACK_PATH_INVALID"


class PackSymlinkError(CapabilityPackError):
    """A source path or archive member is a symbolic link."""

    code = "ACC_PACK_SYMLINK_REJECTED"


class PackDuplicateEntryError(CapabilityPackError):
    """An archive repeats a member name."""

    code = "ACC_PACK_ENTRY_DUPLICATE"


class PackUnknownEntryError(CapabilityPackError):
    """A source directory or archive contains a non-allowlisted entry."""

    code = "ACC_PACK_ENTRY_UNKNOWN"


class PackChecksumMismatchError(CapabilityPackError):
    """A member does not match its lock-file digest or size."""

    code = "ACC_PACK_CHECKSUM_MISMATCH"


class PackFileTooLargeError(CapabilityPackError):
    """A source file or archive member exceeds its configured bound."""

    code = "ACC_PACK_FILE_TOO_LARGE"


class PackFormatError(CapabilityPackError):
    """A pack, manifest, lock file, or compiled IR is malformed."""

    code = "ACC_PACK_FORMAT_INVALID"


@dataclass(frozen=True, slots=True)
class PackManifest:
    """Strict public metadata identifying the pack format and ACC project."""

    format: str
    format_version: int
    project_id: str
    project_version: str

    def to_dict(self) -> dict[str, object]:
        """Return the canonical JSON-compatible manifest shape."""

        return {
            "format": self.format,
            "format_version": self.format_version,
            "project": {"id": self.project_id, "version": self.project_version},
        }


@dataclass(frozen=True, slots=True)
class PackFileRecord:
    """One payload member recorded by ``pack.lock``."""

    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Return the canonical JSON-compatible lock record."""

        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class PackBuildResult:
    """Result metadata for one completed pack build."""

    path: Path
    sha256: str
    manifest: PackManifest


@dataclass(frozen=True, slots=True)
class PackVerification:
    """Verified metadata without extracting any archive member."""

    path: Path
    sha256: str
    manifest: PackManifest
    files: tuple[PackFileRecord, ...]


def _validate_max_bytes(max_file_bytes: int) -> None:
    if (
        isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or max_file_bytes <= 0
    ):
        raise ValueError("max_file_bytes must be a positive integer")


def _canonical_json(value: object, *, description: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PackFormatError(f"{description} must contain canonical JSON values") from exc
    return f"{encoded}\n".encode()


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(path: str, contents: bytes) -> PackFileRecord:
    return PackFileRecord(path=path, sha256=_sha256(contents), size=len(contents))


def _document_directories(format_version: int) -> tuple[str, ...]:
    if format_version != PACK_FORMAT_VERSION:
        raise PackFormatError("unsupported capability-pack format version")
    return _DOCUMENT_DIRECTORIES


def _is_allowed_entry(path: str, *, format_version: int | None = None) -> bool:
    if path in _REQUIRED_ENTRIES:
        return True
    if path == "compiled/ir.json":
        return True
    if path in _FIXED_PROJECT_DOCUMENTS:
        return True
    parts = path.split("/")
    return (
        len(parts) == 2
        and parts[0]
        in (
            _DOCUMENT_DIRECTORIES
            if format_version is None
            else _document_directories(format_version)
        )
        and bool(parts[1])
        and PurePosixPath(parts[1]).suffix.lower() in _DOCUMENT_SUFFIXES
    )


def _validate_member_path(path: str) -> None:
    if not path or "\x00" in path or "\\" in path:
        raise PackPathError("pack paths must use non-empty POSIX syntax", path=path)
    parts = path.split("/")
    posix_path = PurePosixPath(path)
    windows_path = PureWindowsPath(path)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PackPathError("pack paths must be relative without traversal", path=path)


def _read_project_member(root: Path, relative_path: str, max_file_bytes: int) -> bytes:
    try:
        return read_project_bytes(root, relative_path, max_bytes=max_file_bytes)
    except ProjectSymlinkError as exc:
        raise PackSymlinkError(str(exc), path=relative_path) from exc
    except ProjectFileTooLargeError as exc:
        raise PackFileTooLargeError(str(exc), path=relative_path) from exc
    except ProjectIOError as exc:
        raise PackFormatError(str(exc), path=relative_path) from exc


def _validate_domain_document(relative_path: str, contents: bytes) -> None:
    document_key = relative_path.split("/", maxsplit=1)[0]
    model = _DOMAIN_DOCUMENT_MODELS.get(document_key)
    if model is None:
        return
    try:
        document = yaml.safe_load(contents.decode("utf-8"))
        model.model_validate(document)
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError):
        raise PackFormatError(
            "domain sidecar is not a valid current-format document",
            path=relative_path,
        ) from None


def _collect_project_payloads(root: Path, max_file_bytes: int) -> dict[str, bytes]:
    if root.is_symlink():
        raise PackSymlinkError("project root cannot be a symbolic link", path=".")
    if not root.is_dir():
        raise PackFormatError(f"project root is not a directory: {root}", path=".")

    payloads = {"project.yaml": _read_project_member(root, "project.yaml", max_file_bytes)}
    manifest = _project_manifest(payloads["project.yaml"])
    for relative_path in _FIXED_PROJECT_DOCUMENTS:
        source = root / relative_path
        if not source.exists() and not source.is_symlink():
            continue
        payloads[relative_path] = _read_project_member(root, relative_path, max_file_bytes)
    for directory in _document_directories(manifest.format_version):
        directory_path = root / directory
        if directory_path.is_symlink():
            raise PackSymlinkError(
                f"project directory cannot be a symbolic link: {directory}",
                path=directory,
            )
        if not directory_path.exists():
            continue
        if not directory_path.is_dir():
            raise PackUnknownEntryError(
                f"expected an allowlisted project directory: {directory}",
                path=directory,
            )
        for entry in sorted(directory_path.iterdir(), key=lambda candidate: candidate.name):
            relative_path = f"{directory}/{entry.name}"
            if entry.is_symlink():
                raise PackSymlinkError(
                    f"project member cannot be a symbolic link: {relative_path}",
                    path=relative_path,
                )
            if (
                not entry.is_file()
                or entry.suffix.lower() not in _DOCUMENT_SUFFIXES
                or not _is_allowed_entry(
                    relative_path,
                    format_version=manifest.format_version,
                )
            ):
                raise PackUnknownEntryError(
                    f"unknown project member: {relative_path}",
                    path=relative_path,
                )
            payloads[relative_path] = _read_project_member(root, relative_path, max_file_bytes)
    for relative_path, contents in payloads.items():
        _validate_domain_document(relative_path, contents)
    return payloads


def _project_manifest(project_contents: bytes) -> PackManifest:
    try:
        document = yaml.safe_load(project_contents.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackFormatError("project.yaml must be a valid UTF-8 YAML document") from exc
    if not isinstance(document, dict):
        raise PackFormatError("project.yaml does not have the required project shape")
    schema_version = document.get("schema_version")
    expected_fields = {
        "project",
        "provider",
        "runtime",
        "schema_version",
        "source_workspace",
    }
    if schema_version != "2":
        raise PackFormatError("project.yaml declares an unsupported schema version")
    expected_fields.add("quality")
    if set(document) != expected_fields:
        raise PackFormatError("project.yaml does not have the required project shape")
    identity = document.get("project")
    if not isinstance(identity, dict) or set(identity) != {"id", "version"}:
        raise PackFormatError("project.yaml must declare only project id and version")
    project_id = identity.get("id")
    project_version = identity.get("version")
    if not isinstance(project_id, str) or not project_id:
        raise PackFormatError("project id must be a non-empty string")
    if not isinstance(project_version, str) or not project_version:
        raise PackFormatError("project version must be a non-empty string")
    return PackManifest(
        format=PACK_FORMAT,
        format_version=PACK_FORMAT_VERSION,
        project_id=project_id,
        project_version=project_version,
    )


def _read_compiled_path(path: Path, max_file_bytes: int) -> bytes:
    if path.is_symlink():
        raise PackSymlinkError("compiled IR cannot be a symbolic link", path=str(path))
    if not path.is_file():
        raise PackFormatError("compiled IR must be a regular JSON file", path=str(path))
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError as exc:
        raise PackFormatError("cannot inspect compiled IR", path=str(path)) from exc
    if size > max_file_bytes:
        raise PackFileTooLargeError(f"compiled IR exceeds {max_file_bytes} bytes", path=str(path))
    try:
        with path.open("rb") as compiled_file:
            contents = compiled_file.read(max_file_bytes + 1)
    except OSError as exc:
        raise PackFormatError("cannot read compiled IR", path=str(path)) from exc
    if len(contents) > max_file_bytes:
        raise PackFileTooLargeError(f"compiled IR exceeds {max_file_bytes} bytes", path=str(path))
    return contents


def _compiled_payload(
    compiled_ir: Mapping[str, object] | str | os.PathLike[str] | None,
    max_file_bytes: int,
    *,
    format_version: int,
) -> bytes | None:
    if compiled_ir is None:
        return None
    if isinstance(compiled_ir, Mapping):
        ir_version = compiled_ir.get("ir_version")
        if ir_version != str(format_version):
            raise PackFormatError("compiled IR version does not match the pack format")
        contents = _canonical_json(dict(compiled_ir), description="compiled IR")
        if len(contents) > max_file_bytes:
            raise PackFileTooLargeError(
                f"compiled IR exceeds {max_file_bytes} bytes", path="compiled/ir.json"
            )
        return contents

    source = Path(compiled_ir)
    if source.is_symlink():
        raise PackSymlinkError("compiled IR source cannot be a symbolic link", path=str(source))
    if source.is_dir():
        entries = sorted(source.iterdir(), key=lambda candidate: candidate.name)
        for entry in entries:
            if entry.is_symlink():
                raise PackSymlinkError(
                    "compiled IR directory cannot contain symbolic links", path=str(entry)
                )
            if entry.name != "ir.json" or not entry.is_file():
                raise PackUnknownEntryError(
                    "compiled IR directory may contain only ir.json", path=str(entry)
                )
        if not entries:
            raise PackFormatError(
                "compiled IR directory does not contain ir.json", path=str(source)
            )
        source = source / "ir.json"

    raw_contents = _read_compiled_path(source, max_file_bytes)
    try:
        value = json.loads(
            raw_contents.decode("utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PackFormatError("compiled IR must be a valid UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise PackFormatError("compiled IR must be a JSON object")
    ir_version = value.get("ir_version")
    if ir_version != str(format_version):
        raise PackFormatError("compiled IR version does not match the pack format")
    contents = _canonical_json(value, description="compiled IR")
    if len(contents) > max_file_bytes:
        raise PackFileTooLargeError(
            f"compiled IR exceeds {max_file_bytes} bytes", path="compiled/ir.json"
        )
    return contents


def _lock_contents(
    payloads: Mapping[str, bytes],
    *,
    format_version: int,
) -> tuple[bytes, tuple[PackFileRecord, ...]]:
    records = tuple(_record(path, payloads[path]) for path in sorted(payloads))
    lock = {
        "algorithm": "sha256",
        "files": [record.to_dict() for record in records],
        "format_version": format_version,
    }
    return _canonical_json(lock, description="pack lock"), records


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def build_pack(
    project_root: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    compiled_ir: Mapping[str, object] | str | os.PathLike[str] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> PackBuildResult:
    """Build an allowlisted, byte-reproducible ZIP capability pack."""

    _validate_max_bytes(max_file_bytes)
    root = Path(project_root)
    destination = Path(output_path)
    if destination.suffix.lower() != ".accpkg":
        raise PackPathError(
            "capability-pack output must use the .accpkg suffix", path=str(destination)
        )
    resolved_root = root.resolve(strict=False)
    resolved_destination = destination.resolve(strict=False)
    for directory in _DOCUMENT_DIRECTORIES:
        if resolved_destination.is_relative_to(resolved_root / directory):
            raise PackPathError(
                "capability-pack output cannot overwrite a project definition directory",
                path=str(destination),
            )
    payloads = _collect_project_payloads(root, max_file_bytes)
    manifest = _project_manifest(payloads["project.yaml"])
    payloads["manifest.json"] = _canonical_json(manifest.to_dict(), description="manifest")
    compiled_contents = _compiled_payload(
        compiled_ir,
        max_file_bytes,
        format_version=manifest.format_version,
    )
    if compiled_contents is not None:
        payloads["compiled/ir.json"] = compiled_contents
    lock_contents, _ = _lock_contents(
        payloads,
        format_version=manifest.format_version,
    )
    payloads["pack.lock"] = lock_contents

    if destination.is_symlink():
        raise PackSymlinkError("pack output cannot be a symbolic link", path=str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(payloads):
                archive.writestr(_zip_info(path), payloads[path])
        os.replace(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return PackBuildResult(
        path=destination,
        sha256=_file_sha256(destination),
        manifest=manifest,
    )


def _read_archive_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_file_bytes: int,
) -> bytes:
    if info.file_size > max_file_bytes:
        raise PackFileTooLargeError(
            f"pack member exceeds {max_file_bytes} bytes: {info.filename}",
            path=info.filename,
        )
    if info.flag_bits & 0x1:
        raise PackFormatError("encrypted pack members are forbidden", path=info.filename)
    try:
        with archive.open(info) as member:
            contents = member.read(max_file_bytes + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PackFormatError("cannot read pack member", path=info.filename) from exc
    if len(contents) > max_file_bytes:
        raise PackFileTooLargeError(
            f"pack member exceeds {max_file_bytes} bytes: {info.filename}",
            path=info.filename,
        )
    return contents


def _parse_json_object(contents: bytes, *, name: str) -> dict[str, object]:
    try:
        value = json.loads(
            contents.decode("utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PackFormatError(f"{name} must be a valid UTF-8 JSON object", path=name) from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PackFormatError(f"{name} must be a JSON object", path=name)
    return value


def _parse_manifest(contents: bytes) -> PackManifest:
    value = _parse_json_object(contents, name="manifest.json")
    if set(value) != {"format", "format_version", "project"}:
        raise PackFormatError("manifest.json has unknown or missing fields", path="manifest.json")
    project = value.get("project")
    if not isinstance(project, dict) or set(project) != {"id", "version"}:
        raise PackFormatError(
            "manifest project has unknown or missing fields", path="manifest.json"
        )
    pack_format = value.get("format")
    format_version = value.get("format_version")
    project_id = project.get("id")
    project_version = project.get("version")
    if (
        pack_format != PACK_FORMAT
        or isinstance(format_version, bool)
        or format_version not in SUPPORTED_PACK_FORMAT_VERSIONS
    ):
        raise PackFormatError("unsupported capability-pack format or version", path="manifest.json")
    if not isinstance(project_id, str) or not project_id:
        raise PackFormatError(
            "manifest project id must be a non-empty string", path="manifest.json"
        )
    if not isinstance(project_version, str) or not project_version:
        raise PackFormatError(
            "manifest project version must be a non-empty string", path="manifest.json"
        )
    return PackManifest(
        format=pack_format,
        format_version=format_version,
        project_id=project_id,
        project_version=project_version,
    )


def _parse_lock(
    contents: bytes,
    *,
    format_version: int,
) -> tuple[PackFileRecord, ...]:
    value = _parse_json_object(contents, name="pack.lock")
    if set(value) != {"algorithm", "files", "format_version"}:
        raise PackFormatError("pack.lock has unknown or missing fields", path="pack.lock")
    if value.get("algorithm") != "sha256" or value.get("format_version") != format_version:
        raise PackFormatError("pack.lock has an unsupported algorithm or version", path="pack.lock")
    if isinstance(value.get("format_version"), bool):
        raise PackFormatError("pack.lock format_version must be an integer", path="pack.lock")
    files = value.get("files")
    if not isinstance(files, list):
        raise PackFormatError("pack.lock files must be an array", path="pack.lock")

    records: list[PackFileRecord] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise PackFormatError("pack.lock contains an invalid file record", path="pack.lock")
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(path, str):
            raise PackFormatError("pack.lock file path must be a string", path="pack.lock")
        _validate_member_path(path)
        if path == "pack.lock":
            raise PackFormatError("pack.lock cannot checksum itself", path="pack.lock")
        if not _is_allowed_entry(path, format_version=format_version):
            raise PackUnknownEntryError("pack.lock lists an unknown member", path=path)
        if path in seen:
            raise PackDuplicateEntryError("pack.lock repeats a member", path=path)
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise PackFormatError("pack.lock digest must be lowercase SHA-256", path=path)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PackFormatError("pack.lock size must be a non-negative integer", path=path)
        seen.add(path)
        records.append(PackFileRecord(path=path, sha256=digest, size=size))
    if [record.path for record in records] != sorted(record.path for record in records):
        raise PackFormatError("pack.lock records must use stable path ordering", path="pack.lock")
    return tuple(records)


def verify_pack(
    pack_path: str | os.PathLike[str],
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> PackVerification:
    """Verify safe paths, the allowlist, bounded members, and all lock checksums.

    Verification establishes archive integrity only. Without a trusted external
    digest or signature it does not authenticate the pack's publisher.
    """

    _validate_max_bytes(max_file_bytes)
    path = Path(pack_path)
    if path.is_symlink():
        raise PackSymlinkError("capability pack cannot be a symbolic link", path=str(path))
    if not path.is_file():
        raise PackFormatError("capability pack is not a regular file", path=str(path))

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            for name in names:
                _validate_member_path(name)
            if len(names) != len(set(names)):
                duplicate = next(name for name in names if names.count(name) > 1)
                raise PackDuplicateEntryError("capability pack repeats a member", path=duplicate)

            members: dict[str, bytes] = {}
            for info in infos:
                member_mode = info.external_attr >> 16
                member_type = stat.S_IFMT(member_mode)
                if member_type == stat.S_IFLNK:
                    raise PackSymlinkError(
                        "symbolic links are forbidden in capability packs", path=info.filename
                    )
                if info.is_dir() or member_type not in {0, stat.S_IFREG}:
                    raise PackUnknownEntryError(
                        "non-regular capability-pack members are forbidden", path=info.filename
                    )
                if not _is_allowed_entry(info.filename):
                    raise PackUnknownEntryError(
                        "unknown capability-pack member", path=info.filename
                    )
                members[info.filename] = _read_archive_member(archive, info, max_file_bytes)
    except CapabilityPackError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise PackFormatError(
            "capability pack is not a readable ZIP archive", path=str(path)
        ) from exc

    missing = sorted(_REQUIRED_ENTRIES - set(members))
    if missing:
        raise PackFormatError(f"capability pack is missing required members: {', '.join(missing)}")

    manifest = _parse_manifest(members["manifest.json"])
    for member_name in members:
        if not _is_allowed_entry(
            member_name,
            format_version=manifest.format_version,
        ):
            raise PackUnknownEntryError(
                "unknown capability-pack member for format version",
                path=member_name,
            )
    records = _parse_lock(
        members["pack.lock"],
        format_version=manifest.format_version,
    )
    expected_paths = set(members) - {"pack.lock"}
    locked_paths = {record.path for record in records}
    if expected_paths != locked_paths:
        raise PackChecksumMismatchError("pack.lock does not cover exactly every payload member")
    for record in records:
        contents = members[record.path]
        if len(contents) != record.size or _sha256(contents) != record.sha256:
            raise PackChecksumMismatchError(
                "capability-pack member does not match pack.lock", path=record.path
            )

    project_manifest = _project_manifest(members["project.yaml"])
    if manifest != project_manifest:
        raise PackFormatError("manifest project identity does not match project.yaml")
    return PackVerification(
        path=path,
        sha256=_file_sha256(path),
        manifest=manifest,
        files=records,
    )


def load_pack_manifest(
    pack_path: str | os.PathLike[str],
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> PackManifest:
    """Fully verify a capability pack, then return its strict manifest."""

    return verify_pack(pack_path, max_file_bytes=max_file_bytes).manifest


__all__ = [
    "CapabilityPackError",
    "PackBuildResult",
    "PackChecksumMismatchError",
    "PackDuplicateEntryError",
    "PackFileRecord",
    "PackFileTooLargeError",
    "PackFormatError",
    "PackManifest",
    "PackPathError",
    "PackSymlinkError",
    "PackUnknownEntryError",
    "PackVerification",
    "build_pack",
    "load_pack_manifest",
    "verify_pack",
]
