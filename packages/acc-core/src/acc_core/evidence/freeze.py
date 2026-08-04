"""Read-only evidence hashing with writes confined to ACC operation files."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

import yaml
from pydantic import JsonValue

from acc_core.io import (
    DEFAULT_MAX_FILE_BYTES,
    InvalidProjectRootError,
    ProjectFileNotFoundError,
    ProjectFileTypeError,
    ProjectIOError,
    ProjectSymlinkError,
    load_project_object,
    read_project_bytes,
    resolve_project_path,
)
from acc_core.models import Evidence, Operation, Project

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


class EvidenceFreezeError(ProjectIOError):
    """Base class for deterministic evidence-freeze failures."""

    code: ClassVar[str] = "ACC_EVIDENCE_FREEZE_ERROR"


class EvidenceOperationNotFoundError(EvidenceFreezeError, LookupError):
    """The requested operation id does not exist in the ACC project."""

    code = "ACC_EVIDENCE_OPERATION_NOT_FOUND"


class EvidenceOperationDuplicateError(EvidenceFreezeError):
    """More than one ACC operation document declares the requested id."""

    code = "ACC_EVIDENCE_OPERATION_DUPLICATE"


class EvidenceLocatorError(EvidenceFreezeError, ValueError):
    """Evidence does not identify a source-workspace file."""

    code = "ACC_EVIDENCE_LOCATOR_INVALID"


def _reject_symlink_components(path: Path, *, display_path: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ProjectSymlinkError(
                f"symbolic links are forbidden in source workspace paths: {display_path}",
                path=display_path,
            )


def _source_workspace_root(project_root: Path, project: Project) -> Path:
    declared_path = project.source_workspace.path
    source = Path(declared_path)
    if not source.is_absolute():
        source = project_root / source
    _reject_symlink_components(source, display_path=declared_path)
    try:
        resolved = source.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise InvalidProjectRootError(
            f"source workspace is unavailable: {declared_path}", path=declared_path
        ) from exc
    if not resolved.is_dir():
        raise InvalidProjectRootError(
            f"source workspace is not a directory: {declared_path}", path=declared_path
        )
    resolved_project = project_root.resolve(strict=True)
    if resolved_project.is_relative_to(resolved):
        raise EvidenceFreezeError(
            "source workspace contains the ACC project and cannot be frozen safely",
            path=declared_path,
        )
    if resolved.is_relative_to(resolved_project):
        raise EvidenceFreezeError(
            "source workspace and ACC project overlap and cannot be frozen safely",
            path=declared_path,
        )
    return resolved


def _operation_document(
    project_root: Path, operation_id: str
) -> tuple[str, dict[str, Any], Operation]:
    operations_path = resolve_project_path(project_root, "operations")
    if not operations_path.exists():
        raise EvidenceOperationNotFoundError(
            f"operation does not exist: {operation_id}", path="operations"
        )
    if not operations_path.is_dir():
        raise ProjectFileTypeError("project operations path is not a directory", path="operations")

    matches: list[tuple[str, dict[str, Any], Operation]] = []
    for entry in sorted(operations_path.iterdir(), key=lambda item: item.name):
        relative_path = f"operations/{entry.name}"
        if entry.is_symlink():
            raise ProjectSymlinkError(
                f"symbolic links are forbidden in project file paths: {relative_path}",
                path=relative_path,
            )
        if not entry.is_file() or entry.suffix.lower() not in _DOCUMENT_SUFFIXES:
            continue
        document = load_project_object(project_root, relative_path)
        operation = Operation.model_validate(document)
        if operation.id == operation_id:
            matches.append((relative_path, document, operation))

    if not matches:
        raise EvidenceOperationNotFoundError(
            f"operation does not exist: {operation_id}", path="operations"
        )
    if len(matches) > 1:
        raise EvidenceOperationDuplicateError(
            f"duplicate operation id cannot be frozen: {operation_id}", path="operations"
        )
    return matches[0]


def _evidence_path(evidence: Evidence) -> str:
    if evidence.path is not None:
        return evidence.path
    if evidence.locator is None:
        raise EvidenceLocatorError("evidence does not contain a source file path")

    locator_path = evidence.locator.split("#", 1)[0]
    parsed = urlsplit(locator_path)
    if not locator_path or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise EvidenceLocatorError(
            f"evidence locator is not a source-workspace file: {evidence.locator}"
        )
    return locator_path


def _serialize_operation(path: str, document: dict[str, Any]) -> bytes:
    if Path(path).suffix.lower() == ".json":
        return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode()


def _replace_operation_file(project_root: Path, relative_path: str, contents: bytes) -> None:
    target = resolve_project_path(project_root, relative_path)
    if not target.exists():
        raise ProjectFileNotFoundError(
            f"project file does not exist: {relative_path}", path=relative_path
        )
    if target.is_symlink():
        raise ProjectSymlinkError(
            f"symbolic links are forbidden in project file paths: {relative_path}",
            path=relative_path,
        )
    file_mode = stat.S_IMODE(target.stat(follow_symlinks=False).st_mode)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target.parent, prefix=".acc-freeze-", delete=False
        ) as file:
            temporary_path = file.name
            file.write(contents)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, file_mode)
        if target.is_symlink():
            raise ProjectSymlinkError(
                f"symbolic links are forbidden in project file paths: {relative_path}",
                path=relative_path,
            )
        os.replace(temporary_path, target)
        temporary_path = None
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


def freeze_operation_evidence(
    project_root: str | Path,
    operation_id: str,
    *,
    write: bool = False,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, object]:
    """Hash evidence source files and optionally update one ACC operation.

    Source-workspace paths are only passed to the bounded, symlink-rejecting
    project reader. All sources are read successfully before an operation file
    is replaced, so a failed freeze cannot partially update its evidence list.
    """

    if not isinstance(operation_id, str) or not operation_id:
        raise ValueError("operation_id must be a non-empty string")
    if not isinstance(write, bool):
        raise TypeError("write must be a boolean")

    root = Path(project_root)
    project = Project.model_validate(load_project_object(root, "project.yaml"))
    source_root = _source_workspace_root(root, project)
    operation_path, operation_document, operation = _operation_document(root, operation_id)

    frozen_evidence: list[dict[str, JsonValue]] = []
    digests: list[str] = []
    for index, evidence in enumerate(operation.evidence):
        source_path = _evidence_path(evidence)
        contents = read_project_bytes(source_root, source_path, max_bytes=max_bytes)
        digest = f"sha256:{hashlib.sha256(contents).hexdigest()}"
        digests.append(digest)
        frozen_evidence.append(
            {
                "index": index,
                "path": source_path,
                "size_bytes": len(contents),
                "digest": digest,
            }
        )

    if write:
        raw_evidence = operation_document.get("evidence")
        if not isinstance(raw_evidence, list) or len(raw_evidence) != len(digests):
            raise EvidenceFreezeError(
                "operation evidence changed while preparing the freeze", path=operation_path
            )
        for index, digest in enumerate(digests):
            item = raw_evidence[index]
            if not isinstance(item, dict):
                raise EvidenceFreezeError(
                    "operation evidence must contain objects", path=operation_path
                )
            item["digest"] = digest
        _replace_operation_file(
            root,
            operation_path,
            _serialize_operation(operation_path, operation_document),
        )

    return {
        "freeze_version": "1",
        "operation_id": operation_id,
        "operation_path": operation_path,
        "written": write,
        "evidence": frozen_evidence,
    }


__all__ = [
    "EvidenceFreezeError",
    "EvidenceLocatorError",
    "EvidenceOperationDuplicateError",
    "EvidenceOperationNotFoundError",
    "freeze_operation_evidence",
]
