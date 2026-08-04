"""Bounded, project-confined readers for ACC YAML and JSON documents."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, ClassVar, cast

import yaml

DEFAULT_MAX_FILE_BYTES = 1_048_576


class ProjectIOError(Exception):
    """Base class for explicit failures while reading an ACC project file."""

    code: ClassVar[str] = "ACC_IO_ERROR"

    def __init__(self, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.path = path


class InvalidProjectPathError(ProjectIOError, ValueError):
    """The requested path is not a valid project-relative path."""

    code = "ACC_IO_INVALID_PATH"


class InvalidProjectRootError(ProjectIOError):
    """The project root is missing, unsafe, or not a directory."""

    code = "ACC_IO_INVALID_ROOT"


class ProjectPathEscapeError(ProjectIOError):
    """Resolution placed the requested path outside the project root."""

    code = "ACC_IO_PATH_OUTSIDE_PROJECT"


class ProjectSymlinkError(ProjectIOError):
    """A project file path contains a symbolic link."""

    code = "ACC_IO_SYMLINK_REJECTED"


class ProjectFileNotFoundError(ProjectIOError, FileNotFoundError):
    """A requested project file does not exist."""

    code = "ACC_IO_NOT_FOUND"


class ProjectFileTypeError(ProjectIOError):
    """A requested project path is not a regular file."""

    code = "ACC_IO_NOT_A_FILE"


class ProjectFileTooLargeError(ProjectIOError):
    """A project file exceeds the configured byte limit."""

    code = "ACC_IO_FILE_TOO_LARGE"


class ProjectFileEncodingError(ProjectIOError, UnicodeError):
    """A project document is not valid UTF-8."""

    code = "ACC_IO_INVALID_UTF8"


class ProjectDocumentParseError(ProjectIOError):
    """A YAML or JSON document cannot be parsed."""

    code = "ACC_IO_PARSE_ERROR"


class ProjectDocumentTypeError(ProjectIOError, TypeError):
    """A parsed project document is not an object."""

    code = "ACC_IO_OBJECT_REQUIRED"


class UnsupportedProjectDocumentError(ProjectIOError):
    """A project document does not have a YAML or JSON suffix."""

    code = "ACC_IO_UNSUPPORTED_FORMAT"


def _relative_path_text(relative_path: str | os.PathLike[str]) -> str:
    raw_path = os.fspath(relative_path)
    if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
        raise InvalidProjectPathError(
            "project file path must be a non-empty string",
            path=raw_path if isinstance(raw_path, str) else None,
        )
    if "\\" in raw_path:
        raise InvalidProjectPathError(
            "project file path must use project-relative POSIX syntax",
            path=raw_path,
        )

    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise InvalidProjectPathError("absolute project file paths are forbidden", path=raw_path)
    if posix_path == PurePosixPath(".") or ".." in posix_path.parts:
        raise InvalidProjectPathError(
            "project file path cannot contain '..' segments",
            path=raw_path,
        )
    return raw_path


def _resolved_project_root(project_root: str | os.PathLike[str]) -> tuple[Path, Path]:
    root = Path(project_root)
    if root.is_symlink():
        raise ProjectSymlinkError("project root cannot be a symbolic link", path=".")
    try:
        resolved_root = root.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise InvalidProjectRootError(f"project root is unavailable: {root}", path=".") from exc
    if not resolved_root.is_dir():
        raise InvalidProjectRootError(f"project root is not a directory: {root}", path=".")
    return root, resolved_root


def resolve_project_path(
    project_root: str | os.PathLike[str],
    relative_path: str | os.PathLike[str],
) -> Path:
    """Resolve a path inside ``project_root`` without accepting symlinks or traversal."""

    relative_text = _relative_path_text(relative_path)
    relative = PurePosixPath(relative_text)
    root, resolved_root = _resolved_project_root(project_root)

    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ProjectSymlinkError(
                f"symbolic links are forbidden in project file paths: {relative_text}",
                path=relative_text,
            )

    resolved_candidate = candidate.resolve(strict=False)
    if not resolved_candidate.is_relative_to(resolved_root):
        raise ProjectPathEscapeError(
            f"project file path resolves outside the project root: {relative_text}",
            path=relative_text,
        )
    return resolved_candidate


def _validate_max_bytes(max_bytes: int) -> None:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")


def read_project_bytes(
    project_root: str | os.PathLike[str],
    relative_path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> bytes:
    """Read at most ``max_bytes`` from a regular, non-symlink project file."""

    _validate_max_bytes(max_bytes)
    relative_text = _relative_path_text(relative_path)
    target = resolve_project_path(project_root, relative_text)
    try:
        file_stat = target.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ProjectFileNotFoundError(
            f"project file does not exist: {relative_text}",
            path=relative_text,
        ) from exc
    except OSError as exc:
        raise ProjectIOError(
            f"cannot inspect project file: {relative_text}",
            path=relative_text,
        ) from exc

    if stat.S_ISLNK(file_stat.st_mode):
        raise ProjectSymlinkError(
            f"symbolic links are forbidden in project file paths: {relative_text}",
            path=relative_text,
        )
    if not stat.S_ISREG(file_stat.st_mode):
        raise ProjectFileTypeError(
            f"project path is not a regular file: {relative_text}",
            path=relative_text,
        )
    if file_stat.st_size > max_bytes:
        raise ProjectFileTooLargeError(
            f"project file exceeds {max_bytes} bytes: {relative_text}",
            path=relative_text,
        )

    try:
        with target.open("rb") as project_file:
            contents = project_file.read(max_bytes + 1)
    except OSError as exc:
        raise ProjectIOError(
            f"cannot read project file: {relative_text}",
            path=relative_text,
        ) from exc
    if len(contents) > max_bytes:
        raise ProjectFileTooLargeError(
            f"project file exceeds {max_bytes} bytes: {relative_text}",
            path=relative_text,
        )
    return contents


def read_project_text(
    project_root: str | os.PathLike[str],
    relative_path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> str:
    """Read a bounded project file and decode it as strict UTF-8."""

    relative_text = _relative_path_text(relative_path)
    contents = read_project_bytes(project_root, relative_text, max_bytes=max_bytes)
    try:
        return contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProjectFileEncodingError(
            f"project file is not valid UTF-8: {relative_text}",
            path=relative_text,
        ) from exc


def load_project_object(
    project_root: str | os.PathLike[str],
    relative_path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Load a bounded UTF-8 YAML or JSON file whose top level is an object."""

    relative_text = _relative_path_text(relative_path)
    suffix = PurePosixPath(relative_text).suffix.lower()
    if suffix not in {".yaml", ".yml", ".json"}:
        raise UnsupportedProjectDocumentError(
            f"project document must be YAML or JSON: {relative_text}",
            path=relative_text,
        )

    document = read_project_text(project_root, relative_text, max_bytes=max_bytes)
    try:
        loaded: Any = json.loads(document) if suffix == ".json" else yaml.safe_load(document)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ProjectDocumentParseError(
            f"cannot parse project document: {relative_text}",
            path=relative_text,
        ) from exc

    if not isinstance(loaded, dict):
        raise ProjectDocumentTypeError(
            f"project document must contain a top-level object: {relative_text}",
            path=relative_text,
        )
    return cast(dict[str, Any], loaded)


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "InvalidProjectPathError",
    "InvalidProjectRootError",
    "ProjectDocumentParseError",
    "ProjectDocumentTypeError",
    "ProjectFileEncodingError",
    "ProjectFileNotFoundError",
    "ProjectFileTooLargeError",
    "ProjectFileTypeError",
    "ProjectIOError",
    "ProjectPathEscapeError",
    "ProjectSymlinkError",
    "UnsupportedProjectDocumentError",
    "load_project_object",
    "read_project_bytes",
    "read_project_text",
    "resolve_project_path",
]
