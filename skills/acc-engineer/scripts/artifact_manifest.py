#!/usr/bin/env python3
"""Generate a deterministic, content-free manifest for a non-Git ACC project."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path

from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    bounded_size,
    diagnostic,
    emit,
    hash_file,
    is_path_link,
    is_sensitive_path,
    iter_workspace,
    reject_parent_segments,
    reject_symlink_components,
    safe_existing_path,
)


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="artifact-manifest")
    value.add_argument("--project", required=True)
    value.add_argument("--output")
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def output_path(project: Path, raw: str) -> tuple[Path, str]:
    """Resolve an output without allowing traversal, symlinks, or project escape."""

    reject_parent_segments(raw)
    supplied = Path(raw)
    target = supplied if supplied.is_absolute() else project / supplied
    target = target.absolute()
    if not target.is_relative_to(project) or target == project:
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "manifest output must be a file inside the ACC project",
            path=raw,
        )
    relative = target.relative_to(project).as_posix()
    if is_sensitive_path(relative):
        raise SafePathError(
            "ACC_SKILL_SECRET_REJECTED",
            "manifest output must not use a secret-like filename",
            path=relative,
        )
    reject_symlink_components(target, allow_missing_leaf=True)
    if target.exists() and not target.is_file():
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "manifest output must be a regular file",
            path=relative,
        )
    return target, relative


def reject_nested_workspaces(project: Path) -> None:
    """Reject Git metadata anywhere inside a project without following links."""

    def visit(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SafePathError(
                "ACC_SKILL_WORKSPACE_UNREADABLE",
                "ACC project directory cannot be read",
                path=prefix or ".",
            ) from exc
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if entry.name == ".git":
                raise SafePathError(
                    "ACC_SKILL_NESTED_WORKSPACE_REJECTED",
                    "Git workspaces are not accepted by the non-Git manifest helper",
                    path=relative,
                )
            if entry.is_dir(follow_symlinks=False) and not (
                entry.is_symlink() or bool(getattr(entry, "is_junction", lambda: False)())
            ):
                visit(Path(entry.path), relative)

    visit(project, "")


def build_manifest(
    project: Path, *, output_relative: str | None, max_file_bytes: int
) -> dict[str, object]:
    """Hash sorted regular files after fail-closed path safety checks."""

    reject_nested_workspaces(project)
    files: list[dict[str, object]] = []
    for relative, path, metadata in iter_workspace(project):
        if relative == output_relative:
            continue
        if path is None or metadata is None:
            raise SafePathError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "ACC project symlinks are not accepted",
                path=relative,
            )
        if is_sensitive_path(relative):
            raise SafePathError(
                "ACC_SKILL_SECRET_REJECTED",
                "secret-like ACC project files are not read",
                path=relative,
            )
        files.append(
            {
                "path": relative,
                "size": metadata.st_size,
                "sha256": hash_file(path, metadata, max_file_bytes, relative),
            }
        )
    canonical = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return {
        "algorithm": "sha256",
        "digest": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "files": files,
    }


def atomic_write_json(target: Path, value: dict[str, object]) -> None:
    """Atomically replace a regular manifest without following symlinks."""

    try:
        metadata = target.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_SYMLINK_REJECTED",
            "manifest output must not be a symlink",
            path=target.name,
        )
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "manifest output must be a regular file",
            path=target.name,
        )
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".acc-manifest-", dir=target.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if is_path_link(target):
            raise SafePathError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "manifest output became a symlink",
                path=target.name,
            )
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    command = "artifact-manifest"
    arguments = parser().parse_args(argv)
    try:
        project = safe_existing_path(arguments.project, kind="directory")
        target: Path | None = None
        output_relative: str | None = None
        if arguments.output is not None:
            target, output_relative = output_path(project, arguments.output)
        manifest = build_manifest(
            project,
            output_relative=output_relative,
            max_file_bytes=arguments.max_file_bytes,
        )
        if target is not None:
            atomic_write_json(target, manifest)
        emit(command, ok=True, result=manifest, diagnostics=[])
        return 0
    except SafePathError as exc:
        emit(
            command,
            ok=False,
            result=None,
            diagnostics=[diagnostic(exc.code, str(exc), path=exc.path)],
        )
        return 2 if exc.code == "ACC_SKILL_PATH_INVALID" else 3


if __name__ == "__main__":
    raise SystemExit(main())
