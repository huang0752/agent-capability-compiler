#!/usr/bin/env python3
"""Snapshot a source workspace without writing it or following symlinks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NoReturn, cast

DEFAULT_MAX_FILE_BYTES = 1_048_576
MAX_FILE_BYTES = 100 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
type WalkEntry = tuple[str, Path, os.stat_result] | tuple[str, None, None]
_SENSITIVE_TOKEN = re.compile(
    r"(^|[._-])(secret|secrets|token|credential|credentials)([._-]|$)",
    re.IGNORECASE,
)


class SafePathError(ValueError):
    """A path violates the skill's no-traversal/no-symlink boundary."""

    def __init__(self, code: str, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path


class JsonArgumentParser(argparse.ArgumentParser):
    """Argument parser that never writes human-only usage text."""

    def __init__(self, *args: Any, command: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.command = command

    def error(self, message: str) -> NoReturn:
        emit(
            self.command,
            ok=False,
            result=None,
            diagnostics=[diagnostic("ACC_SKILL_USAGE", message)],
        )
        raise SystemExit(2)


def diagnostic(
    code: str,
    message: str,
    *,
    path: str | None = None,
    pointer: str | None = None,
    severity: str = "error",
) -> dict[str, object]:
    value: dict[str, object] = {
        "code": code,
        "severity": severity,
        "message": message,
    }
    if path is not None:
        value["path"] = path
    if pointer is not None:
        value["pointer"] = pointer
    return value


def emit(
    command: str,
    *,
    ok: bool,
    result: object,
    diagnostics: list[dict[str, object]],
) -> None:
    print(
        json.dumps(
            {
                "ok": ok,
                "command": command,
                "result": result,
                "diagnostics": diagnostics,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


def bounded_size(value: str) -> int:
    try:
        size = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("file size limit must be an integer") from exc
    if not 1 <= size <= MAX_FILE_BYTES:
        raise argparse.ArgumentTypeError(f"file size limit must be between 1 and {MAX_FILE_BYTES}")
    return size


def safe_existing_path(raw: str, *, kind: str) -> Path:
    reject_parent_segments(raw)
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    reject_symlink_components(path)
    if kind == "directory" and not path.is_dir():
        raise SafePathError("ACC_SKILL_PATH_INVALID", "path is not a directory", path=raw)
    if kind == "file" and not path.is_file():
        raise SafePathError("ACC_SKILL_PATH_INVALID", "path is not a file", path=raw)
    return path.resolve(strict=True)


def reject_parent_segments(raw: str) -> None:
    normalized_parts = raw.replace("\\", "/").split("/")
    if not raw or ".." in normalized_parts:
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "paths must not be empty or contain parent traversal segments",
            path=raw,
        )


def is_sensitive_path(relative: str) -> bool:
    """Classify secret-like names without opening or inspecting their content."""

    name = Path(relative).name.lower()
    return (
        name == ".env"
        or name.startswith(".env.")
        or name in {"id_rsa", "id_ed25519", "credentials.json"}
        or Path(name).suffix in {".key", ".pem", ".p12", ".pfx"}
        or _SENSITIVE_TOKEN.search(name) is not None
    )


def reject_symlink_components(path: Path, *, allow_missing_leaf: bool = False) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and index == len(parts) - 1:
                return
            raise SafePathError(
                "ACC_SKILL_PATH_INVALID", "path component does not exist", path=str(path)
            ) from None
        if stat.S_ISLNK(metadata.st_mode):
            raise SafePathError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "symlink path components are not allowed",
                path=str(path),
            )


def normalize_include_paths(root: Path, raw_paths: list[str] | None) -> list[str]:
    """Validate and normalize explicit workspace-relative scan boundaries."""

    if not raw_paths:
        return []
    normalized: list[str] = []
    for raw in raw_paths:
        reject_parent_segments(raw)
        relative = Path(raw)
        if relative.is_absolute():
            raise SafePathError(
                "ACC_SKILL_PATH_INVALID",
                "include paths must be relative to the workspace",
                path=raw,
            )
        candidate = root / relative
        reject_symlink_components(candidate)
        if not candidate.exists():
            raise SafePathError(
                "ACC_SKILL_PATH_INVALID",
                "include path does not exist",
                path=raw,
            )
        value = candidate.relative_to(root).as_posix()
        if value == ".":
            return ["."]
        normalized.append(value)

    selected: list[str] = []
    for value in sorted(set(normalized)):
        path = Path(value)
        if any(path == Path(parent) or path.is_relative_to(Path(parent)) for parent in selected):
            continue
        selected.append(value)
    return selected


def iter_workspace(root: Path, include_paths: list[str] | None = None) -> Iterator[WalkEntry]:
    """Yield sorted regular files and symlink markers without following links."""

    def visit(directory: Path, prefix: str) -> Iterator[WalkEntry]:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SafePathError(
                "ACC_SKILL_WORKSPACE_UNREADABLE",
                "workspace directory cannot be read",
                path=prefix or ".",
            ) from exc
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if entry.is_symlink():
                yield relative, None, None
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    yield from visit(Path(entry.path), relative)
                elif entry.is_file(follow_symlinks=False):
                    yield relative, Path(entry.path), entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SafePathError(
                    "ACC_SKILL_WORKSPACE_UNREADABLE",
                    "workspace entry cannot be inspected",
                    path=relative,
                ) from exc

    selected = normalize_include_paths(root, include_paths)
    if not selected or selected == ["."]:
        yield from visit(root, "")
        return
    for relative in selected:
        path = root / relative
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            yield from visit(path, relative)
        elif stat.S_ISREG(metadata.st_mode):
            yield relative, path, metadata


def hash_file(path: Path, metadata: os.stat_result, max_file_bytes: int, relative: str) -> str:
    raw = read_file_bytes(path, metadata, max_file_bytes, relative)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def read_file_bytes(
    path: Path, metadata: os.stat_result, max_file_bytes: int, relative: str
) -> bytes:
    if metadata.st_size > max_file_bytes:
        raise SafePathError(
            "ACC_SKILL_FILE_TOO_LARGE",
            "file exceeds the configured read limit",
            path=relative,
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SafePathError(
            "ACC_SKILL_WORKSPACE_UNREADABLE", "file cannot be opened safely", path=relative
        ) from exc
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise SafePathError(
                "ACC_SKILL_FILE_CHANGED", "file changed during safe inspection", path=relative
            )
        total = 0
        while chunk := os.read(descriptor, READ_CHUNK_BYTES):
            total += len(chunk)
            if total > max_file_bytes:
                raise SafePathError(
                    "ACC_SKILL_FILE_TOO_LARGE",
                    "file exceeds the configured read limit",
                    path=relative,
                )
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def build_snapshot(
    root: Path,
    max_file_bytes: int,
    include_paths: list[str] | None = None,
) -> dict[str, object]:
    selected = normalize_include_paths(root, include_paths)
    files: list[dict[str, object]] = []
    sensitive_paths: list[dict[str, object]] = []
    symlinks: list[str] = []
    for relative, path, metadata in iter_workspace(root, selected):
        if path is None or metadata is None:
            symlinks.append(relative)
            continue
        if is_sensitive_path(relative):
            sensitive_paths.append({"path": relative, "size": metadata.st_size})
            continue
        files.append(
            {
                "path": relative,
                "size": metadata.st_size,
                "sha256": hash_file(path, metadata, max_file_bytes, relative),
            }
        )
    canonical = json.dumps(
        {
            "include_paths": selected,
            "files": files,
            "sensitive_paths": sensitive_paths,
            "symlinks": symlinks,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "algorithm": "sha256",
        "digest": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "include_paths": selected,
        "files": files,
        "sensitive_paths": sensitive_paths,
        "symlinks": symlinks,
    }


def read_json_file(raw: str, max_file_bytes: int) -> object:
    path = safe_existing_path(raw, kind="file")
    if is_sensitive_path(path.name):
        raise SafePathError(
            "ACC_SKILL_SECRET_REJECTED",
            "secret-like JSON input paths are not read",
            path=path.name,
        )
    metadata = path.stat()
    content = read_file_bytes(path, metadata, max_file_bytes, path.name)
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafePathError(
            "ACC_SKILL_JSON_INVALID", "input is not valid UTF-8 JSON", path=path.name
        ) from exc


def snapshot_from_document(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        result = value.get("result")
        if isinstance(result, Mapping):
            nested_snapshot = result.get("snapshot")
            if isinstance(nested_snapshot, Mapping) and all(
                isinstance(key, str) for key in nested_snapshot
            ):
                return cast(Mapping[str, object], nested_snapshot)
        direct_snapshot = value.get("snapshot")
        if isinstance(direct_snapshot, Mapping) and all(
            isinstance(key, str) for key in direct_snapshot
        ):
            return cast(Mapping[str, object], direct_snapshot)
        if "digest" in value and "files" in value:
            return value
    raise SafePathError("ACC_SKILL_JSON_INVALID", "baseline does not contain a workspace snapshot")


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="verify-read-only-workspace")
    value.add_argument("--workspace", required=True)
    value.add_argument("--baseline")
    value.add_argument("--include", action="append", default=[])
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def main(argv: list[str] | None = None) -> int:
    command = "verify-read-only-workspace"
    arguments = parser().parse_args(argv)
    try:
        workspace = safe_existing_path(arguments.workspace, kind="directory")
        snapshot = build_snapshot(workspace, arguments.max_file_bytes, arguments.include)
        unchanged: bool | None = None
        diagnostics: list[dict[str, object]] = []
        if arguments.baseline:
            baseline = snapshot_from_document(
                read_json_file(arguments.baseline, arguments.max_file_bytes)
            )
            unchanged = baseline.get("digest") == snapshot["digest"]
            if not unchanged:
                diagnostics.append(
                    diagnostic(
                        "ACC_SKILL_WORKSPACE_CHANGED",
                        "workspace differs from the supplied read-only baseline",
                    )
                )
        result = {
            "root": str(workspace),
            "snapshot": snapshot,
            "unchanged": unchanged,
        }
        emit(command, ok=not diagnostics, result=result, diagnostics=diagnostics)
        return 0 if not diagnostics else 3
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
