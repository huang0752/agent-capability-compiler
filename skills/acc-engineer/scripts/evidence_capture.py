#!/usr/bin/env python3
"""Capture source evidence metadata without copying source content."""

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
    is_sensitive_path,
    read_file_bytes,
    reject_parent_segments,
    reject_symlink_components,
    safe_existing_path,
)


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="evidence-capture")
    value.add_argument("--source-workspace", required=True)
    value.add_argument("--project-dir", required=True)
    value.add_argument("--source", required=True)
    value.add_argument("--source-id", required=True)
    value.add_argument("--output", required=True)
    value.add_argument("--line-start", type=int)
    value.add_argument("--line-end", type=int)
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def safe_relative(raw: str, *, suffix: str | None = None) -> Path:
    reject_parent_segments(raw)
    path = Path(raw)
    if path.is_absolute():
        raise SafePathError("ACC_SKILL_PATH_INVALID", "path must be relative", path=raw)
    if suffix is not None and path.suffix.lower() != suffix:
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID", f"path must use the {suffix} suffix", path=raw
        )
    return path


def ensure_disjoint(source: Path, project: Path) -> None:
    if source == project or source.is_relative_to(project) or project.is_relative_to(source):
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "source workspace and ACC project must not overlap",
        )


def validate_evidence_root(project: Path) -> Path:
    evidence = project / "evidence"
    try:
        metadata = evidence.lstat()
    except FileNotFoundError:
        return evidence
    if stat.S_ISLNK(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_SYMLINK_REJECTED",
            "ACC evidence directory must not be a symlink",
            path="evidence",
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "ACC evidence path must be a directory",
            path="evidence",
        )
    return evidence


def create_safe_parents(evidence: Path, relative_parent: Path) -> Path:
    if not evidence.exists():
        evidence.mkdir(mode=0o700)
    reject_symlink_components(evidence)
    current = evidence
    for part in relative_parent.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise SafePathError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "evidence output parent must not be a symlink",
                path=str(relative_parent),
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise SafePathError(
                "ACC_SKILL_PATH_INVALID",
                "evidence output parent must be a directory",
                path=str(relative_parent),
            )
    return current


def atomic_write_json(target: Path, value: dict[str, object]) -> None:
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_SYMLINK_REJECTED",
            "evidence output must not be a symlink",
            path=target.name,
        )
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "evidence output must be a regular file",
            path=target.name,
        )
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".acc-evidence-", dir=target.parent)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if target.is_symlink():
            raise SafePathError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "evidence output became a symlink",
                path=target.name,
            )
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    command = "evidence-capture"
    arguments = parser().parse_args(argv)
    try:
        source_root = safe_existing_path(arguments.source_workspace, kind="directory")
        project = safe_existing_path(arguments.project_dir, kind="directory")
        ensure_disjoint(source_root, project)
        source_relative = safe_relative(arguments.source)
        output_relative = safe_relative(arguments.output, suffix=".json")
        if is_sensitive_path(source_relative.as_posix()):
            raise SafePathError(
                "ACC_SKILL_SECRET_REJECTED",
                "secret-like source paths cannot be captured",
                path=source_relative.as_posix(),
            )
        evidence_root = validate_evidence_root(project)
        source_path = source_root / source_relative
        reject_symlink_components(source_path)
        if not source_path.is_file():
            raise SafePathError(
                "ACC_SKILL_PATH_INVALID",
                "evidence source must be a regular file",
                path=source_relative.as_posix(),
            )
        metadata = source_path.stat()
        raw = read_file_bytes(
            source_path,
            metadata,
            arguments.max_file_bytes,
            source_relative.as_posix(),
        )
        if (arguments.line_start is None) != (arguments.line_end is None):
            raise SafePathError(
                "ACC_SKILL_LINE_RANGE_INVALID",
                "line_start and line_end must be supplied together",
            )
        if arguments.line_start is not None and arguments.line_end is not None:
            if arguments.line_start < 1 or arguments.line_end < arguments.line_start:
                raise SafePathError(
                    "ACC_SKILL_LINE_RANGE_INVALID",
                    "line range must be positive and ordered",
                )
            try:
                line_count = len(raw.decode("utf-8").splitlines())
            except UnicodeDecodeError as exc:
                raise SafePathError(
                    "ACC_SKILL_TEXT_INVALID",
                    "line evidence requires UTF-8 source text",
                    path=source_relative.as_posix(),
                ) from exc
            if arguments.line_end > line_count:
                raise SafePathError(
                    "ACC_SKILL_LINE_RANGE_INVALID",
                    "line range exceeds the source file",
                )
        evidence: dict[str, object] = {
            "source_id": arguments.source_id,
            "kind": "source_file",
            "path": source_relative.as_posix(),
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "size_bytes": len(raw),
        }
        if arguments.line_start is not None:
            evidence["line_start"] = arguments.line_start
            evidence["line_end"] = arguments.line_end
        parent = create_safe_parents(evidence_root, output_relative.parent)
        target = parent / output_relative.name
        atomic_write_json(target, evidence)
        emit(
            command,
            ok=True,
            result={
                "output": f"evidence/{output_relative.as_posix()}",
                "evidence": evidence,
            },
            diagnostics=[],
        )
        return 0
    except SafePathError as exc:
        emit(
            command,
            ok=False,
            result=None,
            diagnostics=[diagnostic(exc.code, str(exc), path=exc.path)],
        )
        return 2 if exc.code in {"ACC_SKILL_PATH_INVALID", "ACC_SKILL_LINE_RANGE_INVALID"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
