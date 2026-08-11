#!/usr/bin/env python3
"""Safely capture platform-neutral Usage Evidence locator metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

import yaml

DEFAULT_MAX_FILE_BYTES = 1_048_576
MAX_FILE_BYTES = 100 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
SOURCE_LAYERS = frozenset({"client", "service", "test", "mcp", "runtime_observation"})
CLIENT_SURFACES = frozenset({"web", "mobile", "desktop", "cli", "automation", "other"})
_SENSITIVE_TOKEN = re.compile(
    r"(^|[._-])(secret|secrets|token|credential|credentials|password|authorization)([._-]|$)",
    re.IGNORECASE,
)


class SafeUsageError(ValueError):
    """A Usage Evidence safety boundary was violated."""

    def __init__(self, code: str, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path


def diagnostic(error: SafeUsageError) -> dict[str, object]:
    value: dict[str, object] = {
        "code": error.code,
        "severity": "error",
        "message": str(error),
    }
    if error.path is not None:
        value["path"] = error.path
    return value


def emit(*, ok: bool, result: object, diagnostics: list[dict[str, object]]) -> None:
    print(
        json.dumps(
            {
                "command": "usage-evidence-capture",
                "diagnostics": diagnostics,
                "ok": ok,
                "result": result,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


class JsonArgumentParser(argparse.ArgumentParser):
    """Argument parser with stable JSON errors."""

    def error(self, message: str) -> NoReturn:
        error = SafeUsageError("ACC_SKILL_USAGE", message)
        emit(ok=False, result=None, diagnostics=[diagnostic(error)])
        raise SystemExit(2)


def bounded_size(raw: str) -> int:
    try:
        size = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("file size limit must be an integer") from exc
    if not 1 <= size <= MAX_FILE_BYTES:
        raise argparse.ArgumentTypeError(f"file size limit must be between 1 and {MAX_FILE_BYTES}")
    return size


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser()
    value.add_argument("--source-workspace", required=True)
    value.add_argument("--acc-project", required=True)
    value.add_argument("--usage-project", required=True)
    value.add_argument("--accepted-mcp-digest", required=True)
    value.add_argument("--domain-id", required=True)
    value.add_argument("--source", required=True)
    value.add_argument("--source-id", required=True)
    value.add_argument("--source-layer", choices=sorted(SOURCE_LAYERS), required=True)
    value.add_argument("--client-surface", choices=sorted(CLIENT_SURFACES))
    value.add_argument("--output", required=True)
    value.add_argument("--line-start", type=int)
    value.add_argument("--line-end", type=int)
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def reject_parent_segments(raw: str) -> None:
    if not raw or ".." in raw.replace("\\", "/").split("/"):
        raise SafeUsageError(
            "ACC_SKILL_PATH_INVALID",
            "paths must not be empty or contain parent traversal segments",
            path=raw,
        )


def reject_symlink_components(path: Path, *, allow_missing: bool = False) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                return
            raise SafeUsageError(
                "ACC_SKILL_PATH_INVALID", "path component does not exist", path=str(path)
            ) from None
        if stat.S_ISLNK(metadata.st_mode):
            raise SafeUsageError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "symlink path components are not allowed",
                path=str(path),
            )


def existing_directory(raw: str) -> Path:
    reject_parent_segments(raw)
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    reject_symlink_components(path)
    if not path.is_dir():
        raise SafeUsageError("ACC_SKILL_PATH_INVALID", "path is not a directory", path=raw)
    return path.resolve(strict=True)


def ensure_disjoint(*roots: Path) -> None:
    for index, first in enumerate(roots):
        for second in roots[index + 1 :]:
            if first == second or first.is_relative_to(second) or second.is_relative_to(first):
                raise SafeUsageError(
                    "ACC_SKILL_PATH_INVALID",
                    "source, ACC, and Usage roots must be pairwise disjoint",
                )


def safe_relative(raw: str, *, suffix: str | None = None) -> Path:
    reject_parent_segments(raw)
    path = Path(raw)
    if path.is_absolute() or Path(raw.replace("\\", "/")).anchor:
        raise SafeUsageError("ACC_SKILL_PATH_INVALID", "path must be relative", path=raw)
    if suffix is not None and path.suffix.lower() != suffix:
        raise SafeUsageError(
            "ACC_SKILL_PATH_INVALID", f"path must use the {suffix} suffix", path=raw
        )
    return path


def is_sensitive_path(relative: str) -> bool:
    name = Path(relative).name.lower()
    return (
        name == ".env"
        or name.startswith(".env.")
        or name in {"id_rsa", "id_ed25519", "credentials.json"}
        or Path(name).suffix in {".key", ".pem", ".p12", ".pfx"}
        or _SENSITIVE_TOKEN.search(name) is not None
    )


def read_regular_file(path: Path, relative: str, max_bytes: int) -> tuple[bytes, os.stat_result]:
    reject_symlink_components(path)
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise SafeUsageError(
            "ACC_SKILL_PATH_INVALID", "source must be a regular file", path=relative
        ) from exc
    if not stat.S_ISREG(before.st_mode):
        raise SafeUsageError(
            "ACC_SKILL_PATH_INVALID", "source must be a regular file", path=relative
        )
    if before.st_size > max_bytes:
        raise SafeUsageError(
            "ACC_SKILL_FILE_TOO_LARGE",
            "file exceeds the configured read limit",
            path=relative,
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SafeUsageError(
            "ACC_SKILL_WORKSPACE_UNREADABLE", "file cannot be opened safely", path=relative
        ) from exc
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise SafeUsageError(
                "ACC_SKILL_FILE_CHANGED", "file changed during read", path=relative
            )
        total = 0
        while chunk := os.read(descriptor, READ_CHUNK_BYTES):
            total += len(chunk)
            if total > max_bytes:
                raise SafeUsageError(
                    "ACC_SKILL_FILE_TOO_LARGE",
                    "file exceeds the configured read limit",
                    path=relative,
                )
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    after = path.stat(follow_symlinks=False)
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity):
        raise SafeUsageError("ACC_SKILL_FILE_CHANGED", "file changed during read", path=relative)
    return b"".join(chunks), after


def load_acceptance(usage_root: Path, max_bytes: int) -> Mapping[str, object]:
    relative = "mcp-release-acceptance.yaml"
    raw, _ = read_regular_file(usage_root / relative, relative, max_bytes)
    try:
        value = yaml.safe_load(raw)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SafeUsageError(
            "ACC_USAGE_RELEASE_NOT_ACCEPTED", "MCP acceptance record is invalid", path=relative
        ) from exc
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise SafeUsageError(
            "ACC_USAGE_RELEASE_NOT_ACCEPTED", "MCP acceptance record is invalid", path=relative
        )
    if any(_SENSITIVE_TOKEN.search(key) for key in value):
        raise SafeUsageError(
            "ACC_SKILL_SECRET_REJECTED", "MCP acceptance contains secret-like fields", path=relative
        )
    return value


def validate_acceptance(
    acceptance: Mapping[str, object], accepted_digest: str, domain_id: str
) -> None:
    if acceptance.get("pack_digest") != accepted_digest:
        raise SafeUsageError(
            "ACC_USAGE_RELEASE_NOT_ACCEPTED", "accepted MCP digest does not match the fixed Release"
        )
    accepted_domains = acceptance.get("accepted_domain_ids")
    if not isinstance(accepted_domains, list) or domain_id not in accepted_domains:
        raise SafeUsageError(
            "ACC_USAGE_DOMAIN_NOT_ACCEPTED", "domain is not accepted by the fixed MCP Release"
        )


def safe_output_parent(usage_root: Path, source_layer: str, parent: Path) -> Path:
    current = usage_root
    for part in ("usage-evidence", source_layer, *parent.parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise SafeUsageError(
                "ACC_SKILL_SYMLINK_REJECTED",
                "Usage Evidence output directories must not be symlinks",
                path=str(current.relative_to(usage_root)),
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise SafeUsageError(
                "ACC_SKILL_PATH_INVALID",
                "Usage Evidence output parent must be a directory",
                path=str(current.relative_to(usage_root)),
            )
    return current


def atomic_write_json(target: Path, value: Mapping[str, object]) -> None:
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise SafeUsageError(
            "ACC_SKILL_SYMLINK_REJECTED", "Usage Evidence output must not be a symlink"
        )
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise SafeUsageError(
            "ACC_SKILL_PATH_INVALID", "Usage Evidence output must be a regular file"
        )
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".acc-usage-evidence-", dir=target.parent)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if target.is_symlink():
            raise SafeUsageError(
                "ACC_SKILL_SYMLINK_REJECTED", "Usage Evidence output became a symlink"
            )
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def validate_line_range(raw: bytes, line_start: int | None, line_end: int | None) -> None:
    if (line_start is None) != (line_end is None):
        raise SafeUsageError(
            "ACC_SKILL_LINE_RANGE_INVALID", "line_start and line_end must be supplied together"
        )
    if line_start is None or line_end is None:
        return
    if line_start < 1 or line_end < line_start:
        raise SafeUsageError(
            "ACC_SKILL_LINE_RANGE_INVALID", "line range must be positive and ordered"
        )
    try:
        line_count = len(raw.decode("utf-8").splitlines())
    except UnicodeDecodeError as exc:
        raise SafeUsageError("ACC_SKILL_TEXT_INVALID", "line evidence requires UTF-8") from exc
    if line_end > line_count:
        raise SafeUsageError("ACC_SKILL_LINE_RANGE_INVALID", "line range exceeds source file")


def validate_source_layer(source_layer: str, client_surface: str | None) -> None:
    if source_layer == "client" and client_surface is None:
        raise SafeUsageError(
            "ACC_SKILL_USAGE", "client evidence requires an explicit --client-surface"
        )
    if source_layer != "client" and client_surface is not None:
        raise SafeUsageError(
            "ACC_SKILL_USAGE", "--client-surface is only valid for client evidence"
        )


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        source_root = existing_directory(arguments.source_workspace)
        acc_root = existing_directory(arguments.acc_project)
        usage_root = existing_directory(arguments.usage_project)
        ensure_disjoint(source_root, acc_root, usage_root)
        validate_source_layer(arguments.source_layer, arguments.client_surface)

        acceptance = load_acceptance(usage_root, arguments.max_file_bytes)
        validate_acceptance(acceptance, arguments.accepted_mcp_digest, arguments.domain_id)

        source_relative = safe_relative(arguments.source)
        output_relative = safe_relative(arguments.output, suffix=".json")
        if is_sensitive_path(source_relative.as_posix()):
            raise SafeUsageError(
                "ACC_SKILL_SECRET_REJECTED",
                "secret-like source paths cannot be captured",
                path=source_relative.as_posix(),
            )
        raw, source_after = read_regular_file(
            source_root / source_relative,
            source_relative.as_posix(),
            arguments.max_file_bytes,
        )
        validate_line_range(raw, arguments.line_start, arguments.line_end)
        evidence: dict[str, object] = {
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "domain_id": arguments.domain_id,
            "kind": "source_file",
            "path": source_relative.as_posix(),
            "size_bytes": len(raw),
            "source_layer": arguments.source_layer,
            "source_id": arguments.source_id,
        }
        if arguments.client_surface is not None:
            evidence["client_surface"] = arguments.client_surface
        if arguments.line_start is not None:
            evidence["line_start"] = arguments.line_start
            evidence["line_end"] = arguments.line_end
        parent = safe_output_parent(usage_root, arguments.source_layer, output_relative.parent)
        target = parent / output_relative.name
        # Recheck immediately before the only write performed by this command.
        current = (source_root / source_relative).stat(follow_symlinks=False)
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(source_after, field) != getattr(current, field) for field in identity):
            raise SafeUsageError(
                "ACC_SKILL_FILE_CHANGED",
                "source changed before Usage Evidence write",
                path=source_relative.as_posix(),
            )
        atomic_write_json(target, evidence)
        emit(
            ok=True,
            result={
                "evidence": evidence,
                "output": (
                    Path("usage-evidence") / arguments.source_layer / output_relative
                ).as_posix(),
            },
            diagnostics=[],
        )
        return 0
    except SafeUsageError as exc:
        emit(ok=False, result=None, diagnostics=[diagnostic(exc)])
        return (
            2
            if exc.code
            in {"ACC_SKILL_PATH_INVALID", "ACC_SKILL_LINE_RANGE_INVALID", "ACC_SKILL_USAGE"}
            else 3
        )


if __name__ == "__main__":
    raise SystemExit(main())
