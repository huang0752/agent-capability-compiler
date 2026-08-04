#!/usr/bin/env python3
"""Build a bounded, content-free inventory of a source workspace."""

from __future__ import annotations

from pathlib import Path

from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    bounded_size,
    diagnostic,
    emit,
    hash_file,
    is_sensitive_path,
    iter_workspace,
    safe_existing_path,
)


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="inventory")
    value.add_argument("--workspace", required=True)
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def is_openapi_candidate(relative: str) -> bool:
    name = Path(relative).name.lower()
    return name.startswith("openapi.") or name.startswith("swagger.")


def main(argv: list[str] | None = None) -> int:
    command = "inventory"
    arguments = parser().parse_args(argv)
    try:
        workspace = safe_existing_path(arguments.workspace, kind="directory")
        files: list[dict[str, object]] = []
        sensitive_paths: list[str] = []
        symlinks: list[str] = []
        openapi_candidates: list[str] = []
        for relative, path, metadata in iter_workspace(workspace):
            if path is None or metadata is None:
                symlinks.append(relative)
                continue
            if is_sensitive_path(relative):
                sensitive_paths.append(relative)
                continue
            files.append(
                {
                    "path": relative,
                    "size": metadata.st_size,
                    "sha256": hash_file(path, metadata, arguments.max_file_bytes, relative),
                    "extension": Path(relative).suffix.lower(),
                }
            )
            if is_openapi_candidate(relative):
                openapi_candidates.append(relative)
        result = {
            "root": str(workspace),
            "files": files,
            "sensitive_paths": sensitive_paths,
            "symlinks": symlinks,
            "openapi_candidates": openapi_candidates,
            "summary": {
                "regular_files": len(files),
                "sensitive_files_skipped": len(sensitive_paths),
                "symlinks_skipped": len(symlinks),
            },
        }
        emit(command, ok=True, result=result, diagnostics=[])
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
