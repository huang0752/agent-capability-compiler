#!/usr/bin/env python3
"""Fail-closed preflight checks for a read-only source analysis run."""

from __future__ import annotations

import shutil
from pathlib import Path

from inventory import is_openapi_candidate
from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    bounded_size,
    diagnostic,
    emit,
    is_sensitive_path,
    iter_workspace,
    safe_existing_path,
)


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="preflight")
    value.add_argument("--source-workspace", required=True)
    value.add_argument("--project-dir", required=True)
    value.add_argument("--acc-command", default="acc")
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def ensure_disjoint(source: Path, project: Path) -> None:
    if source == project or source.is_relative_to(project) or project.is_relative_to(source):
        raise SafePathError(
            "ACC_SKILL_PATH_INVALID",
            "source workspace and ACC project must not overlap",
        )


def is_test_candidate(relative: str) -> bool:
    path = Path(relative)
    name = path.name.lower()
    return (
        "tests" in {part.lower() for part in path.parts[:-1]}
        or name.startswith("test_")
        or name.endswith((".spec.js", ".spec.ts", ".test.js", ".test.ts"))
    )


def suggested_test_commands(files: list[str], test_candidates: list[str]) -> list[str]:
    names = {Path(path).name.lower() for path in files}
    commands: list[str] = []
    if any(path.endswith(".py") for path in test_candidates) or "pyproject.toml" in names:
        commands.append("pytest")
    if "package.json" in names:
        commands.append("npm test")
    if "pom.xml" in names:
        commands.append("mvn test")
    if "build.gradle" in names or "build.gradle.kts" in names:
        commands.append("gradle test")
    return commands


def main(argv: list[str] | None = None) -> int:
    command = "preflight"
    arguments = parser().parse_args(argv)
    try:
        source = safe_existing_path(arguments.source_workspace, kind="directory")
        project = safe_existing_path(arguments.project_dir, kind="directory")
        ensure_disjoint(source, project)
        acc_path = shutil.which(arguments.acc_command)
        regular_paths: list[str] = []
        sensitive_paths: list[str] = []
        symlinks: list[str] = []
        oversized: list[str] = []
        openapi_candidates: list[str] = []
        test_candidates: list[str] = []
        for relative, path, metadata in iter_workspace(source):
            if path is None or metadata is None:
                symlinks.append(relative)
                continue
            if is_sensitive_path(relative):
                sensitive_paths.append(relative)
            else:
                regular_paths.append(relative)
                if is_openapi_candidate(relative):
                    openapi_candidates.append(relative)
                if is_test_candidate(relative):
                    test_candidates.append(relative)
            if metadata.st_size > arguments.max_file_bytes:
                oversized.append(relative)

        diagnostics: list[dict[str, object]] = []
        if acc_path is None:
            diagnostics.append(
                diagnostic(
                    "ACC_SKILL_ACC_NOT_FOUND",
                    "ACC command is not available for the engineering workflow",
                )
            )
        if sensitive_paths:
            diagnostics.append(
                diagnostic(
                    "ACC_SKILL_SECRET_FILE_DETECTED",
                    "secret-like files are present and were not opened",
                    path=sensitive_paths[0],
                )
            )
        if symlinks:
            diagnostics.append(
                diagnostic(
                    "ACC_SKILL_SYMLINK_REJECTED",
                    "source workspace contains symlinks that will not be followed",
                    path=symlinks[0],
                )
            )
        if oversized:
            diagnostics.append(
                diagnostic(
                    "ACC_SKILL_FILE_TOO_LARGE",
                    "source workspace contains files above the configured read limit",
                    path=oversized[0],
                )
            )
        result = {
            "source_workspace": str(source),
            "project_dir": str(project),
            "source_mode": "read_only",
            "acc_available": acc_path is not None,
            "openapi_candidates": openapi_candidates,
            "test_candidates": test_candidates,
            "suggested_test_commands": suggested_test_commands(regular_paths, test_candidates),
            "sensitive_paths": sensitive_paths,
            "symlinks": symlinks,
            "oversized_paths": oversized,
        }
        emit(
            command,
            ok=not diagnostics,
            result=result,
            diagnostics=diagnostics,
        )
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
