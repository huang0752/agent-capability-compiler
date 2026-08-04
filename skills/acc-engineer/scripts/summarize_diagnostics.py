#!/usr/bin/env python3
"""Summarize stable diagnostic codes without echoing diagnostic content."""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence

from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    bounded_size,
    diagnostic,
    emit,
    is_sensitive_path,
    read_file_bytes,
    safe_existing_path,
)


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command="summarize-diagnostics")
    value.add_argument("--input", default="-")
    value.add_argument("--max-file-bytes", type=bounded_size, default=DEFAULT_MAX_FILE_BYTES)
    return value


def load_input(raw_path: str, max_file_bytes: int) -> object:
    if raw_path == "-":
        raw = sys.stdin.buffer.read(max_file_bytes + 1)
        if len(raw) > max_file_bytes:
            raise SafePathError(
                "ACC_SKILL_FILE_TOO_LARGE", "stdin exceeds the configured read limit"
            )
    else:
        path = safe_existing_path(raw_path, kind="file")
        if is_sensitive_path(path.name):
            raise SafePathError(
                "ACC_SKILL_SECRET_REJECTED",
                "secret-like diagnostic input paths are not read",
                path=path.name,
            )
        metadata = path.stat()
        raw = read_file_bytes(path, metadata, max_file_bytes, path.name)
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafePathError(
            "ACC_SKILL_JSON_INVALID", "diagnostic input is not valid UTF-8 JSON"
        ) from exc


def collect_diagnostics(value: object) -> list[Mapping[str, object]]:
    collected: list[Mapping[str, object]] = []

    def visit(item: object, *, root_list: bool = False) -> None:
        if isinstance(item, Mapping):
            diagnostics = item.get("diagnostics")
            if isinstance(diagnostics, Sequence) and not isinstance(diagnostics, (str, bytes)):
                for candidate in diagnostics:
                    add(candidate)
            for key, child in item.items():
                if key != "diagnostics":
                    visit(child)
        elif isinstance(item, list):
            if root_list and all(isinstance(candidate, Mapping) for candidate in item):
                for candidate in item:
                    add(candidate)
            else:
                for child in item:
                    visit(child)

    def add(candidate: object) -> None:
        if not isinstance(candidate, Mapping):
            raise SafePathError("ACC_SKILL_JSON_INVALID", "diagnostics must contain JSON objects")
        code = candidate.get("code")
        severity = candidate.get("severity", "error")
        if not isinstance(code, str) or not code or not isinstance(severity, str):
            raise SafePathError(
                "ACC_SKILL_JSON_INVALID",
                "each diagnostic requires string code and severity",
            )
        collected.append(candidate)

    visit(value, root_list=True)
    return collected


def main(argv: list[str] | None = None) -> int:
    command = "summarize-diagnostics"
    arguments = parser().parse_args(argv)
    try:
        items = collect_diagnostics(load_input(arguments.input, arguments.max_file_bytes))
        by_code = Counter(str(item["code"]) for item in items)
        by_severity = Counter(str(item.get("severity", "error")) for item in items)
        result = {
            "total": len(items),
            "codes": sorted(by_code),
            "by_code": dict(sorted(by_code.items())),
            "by_severity": dict(sorted(by_severity.items())),
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
