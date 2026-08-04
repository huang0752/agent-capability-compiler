"""The stable ``acc`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Never, cast

import yaml

from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.schemas import export_schemas
from acc_core.validation import validate_project

EXIT_SUCCESS = 0
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_COMPILE = 4
EXIT_TEST = 5
EXIT_RUNTIME = 6


class CliUsageError(Exception):
    """An argparse failure that can be rendered as a JSON diagnostic."""


class AccArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise CliUsageError(message)


CommandHandler = Callable[[argparse.Namespace], tuple[int, ResultEnvelope]]


def _add_json_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")


def _parser() -> AccArgumentParser:
    parser = AccArgumentParser(prog="acc", description="Agent Capability Compiler")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="initialize an isolated ACC project")
    init_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(init_parser)
    init_parser.set_defaults(handler=_init_command)

    doctor_parser = subparsers.add_parser("doctor", help="check the local ACC environment")
    doctor_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(doctor_parser)
    doctor_parser.set_defaults(handler=_doctor_command)

    schema_parser = subparsers.add_parser("schema", help="export public JSON Schemas")
    schema_parser.add_argument("--output", default="schemas")
    _add_json_argument(schema_parser)
    schema_parser.set_defaults(handler=_schema_command)

    validate_parser = subparsers.add_parser("validate", help="validate an ACC project")
    validate_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(validate_parser)
    validate_parser.set_defaults(handler=_validate_command)
    return parser


def _success(command: str, result: dict[str, Any]) -> ResultEnvelope:
    return ResultEnvelope(ok=True, command=command, result=result, diagnostics=[])


def _failure(command: str, diagnostic: Diagnostic) -> ResultEnvelope:
    return ResultEnvelope(ok=False, command=command, result=None, diagnostics=[diagnostic])


def _init_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    target = Path(str(arguments.path)).expanduser().resolve()
    project_file = target / "project.yaml"
    if project_file.exists() or (target.exists() and any(target.iterdir())):
        return EXIT_INPUT, _failure(
            "init",
            Diagnostic(
                code="ACC_PROJECT_EXISTS",
                severity="error",
                message="ACC project directory already contains files.",
                path=None,
                pointer=None,
            ),
        )
    target.mkdir(parents=True, exist_ok=True)
    for directory in ("capabilities", "evals", "evidence", "operations", "policies"):
        (target / directory).mkdir()
    template = {
        "schema_version": "1",
        "project": {"id": target.name, "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {"kind": "http", "base_url_ref": "ACC_TARGET_BASE_URL"},
    }
    project_file.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
    return EXIT_SUCCESS, _success("init", {"path": str(target)})


def _doctor_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    project_root = Path(str(arguments.path)).resolve()
    python_ok = sys.version_info[:2] == (3, 12)
    report = validate_project(project_root)
    project_diagnostics = [
        item
        for item in report.diagnostics
        if item.path == "project.yaml" or item.code.startswith("ACC_IO_")
    ]
    project_ok = report.project is not None and not project_diagnostics
    checks = [
        {
            "name": "python",
            "ok": python_ok,
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        {"name": "project", "ok": project_ok, "detail": str(project_root)},
    ]
    if python_ok and project_ok:
        return EXIT_SUCCESS, _success("doctor", {"checks": checks})
    diagnostic = (
        project_diagnostics[0]
        if project_diagnostics
        else Diagnostic(
            code="ACC_DOCTOR_FAILED",
            severity="error",
            message="ACC requires Python 3.12 and a valid project.yaml.",
            path=None,
            pointer=None,
        )
    )
    return EXIT_INPUT, _failure("doctor", diagnostic)


def _schema_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    try:
        written = export_schemas(Path(str(arguments.output)))
    except (OSError, ValueError) as exc:
        return EXIT_INPUT, _failure(
            "schema",
            Diagnostic(
                code="ACC_SCHEMA_EXPORT_FAILED",
                severity="error",
                message=str(exc),
                path=None,
                pointer=None,
            ),
        )
    return EXIT_SUCCESS, _success(
        "schema",
        {"files": [str(path.resolve()) for path in written]},
    )


def _validate_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    report = validate_project(Path(str(arguments.path)))
    if not report.ok or report.project is None:
        diagnostics = report.diagnostics or [
            Diagnostic(
                code="ACC_PROJECT_INVALID",
                severity="error",
                message="ACC project could not be loaded.",
                path="project.yaml",
                pointer=None,
            )
        ]
        return EXIT_INPUT, ResultEnvelope(
            ok=False,
            command="validate",
            result=None,
            diagnostics=diagnostics,
        )
    return EXIT_SUCCESS, _success(
        "validate",
        {
            "project_id": report.project.project.id,
            "counts": {
                "operations": len(report.operations),
                "capabilities": len(report.capabilities),
                "policies": len(report.policies),
                "evals": len(report.evals),
            },
        },
    )


def _render(envelope: ResultEnvelope, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
        return
    if envelope.ok:
        print(f"{envelope.command}: ok")
        if envelope.result:
            print(json.dumps(envelope.result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        for diagnostic in envelope.diagnostics:
            print(f"{diagnostic.code}: {diagnostic.message}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse, execute, and render one ACC command."""

    arguments_list = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in arguments_list
    command = next((item for item in arguments_list if not item.startswith("-")), "cli")
    parser = _parser()
    try:
        arguments = parser.parse_args(arguments_list)
    except CliUsageError as exc:
        envelope = _failure(
            command,
            Diagnostic(
                code="ACC_CLI_USAGE",
                severity="error",
                message=str(exc),
                path=None,
                pointer=None,
            ),
        )
        _render(envelope, json_output=json_output)
        return EXIT_USAGE

    handler = cast(CommandHandler, arguments.handler)
    exit_code, envelope = handler(arguments)
    _render(envelope, json_output=bool(arguments.json_output))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
