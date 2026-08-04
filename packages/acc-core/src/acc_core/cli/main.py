"""The stable ``acc`` command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Never, cast

import yaml

from acc_core.compiler import compile_project
from acc_core.compiler.diff import semantic_diff
from acc_core.coverage import analyze_coverage
from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.evidence import EvidenceFreezeError, freeze_operation_evidence
from acc_core.packaging import CapabilityPackError, build_pack
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

    compile_parser = subparsers.add_parser("compile", help="compile an ACC project")
    compile_parser.add_argument("path", nargs="?", default=".")
    compile_parser.add_argument("--check", action="store_true")
    compile_parser.add_argument("--output", default="build/ir.json")
    _add_json_argument(compile_parser)
    compile_parser.set_defaults(handler=_compile_command)

    coverage_parser = subparsers.add_parser("coverage", help="analyze capability coverage")
    coverage_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(coverage_parser)
    coverage_parser.set_defaults(handler=_coverage_command)

    diff_parser = subparsers.add_parser("diff", help="compare two compiled JSON documents")
    diff_parser.add_argument("before")
    diff_parser.add_argument("after")
    _add_json_argument(diff_parser)
    diff_parser.set_defaults(handler=_diff_command)

    freeze_parser = subparsers.add_parser("freeze", help="freeze operation evidence digests")
    freeze_parser.add_argument("operation_id")
    freeze_parser.add_argument("--project", default=".")
    _add_json_argument(freeze_parser)
    freeze_parser.set_defaults(handler=_freeze_command)

    pack_parser = subparsers.add_parser("pack", help="build a deterministic capability pack")
    pack_parser.add_argument("path", nargs="?", default=".")
    pack_parser.add_argument("--output")
    _add_json_argument(pack_parser)
    pack_parser.set_defaults(handler=_pack_command)
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


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _atomic_write(path: Path, contents: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"output path cannot be a symbolic link: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


def _project_output_path(project_root: Path, value: str, *, suffix: str) -> Path:
    output = Path(value)
    if not output.is_absolute():
        output = project_root / output
    resolved_root = project_root.resolve(strict=True)
    resolved_output = output.resolve(strict=False)
    if not resolved_output.is_relative_to(resolved_root) or resolved_output == resolved_root:
        raise ValueError("generated output must stay inside the ACC project directory")
    if resolved_output.suffix.lower() != suffix:
        raise ValueError(f"generated output must use the {suffix} suffix")
    protected = {resolved_root / "project.yaml"}
    protected.update(
        resolved_root / name
        for name in ("capabilities", "evals", "evidence", "operations", "policies")
    )
    if any(resolved_output == path or resolved_output.is_relative_to(path) for path in protected):
        raise ValueError("generated output cannot overwrite ACC project contracts")
    return resolved_output


def _compilation_failure(command: str, diagnostics: list[Diagnostic]) -> ResultEnvelope:
    return ResultEnvelope(
        ok=False,
        command=command,
        result=None,
        diagnostics=diagnostics,
    )


def _compiled_project_identity(ir: dict[str, Any]) -> tuple[str, str]:
    project_document = ir.get("project")
    if not isinstance(project_document, dict):
        return "capability", "0.0.0"
    identity = project_document.get("project")
    if not isinstance(identity, dict):
        return "capability", "0.0.0"
    project_id = identity.get("id")
    project_version = identity.get("version")
    return (
        project_id if isinstance(project_id, str) else "capability",
        project_version if isinstance(project_version, str) else "0.0.0",
    )


def _compile_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    project_root = Path(str(arguments.path)).resolve()
    report = compile_project(project_root)
    if not report.ok or report.ir is None:
        return EXIT_COMPILE, _compilation_failure("compile", report.diagnostics)
    contents = _canonical_json(report.ir)
    digest = hashlib.sha256(contents).hexdigest()
    project_id, _ = _compiled_project_identity(cast(dict[str, Any], report.ir))
    result: dict[str, Any] = {"project_id": project_id, "sha256": digest, "path": None}
    if not bool(arguments.check):
        try:
            output = _project_output_path(project_root, str(arguments.output), suffix=".json")
            _atomic_write(output, contents)
        except (OSError, ValueError) as exc:
            return EXIT_COMPILE, _failure(
                "compile",
                Diagnostic(
                    code="ACC_COMPILE_OUTPUT_FAILED",
                    severity="error",
                    message=str(exc),
                    path=None,
                    pointer=None,
                ),
            )
        result["path"] = str(output.resolve())
    return EXIT_SUCCESS, _success("compile", result)


def _coverage_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    report = validate_project(Path(str(arguments.path)))
    if not report.ok or report.project is None:
        return EXIT_INPUT, _compilation_failure("coverage", report.diagnostics)
    return EXIT_SUCCESS, _success("coverage", analyze_coverage(report))


def _read_json_document(path_value: str, *, max_bytes: int = 1_048_576) -> object:
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"diff input must be a regular non-symlink file: {path}")
    if path.stat(follow_symlinks=False).st_size > max_bytes:
        raise ValueError(f"diff input exceeds {max_bytes} bytes: {path}")
    contents = path.read_bytes()
    if len(contents) > max_bytes:
        raise ValueError(f"diff input exceeds {max_bytes} bytes: {path}")
    return json.loads(
        contents.decode("utf-8"),
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {constant}")
        ),
    )


def _diff_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    try:
        before = _read_json_document(str(arguments.before))
        after = _read_json_document(str(arguments.after))
        result = semantic_diff(before, after)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return EXIT_INPUT, _failure(
            "diff",
            Diagnostic(
                code="ACC_DIFF_INPUT_INVALID",
                severity="error",
                message=str(exc),
                path=None,
                pointer=None,
            ),
        )
    return EXIT_SUCCESS, _success("diff", result)


def _freeze_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    try:
        result = freeze_operation_evidence(
            Path(str(arguments.project)),
            str(arguments.operation_id),
            write=True,
        )
    except (EvidenceFreezeError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "ACC_EVIDENCE_FREEZE_ERROR")
        return EXIT_INPUT, _failure(
            "freeze",
            Diagnostic(
                code=str(code),
                severity="error",
                message=str(exc),
                path=getattr(exc, "path", None),
                pointer=None,
            ),
        )
    evidence = result.get("evidence")
    result["updated"] = len(evidence) if isinstance(evidence, list) else 0
    return EXIT_SUCCESS, _success("freeze", result)


def _pack_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    project_root = Path(str(arguments.path)).resolve()
    report = compile_project(project_root)
    if not report.ok or report.ir is None:
        return EXIT_COMPILE, _compilation_failure("pack", report.diagnostics)
    project_id, project_version = _compiled_project_identity(cast(dict[str, Any], report.ir))
    try:
        output_value = arguments.output or f"{project_id}-{project_version}.accpkg"
        output = _project_output_path(project_root, str(output_value), suffix=".accpkg")
        built = build_pack(project_root, output, compiled_ir=report.ir)
    except (CapabilityPackError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "ACC_PACK_ERROR")
        return EXIT_RUNTIME, _failure(
            "pack",
            Diagnostic(
                code=str(code),
                severity="error",
                message=str(exc),
                path=getattr(exc, "path", None),
                pointer=None,
            ),
        )
    return EXIT_SUCCESS, _success(
        "pack",
        {
            "path": str(built.path.resolve()),
            "sha256": built.sha256,
            "project_id": built.manifest.project_id,
            "project_version": built.manifest.project_version,
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
