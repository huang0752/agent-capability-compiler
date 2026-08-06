"""The stable ``acc`` command-line interface."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Never, cast

import yaml
from pydantic import JsonValue

from acc_core.compiler import compile_project
from acc_core.compiler.diff import semantic_diff
from acc_core.coverage import analyze_coverage
from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.evals import ContractEvalRunner
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

    run_parser = subparsers.add_parser("run", help="serve a capability pack over MCP stdio")
    run_parser.add_argument("pack")
    run_parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="grant one runtime scope (repeatable)",
    )
    run_parser.add_argument(
        "--tenant-id",
        help="runtime tenant context (defaults to ACC_TENANT_ID)",
    )
    _add_json_argument(run_parser)
    run_parser.set_defaults(handler=_run_command)

    adapter_parser = subparsers.add_parser("adapter", help="manage out-of-process adapters")
    adapter_subparsers = adapter_parser.add_subparsers(
        dest="adapter_command",
        required=True,
    )
    adapter_init_parser = adapter_subparsers.add_parser(
        "init",
        help="initialize a read-only adapter project",
    )
    adapter_init_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(adapter_init_parser)
    adapter_init_parser.set_defaults(handler=_adapter_init_command)

    test_parser = subparsers.add_parser("test", help="run ACC evaluation suites")
    test_subparsers = test_parser.add_subparsers(dest="test_suite", required=True)
    for suite in ("contract", "runtime", "e2e"):
        suite_parser = test_subparsers.add_parser(suite, help=f"run {suite} evaluations")
        suite_parser.add_argument("path", nargs="?", default=".")
        _add_json_argument(suite_parser)
        suite_parser.set_defaults(handler=_test_command)
    return parser


def _success(
    command: str,
    result: dict[str, Any],
    diagnostics: list[Diagnostic] | None = None,
) -> ResultEnvelope:
    return ResultEnvelope(
        ok=True,
        command=command,
        result=result,
        diagnostics=[] if diagnostics is None else diagnostics,
    )


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
        if item.severity == "error"
        and (item.path == "project.yaml" or item.code.startswith("ACC_IO_"))
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
        warnings = [item for item in report.diagnostics if item.severity != "error"]
        return EXIT_SUCCESS, _success("doctor", {"checks": checks}, warnings)
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
        report.diagnostics,
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
    return EXIT_SUCCESS, _success("compile", result, report.diagnostics)


def _coverage_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    report = validate_project(Path(str(arguments.path)))
    if not report.ok or report.project is None:
        return EXIT_INPUT, _compilation_failure("coverage", report.diagnostics)
    return EXIT_SUCCESS, _success("coverage", analyze_coverage(report), report.diagnostics)


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
        report.diagnostics,
    )


def _runtime_scopes(command_line_scopes: Sequence[str]) -> frozenset[str]:
    configured = os.environ.get("ACC_GRANTED_SCOPES", "")
    environment_scopes = configured.replace(",", " ").split()
    return frozenset([*environment_scopes, *command_line_scopes])


def _adapter_module_name(name: str) -> str:
    module = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "acc_adapter"
    if module[0].isdigit():
        module = f"adapter_{module}"
    return module


def _adapter_init_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    target = Path(str(arguments.path)).expanduser().resolve()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        return EXIT_INPUT, _failure(
            "adapter init",
            Diagnostic(
                code="ACC_ADAPTER_EXISTS",
                severity="error",
                message="Adapter project directory already contains files.",
                path=None,
                pointer=None,
            ),
        )
    target.mkdir(parents=True, exist_ok=True)
    module = _adapter_module_name(target.name)
    source = target / "src" / module
    source.mkdir(parents=True)
    (source / "__init__.py").write_text('"""Generated ACC adapter."""\n', encoding="utf-8")
    (source / "main.py").write_text(
        '"""Read-only ACC adapter entrypoint."""\n\n'
        "from acc_adapter_sdk import AdapterServer\n\n"
        'server = AdapterServer.from_contract_file("contract.yaml")\n'
        "app = server.app\n",
        encoding="utf-8",
    )
    (target / "contract.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "id": target.name,
                "version": "0.1.0",
                "base_path": "/adapter",
                "operations": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (target / "pyproject.toml").write_text(
        "[project]\n"
        f'name = "{target.name}"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12,<3.13"\n'
        'dependencies = ["acc-adapter-sdk==0.1.0"]\n\n'
        "[build-system]\n"
        'requires = ["hatchling>=1.27"]\n'
        'build-backend = "hatchling.build"\n',
        encoding="utf-8",
    )
    return EXIT_SUCCESS, _success(
        "adapter init",
        {"path": str(target), "module": module},
    )


def _test_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    suite = str(arguments.test_suite)
    command = f"test {suite}"
    compilation = compile_project(Path(str(arguments.path)).resolve())
    if not compilation.ok or compilation.ir is None:
        return EXIT_TEST, _compilation_failure(command, compilation.diagnostics)
    if suite == "contract":
        report = ContractEvalRunner().run(compilation.ir)
    else:
        try:
            import anyio

            from acc_runtime.errors import RuntimeError as AccRuntimeError

            report = anyio.run(
                _run_runtime_eval_report,
                compilation.ir,
                Path(str(arguments.path)).resolve(),
                suite == "e2e",
            )
        except (AccRuntimeError, CapabilityPackError, OSError, ValueError) as exc:
            return EXIT_TEST, _failure(
                command,
                Diagnostic(
                    code=str(getattr(exc, "code", "ACC_TEST_RUNTIME_FAILED")),
                    severity="error",
                    message="The runtime evaluation suite could not start.",
                    path=None,
                    pointer=None,
                ),
            )
    if report.ok:
        return EXIT_SUCCESS, _success(command, report.to_dict())
    diagnostics: list[Diagnostic] = [
        Diagnostic(
            code=item.code,
            severity="error",
            message=item.message,
            path=None,
            pointer=None,
        )
        for item in report.diagnostics
    ]
    for case in report.cases:
        diagnostics.extend(
            Diagnostic(
                code=item.code,
                severity="error",
                message=item.message,
                path=f"evals/{case.case_id}",
                pointer=None,
            )
            for item in case.diagnostics
        )
    return EXIT_TEST, ResultEnvelope(
        ok=False,
        command=command,
        result=None,
        diagnostics=diagnostics,
    )


async def _run_runtime_eval_report(
    compiled_ir: dict[str, Any],
    project_root: Path,
    through_mcp: bool,
) -> Any:
    """Compose Eval with Runtime lazily so ``acc-core`` has no package cycle."""

    from acc_core.evals import AsyncCapabilityCaller, RuntimeEvalRunner
    from acc_runtime import GenericRuntime
    from acc_runtime.context import PrincipalContext
    from acc_runtime.loader import load_pack
    from acc_runtime.mcp import CapabilityMcpServer
    from acc_runtime.runtime import ContextOperationProvider

    class EvalCallRecorder:
        def __init__(self) -> None:
            self._calls: list[dict[str, object]] = []

        def snapshot(self) -> tuple[dict[str, object], ...]:
            return tuple(copy.deepcopy(self._calls))

        def reset(self) -> None:
            self._calls.clear()

        def bind(self, delegate: ContextOperationProvider) -> ContextOperationProvider:
            recorder = self

            class BoundRecordingProvider:
                async def call(
                    self,
                    operation: Mapping[str, object],
                    arguments: Mapping[str, JsonValue],
                    principal_context: PrincipalContext,
                ) -> JsonValue:
                    operation_id = operation.get("id")
                    if not isinstance(operation_id, str) or not operation_id:
                        raise ValueError("recorded operation requires a stable id")
                    recorder._calls.append(
                        {
                            "operation": operation_id,
                            "arguments": copy.deepcopy(dict(arguments)),
                        }
                    )
                    return await delegate.call(
                        operation,
                        arguments,
                        principal_context=principal_context,
                    )

            return BoundRecordingProvider()

    with tempfile.TemporaryDirectory(prefix="acc-eval-") as temporary_directory:
        pack_path = Path(temporary_directory) / "eval.accpkg"
        build_pack(project_root, pack_path, compiled_ir=compiled_ir)
        loaded_pack = load_pack(pack_path)
        runtime_ir = cast(dict[str, Any], loaded_pack.ir)
        recorder = EvalCallRecorder()
        context = _EvalRuntimeContext(
            granted_scopes=_runtime_scopes(()),
            tenant_id=os.environ.get("ACC_TENANT_ID"),
        )

        def create_runtime() -> GenericRuntime:
            granted_scopes, tenant_id = context.take()
            runtime = GenericRuntime.from_pack(
                pack_path,
                environment=os.environ,
                granted_scopes=granted_scopes,
                tenant_id=tenant_id,
            )
            runtime.provider = recorder.bind(cast(ContextOperationProvider, runtime.provider))
            return runtime

        if through_mcp:

            class McpCaller:
                async def call(
                    self,
                    capability_id: str,
                    input_data: Mapping[str, JsonValue],
                ) -> JsonValue:
                    runtime = create_runtime()
                    try:
                        result = await CapabilityMcpServer(runtime).call_tool(
                            capability_id,
                            input_data,
                        )
                        structured = result.structuredContent or {}
                        if result.isError:
                            error = structured.get("error")
                            if not isinstance(error, dict):
                                raise _McpEvalFailure("ACC_RUNTIME_PROTOCOL_ERROR", 500)
                            code = error.get("code")
                            status = error.get("status")
                            raise _McpEvalFailure(
                                code if isinstance(code, str) else "ACC_RUNTIME_PROTOCOL_ERROR",
                                status if isinstance(status, int) else 500,
                            )
                        return cast(JsonValue, structured.get("result"))
                    finally:
                        await runtime.aclose()

            caller: AsyncCapabilityCaller = McpCaller()
        else:

            class RuntimeCaller:
                async def call(
                    self,
                    capability_id: str,
                    input_data: Mapping[str, JsonValue],
                ) -> JsonValue:
                    runtime = create_runtime()
                    try:
                        return await runtime.call(capability_id, input_data)
                    finally:
                        await runtime.aclose()

            caller = RuntimeCaller()

        return await RuntimeEvalRunner(
            caller,
            fixture_loader=context,
            call_recorder=recorder,
        ).run(runtime_ir)


class _EvalRuntimeContext:
    """Strict, non-secret runtime context fixture for one eval case."""

    def __init__(self, *, granted_scopes: frozenset[str], tenant_id: str | None) -> None:
        self._default_scopes = granted_scopes
        self._default_tenant = tenant_id
        self._next_scopes = granted_scopes
        self._next_tenant = tenant_id

    def take(self) -> tuple[frozenset[str], str | None]:
        """Consume one case override so it cannot leak into a later eval."""

        result = self._next_scopes, self._next_tenant
        self._next_scopes = self._default_scopes
        self._next_tenant = self._default_tenant
        return result

    async def load(self, fixtures: Mapping[str, JsonValue]) -> None:
        if set(fixtures) != {"runtime_context"}:
            raise ValueError("CLI eval fixtures permit only runtime_context")
        raw_context = fixtures.get("runtime_context")
        if not isinstance(raw_context, Mapping) or set(raw_context) - {
            "granted_scopes",
            "tenant_id",
        }:
            raise ValueError("runtime_context contains unsupported fields")

        raw_scopes = raw_context.get("granted_scopes")
        if not isinstance(raw_scopes, list) or not all(
            isinstance(scope, str) and scope for scope in raw_scopes
        ):
            raise ValueError("runtime_context.granted_scopes must be a string array")
        raw_tenant = raw_context.get("tenant_id")
        if raw_tenant is not None and not isinstance(raw_tenant, str):
            raise ValueError("runtime_context.tenant_id must be a string or null")

        self._next_scopes = frozenset(cast(list[str], raw_scopes))
        self._next_tenant = raw_tenant


class _McpEvalFailure(Exception):
    """Internal structured MCP failure consumed by RuntimeEvalRunner."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__("MCP tool returned a structured runtime error")
        self.code = code
        self.status = status


def _run_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    """Load one verified pack and either inspect or serve its capabilities."""

    try:
        import anyio

        from acc_core.models import Project
        from acc_runtime import GenericRuntime
        from acc_runtime.errors import RuntimeError as AccRuntimeError
        from acc_runtime.loader import load_pack
        from acc_runtime.mcp import CapabilityMcpServer
        from acc_runtime.runtime import RuntimeConfigurationError

        pack_path = Path(str(arguments.pack))
        loaded_pack = load_pack(pack_path)
        project = Project.model_validate(loaded_pack.ir.get("project"))
        if project.runtime.transport != ["stdio"]:
            raise RuntimeConfigurationError(
                "Streamable HTTP packs must be served by the ACC Gateway.",
                details={"reason": "streamable_http_requires_gateway"},
            )
        tenant_id = arguments.tenant_id or os.environ.get("ACC_TENANT_ID")
        runtime = GenericRuntime.from_pack(
            pack_path,
            environment=os.environ,
            granted_scopes=_runtime_scopes(cast(Sequence[str], arguments.scope)),
            tenant_id=tenant_id,
        )

        async def inspect_or_serve_stdio() -> list[dict[str, object]]:
            try:
                tools = runtime.tools()
                adapter = CapabilityMcpServer(runtime)
                if not bool(arguments.json_output):
                    await adapter.run_stdio()
                return tools
            finally:
                await runtime.aclose()

        tools = anyio.run(inspect_or_serve_stdio)
        return EXIT_SUCCESS, _success(
            "run",
            {
                "pack": str(Path(str(arguments.pack)).resolve()),
                "transport": "stdio",
                "tools": tools,
            },
        )
    except (AccRuntimeError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "ACC_RUNTIME_START_FAILED")
        message = (
            "Streamable HTTP packs require the ACC Gateway."
            if isinstance(exc, RuntimeConfigurationError)
            and exc.details.get("reason") == "streamable_http_requires_gateway"
            else "ACC runtime could not start."
        )
        return EXIT_RUNTIME, _failure(
            "run",
            Diagnostic(
                code=str(code),
                severity="error",
                message=message,
                path=None,
                pointer=None,
            ),
        )


def _render(envelope: ResultEnvelope, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
        return
    if envelope.ok:
        print(f"{envelope.command}: ok")
        if envelope.result:
            print(json.dumps(envelope.result, indent=2, ensure_ascii=False, sort_keys=True))
        for diagnostic in envelope.diagnostics:
            print(f"{diagnostic.code}: {diagnostic.message}", file=sys.stderr)
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
    if arguments.command != "run" or bool(arguments.json_output):
        _render(envelope, json_output=bool(arguments.json_output))
    elif not envelope.ok:
        _render(envelope, json_output=False)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
