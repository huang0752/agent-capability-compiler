"""The stable ``acc`` command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Never, Protocol, cast

import yaml
from pydantic import JsonValue, ValidationError

from acc_core.cli.domains import (
    action_candidates,
    analyze_domain_changes,
    check_domain_review,
    show_domain,
    status_domains,
)
from acc_core.cli.intents import audit_project_intents, build_intent_brief
from acc_core.cli.scope_diagnostics import analyze_run_scope_configuration
from acc_core.cli.usage import handle_usage_command
from acc_core.compiler import compile_project
from acc_core.compiler.diff import semantic_diff
from acc_core.coverage import (
    LiveObservation,
    LiveObservationArtifactError,
    analyze_coverage,
    artifact_observations,
    load_live_observation_artifact,
)
from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.evals import ContractEvalRunner
from acc_core.evidence import EvidenceFreezeError, freeze_operation_evidence
from acc_core.io import ProjectIOError, load_project_object
from acc_core.packaging import CapabilityPackError, build_pack
from acc_core.schemas import export_schemas
from acc_core.scope import ScopeInventory
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


class _ProjectEvalFixtureAdapter(Protocol):
    """Explicit trusted injection boundary for project-specific test fixtures.

    The CLI never discovers or imports an adapter from a scanned project. A trusted
    host may inject an already-constructed adapter when composing ACC in-process.
    """

    @property
    def fixture_keys(self) -> frozenset[str]:
        """Return the exact fixture namespaces handled by this adapter."""

    async def load(self, fixtures: Mapping[str, JsonValue]) -> None:
        """Install one case's declared project fixtures."""


@dataclass(frozen=True, slots=True)
class _NotProvisionedEvalCase:
    case_id: str
    capability_id: str
    fixture_key: str | None

    def to_dict(self) -> dict[str, object]:
        if self.fixture_key is None:
            status = "not_run_due_to_suite_provisioning"
            message = "Eval case was not run because another case requires an unavailable adapter."
        else:
            status = "not_provisioned"
            message = "Eval case requires a project fixture adapter that was not provided."
        return {
            "id": self.case_id,
            "capability": self.capability_id,
            "ok": False,
            "status": status,
            "calls": 0,
            "diagnostics": [
                {
                    "code": "ACC_TEST_RUNNER_NOT_PROVISIONED",
                    "message": message,
                }
            ],
        }


@dataclass(frozen=True, slots=True)
class _NotProvisionedEvalReport:
    suite: Literal["runtime", "e2e"]
    cases: tuple[_NotProvisionedEvalCase, ...]

    @property
    def ok(self) -> bool:
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "runtime",
            "suite": self.suite,
            "ok": False,
            "status": "not_provisioned",
            "summary": {
                "total": len(self.cases),
                "passed": 0,
                "failed": 0,
                "not_provisioned": sum(case.fixture_key is not None for case in self.cases),
                "not_run": sum(case.fixture_key is None for case in self.cases),
                "calls": 0,
            },
            "diagnostics": [],
            "cases": [case.to_dict() for case in self.cases],
        }


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
    coverage_parser.add_argument(
        "--live-observations",
        help="canonical machine artifact emitted by `acc test live --observations-output`",
    )
    coverage_parser.add_argument(
        "--live-pack",
        help="verified Pack identified by --live-observations (required with that option)",
    )
    _add_json_argument(coverage_parser)
    coverage_parser.set_defaults(handler=_coverage_command)

    intents_parser = subparsers.add_parser(
        "intents", help="prepare and audit evidence-driven business intent plans"
    )
    intents_subparsers = intents_parser.add_subparsers(dest="intents_command", required=True)
    intents_brief_parser = intents_subparsers.add_parser(
        "brief", help="emit bounded facts for the Coding Agent planner"
    )
    intents_brief_parser.add_argument("path", nargs="?", default=".")
    intents_brief_parser.add_argument("--domain")
    _add_json_argument(intents_brief_parser)
    intents_brief_parser.set_defaults(handler=_intents_command)
    intents_audit_parser = intents_subparsers.add_parser(
        "audit", help="audit intent-plan.yaml against the current project"
    )
    intents_audit_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(intents_audit_parser)
    intents_audit_parser.set_defaults(handler=_intents_command)

    domains_parser = subparsers.add_parser("domains", help="inspect deterministic domain workflow")
    domains_subparsers = domains_parser.add_subparsers(dest="domains_command", required=True)
    domains_status_parser = domains_subparsers.add_parser("status", help="show domain readiness")
    domains_status_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(domains_status_parser)
    domains_status_parser.set_defaults(handler=_domains_command)
    domains_actions_parser = domains_subparsers.add_parser(
        "actions", help="show the complete typed Action candidate report"
    )
    domains_actions_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(domains_actions_parser)
    domains_actions_parser.set_defaults(handler=_domains_command)
    domains_show_parser = domains_subparsers.add_parser("show", help="show one domain")
    domains_show_parser.add_argument("domain_id")
    domains_show_parser.add_argument("--project", default=".")
    _add_json_argument(domains_show_parser)
    domains_show_parser.set_defaults(handler=_domains_command)
    domains_review_parser = domains_subparsers.add_parser(
        "review", help="check a structured domain decision"
    )
    domains_review_parser.add_argument("review_path")
    domains_review_parser.add_argument("--project", default=".")
    domains_review_parser.add_argument("--check", action="store_true", required=True)
    _add_json_argument(domains_review_parser)
    domains_review_parser.set_defaults(handler=_domains_command)
    domains_impact_parser = domains_subparsers.add_parser(
        "impact", help="analyze bounded Evidence changes"
    )
    domains_impact_parser.add_argument("path", nargs="?", default=".")
    domains_impact_parser.add_argument("--changed-evidence", required=True)
    domains_impact_parser.add_argument("--write", action="store_true")
    _add_json_argument(domains_impact_parser)
    domains_impact_parser.set_defaults(handler=_domains_command)

    usage_parser = subparsers.add_parser("usage", help="inspect Agent Usage workflow")
    usage_subparsers = usage_parser.add_subparsers(dest="usage_command", required=True)
    usage_init_parser = usage_subparsers.add_parser(
        "init", help="initialize an independent Agent Usage project"
    )
    usage_init_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(usage_init_parser)
    usage_init_parser.set_defaults(handler=handle_usage_command)
    usage_status_parser = usage_subparsers.add_parser(
        "status", help="show deterministic Agent Usage domain readiness"
    )
    usage_status_parser.add_argument("path", nargs="?", default=".")
    _add_json_argument(usage_status_parser)
    usage_status_parser.set_defaults(handler=handle_usage_command)
    usage_scan_parser = usage_subparsers.add_parser(
        "scan", help="check bounded domain scan prerequisites"
    )
    usage_scan_parser.add_argument("--domain", required=True)
    usage_scan_parser.add_argument("--project", default=".")
    usage_scan_parser.add_argument("--check", action="store_true", required=True)
    _add_json_argument(usage_scan_parser)
    usage_scan_parser.set_defaults(handler=handle_usage_command)
    usage_review_parser = usage_subparsers.add_parser(
        "review", help="check one typed Agent Usage domain review"
    )
    usage_review_parser.add_argument("--domain", required=True)
    usage_review_parser.add_argument("--project", default=".")
    usage_review_parser.add_argument("--check", action="store_true", required=True)
    _add_json_argument(usage_review_parser)
    usage_review_parser.set_defaults(handler=handle_usage_command)
    usage_build_parser = usage_subparsers.add_parser(
        "build", help="build one verified released Agent Usage package"
    )
    usage_build_parser.add_argument("--domain", required=True)
    usage_build_parser.add_argument("--project", default=".")
    usage_build_parser.add_argument("--output", required=True)
    usage_build_parser.add_argument("--verification-artifact")
    usage_build_parser.add_argument("--verification-trust-store")
    usage_build_parser.add_argument("--accepted-pack")
    usage_build_parser.add_argument("--accepted-tools")
    usage_build_parser.add_argument("--accepted-test-report")
    usage_build_parser.add_argument("--package-signing-secret-env")
    _add_json_argument(usage_build_parser)
    usage_build_parser.set_defaults(handler=handle_usage_command)
    usage_test_parser = usage_subparsers.add_parser(
        "test", help="check Agent Usage test readiness without inferring live evidence"
    )
    usage_test_parser.add_argument("--domain", required=True)
    usage_test_parser.add_argument("--project", default=".")
    usage_test_parser.add_argument("--check", action="store_true", required=True)
    _add_json_argument(usage_test_parser)
    usage_test_parser.set_defaults(handler=handle_usage_command)
    usage_impact_parser = usage_subparsers.add_parser(
        "impact", help="analyze one bounded Agent Usage change set"
    )
    usage_impact_parser.add_argument("change_set")
    usage_impact_parser.add_argument("--project", default=".")
    usage_impact_parser.add_argument("--output")
    _add_json_argument(usage_impact_parser)
    usage_impact_parser.set_defaults(handler=handle_usage_command)
    usage_release_parser = usage_subparsers.add_parser(
        "release", help="check every required Agent Usage release gate"
    )
    usage_release_parser.add_argument("--domain", required=True)
    usage_release_parser.add_argument("--project", default=".")
    usage_release_parser.add_argument("--check", action="store_true", required=True)
    usage_release_parser.add_argument("--verification-artifact")
    usage_release_parser.add_argument("--verification-trust-store")
    usage_release_parser.add_argument("--accepted-pack")
    usage_release_parser.add_argument("--accepted-tools")
    usage_release_parser.add_argument("--accepted-test-report")
    _add_json_argument(usage_release_parser)
    usage_release_parser.set_defaults(handler=handle_usage_command)
    usage_export_parser = usage_subparsers.add_parser(
        "export", help="export a verified platform-neutral Agent Usage guide"
    )
    usage_export_parser.add_argument("--adapter", required=True)
    usage_export_parser.add_argument("--domain", required=True)
    usage_export_parser.add_argument("--package", required=True)
    usage_export_parser.add_argument("--project", default=".")
    usage_export_parser.add_argument("--output", required=True)
    _add_json_argument(usage_export_parser)
    usage_export_parser.set_defaults(handler=handle_usage_command)

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

    run_parser = subparsers.add_parser("run", help="serve a capability pack over its MCP transport")
    run_parser.add_argument("pack")
    run_scope_group = run_parser.add_mutually_exclusive_group()
    run_scope_group.add_argument(
        "--scope",
        action="append",
        default=[],
        help="grant one runtime scope (repeatable)",
    )
    run_scope_group.add_argument(
        "--scope-ceiling-from-pack",
        action="store_true",
        help="explicitly use every Pack-declared scope as the deployment ceiling",
    )
    run_parser.add_argument(
        "--strict-scope",
        action="store_true",
        help="refuse startup when any capability has no callable scope path",
    )
    run_parser.add_argument(
        "--tenant-id",
        help="runtime tenant context (defaults to ACC_TENANT_ID)",
    )
    run_parser.add_argument("--host", default="127.0.0.1", help="Gateway listen IP")
    run_parser.add_argument("--port", type=int, default=8000, help="Gateway listen port")
    run_parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="exact Gateway Host allowlist entry (repeatable)",
    )
    run_parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="exact Gateway Origin allowlist entry (repeatable)",
    )
    run_parser.add_argument("--session-ttl", type=int, default=3600)
    run_parser.add_argument("--max-sessions", type=int, default=1000)
    run_parser.add_argument("--mcp-idle-timeout", type=float, default=60.0)
    run_parser.add_argument("--body-limit", type=int, default=4 * 1024 * 1024)
    run_parser.add_argument("--workers", type=int, default=1)
    run_parser.add_argument("--tls-certfile")
    run_parser.add_argument("--tls-keyfile")
    run_parser.add_argument(
        "--development-actions",
        action="store_true",
        help="explicitly enable non-durable Action dependencies for development/tests only",
    )
    run_parser.add_argument(
        "--production-actions",
        action="store_true",
        help="enable the explicit durable single-node Action deployment profile",
    )
    run_parser.add_argument(
        "--local-development-action-guards",
        action="store_true",
        help=(
            "enable process-local Action resource guards; requires --development-actions "
            "and never supplies source atomicity"
        ),
    )
    run_parser.add_argument(
        "--development-action-operator-approval",
        action="store_true",
        help="enable the loopback-only trusted Action approval endpoint for development",
    )
    run_parser.add_argument(
        "--action-operator-secret-ref",
        help="environment SecretRef for the independent development operator secret",
    )
    run_parser.add_argument(
        "--production-action-operator-approval",
        action="store_true",
        help="enable the loopback-only durable production Action approval endpoint",
    )
    run_parser.add_argument(
        "--production-action-operator-secret-ref",
        help="environment SecretRef for the independent production operator secret",
    )
    run_parser.add_argument(
        "--action-capability",
        action="append",
        default=[],
        help="allow one Action capability in development mode (repeatable)",
    )
    run_parser.add_argument(
        "--development-action-store",
        choices=("memory", "sqlite"),
        default="memory",
        help="development Action Store backend (default: memory)",
    )
    run_parser.add_argument("--action-store-path", help="SQLite Action Store database path")
    run_parser.add_argument(
        "--action-store-secret-ref",
        help="environment SecretRef for SQLite row authentication",
    )
    run_parser.add_argument(
        "--action-store-salt-ref",
        help="environment SecretRef for SQLite deployment binding salt",
    )
    run_parser.add_argument("--session-vault-path", help="SQLite Gateway session vault path")
    run_parser.add_argument(
        "--session-vault-key-ref", help="environment SecretRef for the session vault KEK"
    )
    run_parser.add_argument(
        "--session-vault-salt-ref",
        help="environment SecretRef for the session vault deployment salt",
    )
    run_parser.add_argument("--approval-db-path", help="SQLite approval authority path")
    run_parser.add_argument(
        "--approval-secret-ref", help="environment SecretRef for approval authentication"
    )
    run_parser.add_argument(
        "--approval-salt-ref", help="environment SecretRef for approval deployment binding"
    )
    run_parser.add_argument("--audit-db-path", help="SQLite Action audit path")
    run_parser.add_argument(
        "--audit-secret-ref", help="environment SecretRef for audit authentication"
    )
    run_parser.add_argument(
        "--audit-salt-ref", help="environment SecretRef for audit deployment binding"
    )
    run_parser.add_argument(
        "--action-effect",
        action="append",
        choices=("create", "update", "delete", "transition", "execute"),
        default=[],
        help="allow one Action effect in development mode (repeatable)",
    )
    run_parser.add_argument(
        "--action-max-risk",
        choices=("low", "medium", "high", "critical"),
        help="maximum Action risk accepted in development mode",
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
    live_parser = test_subparsers.add_parser("live", help="attach tests to a live Gateway")
    live_parser.add_argument("pack")
    live_parser.add_argument("--gateway-url", required=True)
    live_parser.add_argument("--profile", required=True)
    live_parser.add_argument("--allow-source-connect", action="store_true")
    live_parser.add_argument(
        "--observations-output",
        help="write a canonical, Pack-bound live-observation artifact after verification",
    )
    live_parser.add_argument(
        "--allowed-gateway-host",
        action="append",
        default=[],
        help="exact non-loopback Gateway authority allowlist entry (repeatable)",
    )
    _add_json_argument(live_parser)
    live_parser.set_defaults(handler=_live_test_command)
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
    for directory in (
        "capabilities",
        "capability-quality",
        "evals",
        "evidence",
        "interaction-contracts",
        "operations",
        "policies",
        "source-contracts",
        "domain-decisions",
        "domain-change-requests",
    ):
        (target / directory).mkdir()
    template = {
        "schema_version": "2",
        "project": {"id": target.name, "version": "0.1.0"},
        "source_workspace": {"path": "../system", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "ACC_TARGET_BASE_URL",
            "auth": {"kind": "none"},
        },
        "quality": {"profile": "standard"},
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
    project_root = Path(str(arguments.path)).resolve()
    report = validate_project(project_root)
    if not report.ok or report.project is None:
        return EXIT_INPUT, _compilation_failure("coverage", report.diagnostics)
    try:
        inventory = ScopeInventory.model_validate(
            load_project_object(project_root, "scope-inventory.yaml")
        )
    except (ProjectIOError, ValidationError):
        return EXIT_INPUT, _failure(
            "coverage",
            Diagnostic(
                code="ACC_COVERAGE_SCOPE_INVENTORY_INVALID",
                severity="error",
                message="Coverage requires a valid scope-inventory.yaml.",
                path="scope-inventory.yaml",
                pointer=None,
            ),
        )
    live_observations: Sequence[LiveObservation] = ()
    artifact_path = getattr(arguments, "live_observations", None)
    if artifact_path is not None:
        live_pack_path = getattr(arguments, "live_pack", None)
        if live_pack_path is None:
            return EXIT_INPUT, _failure(
                "coverage",
                Diagnostic(
                    code="ACC_COVERAGE_LIVE_PACK_REQUIRED",
                    severity="error",
                    message="Coverage requires the verified Pack for live observations.",
                    path=None,
                    pointer=None,
                ),
            )
        compilation = compile_project(project_root)
        if not compilation.ok or compilation.ir is None or report.project is None:
            return EXIT_INPUT, _compilation_failure("coverage", compilation.diagnostics)
        compiled_capabilities = compilation.ir.get("capabilities")
        if not isinstance(compiled_capabilities, dict):
            return EXIT_INPUT, _compilation_failure("coverage", compilation.diagnostics)
        ir_digest = hashlib.sha256(_canonical_json(compilation.ir)).hexdigest()
        try:
            from acc_runtime.errors import RuntimeError as AccRuntimeError
            from acc_runtime.loader import load_pack

            loaded_pack = load_pack(Path(str(live_pack_path)).expanduser().resolve(strict=False))
            ir_record = next(
                (
                    item
                    for item in loaded_pack.verification.files
                    if item.path == "compiled/ir.json"
                ),
                None,
            )
            if ir_record is None or ir_record.sha256 != ir_digest:
                raise LiveObservationArtifactError(
                    "ACC_COVERAGE_LIVE_OBSERVATIONS_MISMATCH",
                    "The verified live Pack does not match the current Project IR.",
                )
            artifact = load_live_observation_artifact(
                Path(str(artifact_path)).expanduser().resolve(strict=False),
                project_id=report.project.project.id,
                project_version=report.project.project.version,
                pack_sha256=loaded_pack.verification.sha256,
                compiled_ir_sha256=ir_digest,
                capability_ids=compiled_capabilities,
            )
            live_observations = artifact_observations(artifact)
        except AccRuntimeError:
            return EXIT_INPUT, _failure(
                "coverage",
                Diagnostic(
                    code="ACC_COVERAGE_LIVE_PACK_INVALID",
                    severity="error",
                    message="The Pack for live observations is invalid.",
                    path=None,
                    pointer=None,
                ),
            )
        except LiveObservationArtifactError as exc:
            return EXIT_INPUT, _failure(
                "coverage",
                Diagnostic(
                    code=exc.code,
                    severity="error",
                    message=str(exc),
                    path=None,
                    pointer=None,
                ),
            )
    result = analyze_coverage(
        report,
        inventory,
        live_observations=live_observations,
    ).model_dump(mode="json")
    return EXIT_SUCCESS, _success("coverage", result, report.diagnostics)


def _intents_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = f"intents {arguments.intents_command}"
    project = Path(str(arguments.path)).expanduser().resolve()
    if arguments.intents_command == "brief":
        result, diagnostics = build_intent_brief(
            project,
            domain_id=cast(str | None, getattr(arguments, "domain", None)),
        )
    else:
        result, diagnostics = audit_project_intents(project)
    if result is None or any(item.severity == "error" for item in diagnostics):
        errors = [item for item in diagnostics if item.severity == "error"]
        if not errors:
            errors = [
                Diagnostic(
                    code="ACC_INTENT_AUDIT_FAILED",
                    severity="error",
                    message="Intent planning did not produce a valid result.",
                    path=None,
                    pointer=None,
                )
            ]
        return EXIT_INPUT, ResultEnvelope(
            ok=False,
            command=command,
            result=None,
            diagnostics=errors,
        )
    return EXIT_SUCCESS, _success(command, result, diagnostics)


def _domains_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = f"domains {arguments.domains_command}"
    if arguments.domains_command == "status":
        result, diagnostics = status_domains(Path(str(arguments.path)).expanduser().resolve())
    elif arguments.domains_command == "actions":
        result, diagnostics = action_candidates(Path(str(arguments.path)).expanduser().resolve())
    elif arguments.domains_command == "show":
        result, diagnostics = show_domain(
            Path(str(arguments.project)).expanduser().resolve(), str(arguments.domain_id)
        )
    elif arguments.domains_command == "review":
        result, diagnostics = check_domain_review(
            Path(str(arguments.project)).expanduser().resolve(), str(arguments.review_path)
        )
    else:
        result, diagnostics = analyze_domain_changes(
            Path(str(arguments.path)).expanduser().resolve(),
            str(arguments.changed_evidence),
            write=bool(arguments.write),
        )
    if result is None:
        return EXIT_INPUT, ResultEnvelope(
            ok=False,
            command=command,
            result=None,
            diagnostics=diagnostics,
        )
    return EXIT_SUCCESS, _success(command, result, diagnostics)


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
                "schema_version": "2",
                "id": target.name,
                "version": "0.1.0",
                "base_path": "/adapter/v2",
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
    report: Any
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
    if isinstance(report, _NotProvisionedEvalReport):
        provisioning_diagnostics = [
            Diagnostic(
                code="ACC_TEST_RUNNER_NOT_PROVISIONED",
                severity="error",
                message=("The evaluation suite requires a project runner that was not provided."),
                path=f"evals/{case.case_id}",
                pointer=f"/fixtures/{case.fixture_key}",
            )
            for case in report.cases
            if case.fixture_key is not None
        ]
        return EXIT_TEST, ResultEnvelope(
            ok=False,
            command=command,
            result=report.to_dict(),
            diagnostics=provisioning_diagnostics,
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


def _live_test_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    """Load the optional live-test integration only for the explicit subcommand."""

    from acc_core.cli.live import run_live_command

    return run_live_command(arguments, environment=os.environ)


async def _run_runtime_eval_report(
    compiled_ir: dict[str, Any],
    project_root: Path,
    through_mcp: bool,
    project_fixture_adapter: _ProjectEvalFixtureAdapter | None = None,
) -> Any:
    """Compose Eval with Runtime lazily so ``acc-core`` has no package cycle."""

    not_provisioned = _find_not_provisioned_eval_cases(
        compiled_ir,
        project_fixture_adapter=project_fixture_adapter,
    )
    if not_provisioned:
        return _NotProvisionedEvalReport(
            suite="e2e" if through_mcp else "runtime",
            cases=not_provisioned,
        )

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
        fixture_loader = _CliEvalFixtureLoader(
            context=context,
            project_adapter=project_fixture_adapter,
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
                    async with runtime:
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

            caller: AsyncCapabilityCaller = McpCaller()
        else:

            class RuntimeCaller:
                async def call(
                    self,
                    capability_id: str,
                    input_data: Mapping[str, JsonValue],
                ) -> JsonValue:
                    runtime = create_runtime()
                    async with runtime:
                        return await runtime.call(capability_id, input_data)

            caller = RuntimeCaller()

        return await RuntimeEvalRunner(
            caller,
            fixture_loader=fixture_loader,
            call_recorder=recorder,
        ).run(runtime_ir)


def _find_not_provisioned_eval_cases(
    compiled_ir: Mapping[str, Any],
    *,
    project_fixture_adapter: _ProjectEvalFixtureAdapter | None,
) -> tuple[_NotProvisionedEvalCase, ...]:
    """Find fixture namespaces that have no explicitly injected adapter."""

    supported_keys = {"runtime_context"}
    if project_fixture_adapter is not None:
        supported_keys.update(project_fixture_adapter.fixture_keys)
    raw_evals = compiled_ir.get("evals")
    if not isinstance(raw_evals, Mapping):
        return ()

    raw_cases: list[tuple[str, str, str | None]] = []
    has_unsupported = False
    for case_id in sorted(key for key in raw_evals if isinstance(key, str)):
        raw_case = raw_evals[case_id]
        if not isinstance(raw_case, Mapping):
            continue
        raw_fixtures = raw_case.get("fixtures")
        if not isinstance(raw_fixtures, Mapping):
            raw_fixtures = {}
        unsupported = sorted(
            key for key in raw_fixtures if isinstance(key, str) and key not in supported_keys
        )
        capability = raw_case.get("capability")
        fixture_key = unsupported[0] if unsupported else None
        has_unsupported = has_unsupported or fixture_key is not None
        raw_cases.append((case_id, capability if isinstance(capability, str) else "", fixture_key))
    if not has_unsupported:
        return ()
    return tuple(
        _NotProvisionedEvalCase(
            case_id=case_id,
            capability_id=capability_id,
            fixture_key=fixture_key,
        )
        for case_id, capability_id, fixture_key in raw_cases
    )


class _CliEvalFixtureLoader:
    """Route built-in and explicitly injected fixtures without dynamic imports."""

    def __init__(
        self,
        *,
        context: _EvalRuntimeContext,
        project_adapter: _ProjectEvalFixtureAdapter | None,
    ) -> None:
        self._context = context
        self._project_adapter = project_adapter

    async def load(self, fixtures: Mapping[str, JsonValue]) -> None:
        runtime_context = {
            key: copy.deepcopy(value) for key, value in fixtures.items() if key == "runtime_context"
        }
        if runtime_context:
            await self._context.load(runtime_context)

        project_fixtures = {
            key: copy.deepcopy(value) for key, value in fixtures.items() if key != "runtime_context"
        }
        if project_fixtures:
            if self._project_adapter is None:
                raise RuntimeError("project fixture adapter was not provisioned")
            await self._project_adapter.load(project_fixtures)


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
        from acc_core.models import load_project_document
        from acc_runtime.errors import RuntimeError as AccRuntimeError
        from acc_runtime.loader import load_pack
        from acc_runtime.runtime import RuntimeConfigurationError

        pack_path = Path(str(arguments.pack))
        loaded_pack = load_pack(pack_path)
        project = load_project_document(loaded_pack.ir.get("project"))
        scope_configuration = analyze_run_scope_configuration(
            loaded_pack.ir,
            requested_scopes=(
                frozenset()
                if bool(arguments.scope_ceiling_from_pack)
                else _runtime_scopes(cast(Sequence[str], arguments.scope))
            ),
            ceiling_from_pack=bool(arguments.scope_ceiling_from_pack),
            strict=bool(arguments.strict_scope),
        )
        if scope_configuration.has_errors:
            return EXIT_RUNTIME, ResultEnvelope(
                ok=False,
                command="run",
                result=None,
                diagnostics=list(scope_configuration.diagnostics),
            )
        if not bool(arguments.json_output):
            for diagnostic in scope_configuration.diagnostics:
                print(f"{diagnostic.code}: {diagnostic.message}", file=sys.stderr)
        transport = project.runtime.transport[0]
        action_cli_requested = bool(
            getattr(arguments, "development_actions", False)
            or getattr(arguments, "production_actions", False)
            or getattr(arguments, "local_development_action_guards", False)
            or getattr(arguments, "development_action_operator_approval", False)
            or getattr(arguments, "action_operator_secret_ref", None)
            or getattr(arguments, "development_action_store", "memory") != "memory"
            or getattr(arguments, "action_store_path", None)
            or getattr(arguments, "action_store_secret_ref", None)
            or getattr(arguments, "action_store_salt_ref", None)
            or getattr(arguments, "session_vault_path", None)
            or getattr(arguments, "session_vault_key_ref", None)
            or getattr(arguments, "session_vault_salt_ref", None)
            or getattr(arguments, "approval_db_path", None)
            or getattr(arguments, "approval_secret_ref", None)
            or getattr(arguments, "approval_salt_ref", None)
            or getattr(arguments, "audit_db_path", None)
            or getattr(arguments, "audit_secret_ref", None)
            or getattr(arguments, "audit_salt_ref", None)
            or getattr(arguments, "action_capability", ())
            or getattr(arguments, "action_effect", ())
            or getattr(arguments, "action_max_risk", None)
        )
        if transport != "streamable_http" and action_cli_requested:
            raise RuntimeConfigurationError(
                "Action deployment dependencies require a streamable HTTP Gateway.",
                details={"reason": "actions_gateway_required"},
            )
        if transport == "stdio":
            tools = _run_stdio_runtime(
                arguments,
                pack_path=pack_path,
                deployment_scope_ceiling=scope_configuration.deployment_scope_ceiling,
            )
            safe_configuration: dict[str, object] = {}
        elif transport == "streamable_http":
            tools, safe_configuration = _run_streamable_http_gateway(
                arguments,
                pack_path=pack_path,
                deployment_scope_ceiling=scope_configuration.deployment_scope_ceiling,
            )
        else:  # pragma: no cover - Project restricts the transport union
            raise RuntimeConfigurationError(
                "Pack transport is unsupported.",
                details={"reason": "transport_unsupported"},
            )
        return EXIT_SUCCESS, _success(
            "run",
            {
                "pack": str(Path(str(arguments.pack)).resolve()),
                "transport": transport,
                "tools": tools,
                "scope_analysis": scope_configuration.analysis,
                **safe_configuration,
            },
            list(scope_configuration.diagnostics),
        )
    except (AccRuntimeError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "ACC_RUNTIME_START_FAILED")
        return EXIT_RUNTIME, _failure(
            "run",
            Diagnostic(
                code=str(code),
                severity="error",
                message="ACC runtime could not start.",
                path=None,
                pointer=None,
            ),
        )


def _run_stdio_runtime(
    arguments: argparse.Namespace,
    *,
    pack_path: Path,
    deployment_scope_ceiling: frozenset[str],
) -> list[dict[str, object]]:
    """Inspect or serve one current stdio Pack with deterministic cleanup."""

    import anyio

    from acc_runtime import GenericRuntime
    from acc_runtime.mcp import CapabilityMcpServer

    tenant_id = arguments.tenant_id or os.environ.get("ACC_TENANT_ID")
    runtime = GenericRuntime.from_pack(
        pack_path,
        environment=os.environ,
        granted_scopes=deployment_scope_ceiling,
        tenant_id=tenant_id,
    )

    async def inspect_or_serve() -> list[dict[str, object]]:
        async with runtime:
            tools = runtime.tools()
            adapter = CapabilityMcpServer(runtime)
            if not bool(arguments.json_output):
                await adapter.run_stdio()
            return tools

    return anyio.run(inspect_or_serve)


def _run_streamable_http_gateway(
    arguments: argparse.Namespace,
    *,
    pack_path: Path,
    deployment_scope_ceiling: frozenset[str],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Inspect or synchronously serve one single-worker HTTP Gateway."""

    import anyio
    import uvicorn
    from pydantic import ValidationError

    from acc_runtime.gateway import GatewaySettings, create_gateway_runtime
    from acc_runtime.runtime import RuntimeConfigurationError

    certfile = cast(str | None, arguments.tls_certfile)
    keyfile = cast(str | None, arguments.tls_keyfile)
    if (certfile is None) != (keyfile is None):
        raise RuntimeConfigurationError(
            "Gateway TLS certificate and key must be configured together.",
            details={"reason": "gateway_tls_pair_invalid"},
        )
    if arguments.tenant_id is not None:
        raise RuntimeConfigurationError(
            "Gateway tenant context must come from the authenticated source user.",
            details={"reason": "gateway_static_tenant_forbidden"},
        )
    try:
        settings = GatewaySettings(
            listen_host=str(arguments.host),
            listen_port=arguments.port,
            worker_count=arguments.workers,
            tls_enabled=certfile is not None,
            allowed_hosts=tuple(cast(Sequence[str], arguments.allowed_host)),
            allowed_origins=tuple(cast(Sequence[str], arguments.allowed_origin)),
            session_ttl_seconds=arguments.session_ttl,
            max_sessions=arguments.max_sessions,
        )
    except ValidationError:
        raise RuntimeConfigurationError(
            "Gateway deployment settings are invalid.",
            details={"reason": "gateway_settings_invalid"},
        ) from None
    production_only_requested = any(
        getattr(arguments, name, None) is not None
        for name in (
            "approval_db_path",
            "approval_secret_ref",
            "approval_salt_ref",
            "audit_db_path",
            "audit_secret_ref",
            "audit_salt_ref",
        )
    )
    if production_only_requested and not bool(getattr(arguments, "production_actions", False)):
        raise RuntimeConfigurationError(
            "Approval and Action audit SQLite options require --production-actions.",
            details={"reason": "production_actions_opt_in_required"},
        )
    operator_approval, operator_configuration = _development_operator_approval(arguments)
    production_operator_approval, production_operator_configuration = _production_operator_approval(
        arguments
    )
    if bool(getattr(arguments, "production_actions", False)):
        action_dependencies, action_configuration, session_vault = _production_action_dependencies(
            arguments
        )
    else:
        action_dependencies, action_configuration = _development_action_dependencies(arguments)
        session_vault, vault_configuration = _gateway_session_vault(arguments)
        action_configuration = {**action_configuration, **vault_configuration}
    try:
        composition = create_gateway_runtime(
            pack_path=pack_path,
            settings=settings,
            environment=os.environ,
            deployment_scope_ceiling=deployment_scope_ceiling,
            mcp_session_idle_timeout_seconds=arguments.mcp_idle_timeout,
            max_request_body_size=arguments.body_limit,
            action_dependencies=action_dependencies,
            operator_approval=operator_approval,
            production_operator_approval=production_operator_approval,
            session_vault=session_vault,
        )
    except BaseException:
        if action_dependencies is not None:
            with contextlib.suppress(BaseException):
                anyio.run(_close_untransferred_action_dependencies, action_dependencies)
        raise
    safe_configuration: dict[str, object] = {
        "gateway": {
            "host": settings.listen_host,
            "port": settings.listen_port,
            "allowed_hosts": list(settings.allowed_hosts),
            "allowed_origins": list(settings.allowed_origins),
            "session_ttl_seconds": settings.session_ttl_seconds,
            "max_sessions": settings.max_sessions,
            "mcp_session_idle_timeout_seconds": arguments.mcp_idle_timeout,
            "max_request_body_size": arguments.body_limit,
            "workers": settings.worker_count,
            "tls_enabled": settings.tls_enabled,
            "scope_mode": "deployment_ceiling",
        },
        **action_configuration,
        **operator_configuration,
        **production_operator_configuration,
    }
    if bool(arguments.json_output):
        try:
            return composition.tools(), safe_configuration
        finally:
            anyio.run(composition.aclose)

    try:
        uvicorn.run(
            composition.app,
            host=settings.listen_host,
            port=settings.listen_port,
            workers=settings.worker_count,
            ssl_certfile=certfile,
            ssl_keyfile=keyfile,
        )
    except SystemExit:
        with contextlib.suppress(BaseException):
            anyio.run(composition.aclose)
        raise RuntimeConfigurationError(
            "Gateway server failed to start.",
            details={"reason": "gateway_server_start_failed"},
        ) from None
    except BaseException:
        with contextlib.suppress(BaseException):
            anyio.run(composition.aclose)
        raise
    anyio.run(composition.aclose)
    return composition.tools(), safe_configuration


async def _close_untransferred_action_dependencies(dependencies: Any) -> None:
    """Reverse-close CLI-created resources if Gateway composition never takes ownership."""

    resources = (
        dependencies.audit_sink,
        dependencies.approval_authority,
        dependencies.store,
    )
    for resource in resources:
        close = getattr(resource, "close", None)
        if close is not None:
            with contextlib.suppress(BaseException):
                await close()


def _development_action_dependencies(
    arguments: argparse.Namespace,
) -> tuple[Any | None, dict[str, object]]:
    """Build explicitly bounded, non-production Action dependencies or return none."""

    import secrets

    from acc_runtime.actions import (
        ActionRuntimeDependencies,
        InMemoryActionResourceLock,
        InMemoryActionStore,
        InMemoryApprovalAuthority,
        LoggingActionAuditSink,
        SQLiteActionStore,
    )
    from acc_runtime.credentials import SecretRef, resolve_secret
    from acc_runtime.deployment import DeploymentPolicy
    from acc_runtime.runtime import RuntimeConfigurationError

    enabled = bool(getattr(arguments, "development_actions", False))
    local_guards = bool(getattr(arguments, "local_development_action_guards", False))
    capabilities = tuple(cast(Sequence[str], getattr(arguments, "action_capability", ())))
    effects = tuple(cast(Sequence[str], getattr(arguments, "action_effect", ())))
    maximum_risk = cast(str | None, getattr(arguments, "action_max_risk", None))
    store_mode = cast(str, getattr(arguments, "development_action_store", "memory"))
    store_path = cast(str | None, getattr(arguments, "action_store_path", None))
    store_secret_ref = cast(str | None, getattr(arguments, "action_store_secret_ref", None))
    store_salt_ref = cast(str | None, getattr(arguments, "action_store_salt_ref", None))
    store_options = (store_path, store_secret_ref, store_salt_ref)
    if not enabled:
        if (
            local_guards
            or capabilities
            or effects
            or maximum_risk is not None
            or store_mode != "memory"
            or any(value is not None for value in store_options)
        ):
            raise RuntimeConfigurationError(
                "Action deployment ceilings require --development-actions.",
                details={"reason": "development_actions_opt_in_required"},
            )
        return None, {}
    if not capabilities or not effects or maximum_risk is None:
        raise RuntimeConfigurationError(
            "Development Actions require explicit capability, effect, and risk ceilings.",
            details={"reason": "development_actions_ceiling_incomplete"},
        )

    if store_mode == "memory":
        if any(value is not None for value in store_options):
            raise RuntimeConfigurationError(
                "SQLite Action Store options require --development-action-store sqlite.",
                details={"reason": "development_action_store_mode_required"},
            )
        action_store: Any = InMemoryActionStore(
            development_only=True,
            deployment_salt=secrets.token_bytes(32),
        )
        store_label = "in_memory"
        store_durable = False
    elif store_mode == "sqlite":
        if any(value is None for value in store_options):
            raise RuntimeConfigurationError(
                "SQLite Action Store requires path, secret SecretRef, and salt SecretRef.",
                details={"reason": "development_action_store_configuration_incomplete"},
            )
        assert (
            store_path is not None and store_secret_ref is not None and store_salt_ref is not None
        )
        operator_ref = cast(str | None, getattr(arguments, "action_operator_secret_ref", None))
        try:
            secret_reference = SecretRef(store_secret_ref)
            salt_reference = SecretRef(store_salt_ref)
            store_secret = resolve_secret(secret_reference, os.environ)
            salt_secret = resolve_secret(salt_reference, os.environ)
            salt_value = salt_secret.get_secret_value()
            operator_value = (
                None
                if operator_ref is None
                else resolve_secret(SecretRef(operator_ref), os.environ)
            )
            reference_names = {store_secret_ref, store_salt_ref}
            if operator_ref is not None:
                reference_names.add(operator_ref)
            raw_values = [store_secret.get_secret_value(), salt_value]
            if operator_value is not None:
                raw_values.append(operator_value.get_secret_value())
            secret_values = set(raw_values)
            if len(reference_names) != (2 if operator_ref is None else 3) or len(secret_values) != (
                2 if operator_value is None else 3
            ):
                raise ValueError("Action secrets must be independent")
            action_store = SQLiteActionStore(
                store_path,
                operator_secret=store_secret,
                deployment_salt=salt_value.encode("utf-8"),
            )
        except (TypeError, ValueError, OSError):
            raise RuntimeConfigurationError(
                "SQLite Action Store configuration is invalid.",
                details={"reason": "development_action_store_invalid"},
            ) from None
        store_label = "sqlite"
        store_durable = True
    else:
        raise RuntimeConfigurationError(
            "Development Action Store mode is invalid.",
            details={"reason": "development_action_store_invalid"},
        )

    policy = DeploymentPolicy(
        allowed_effects=frozenset(cast(Any, effects)),
        max_risk=cast(Any, maximum_risk),
        capability_allowlist=frozenset(capabilities),
        require_durable_action_store=store_durable,
        action_audit_mode="required",
        action_sandbox_mode=("local_development" if local_guards else "disabled"),
    )
    dependencies = ActionRuntimeDependencies(
        deployment_policy=policy,
        store=action_store,
        approval_authority=InMemoryApprovalAuthority(development_only=True),
        audit_sink=LoggingActionAuditSink(),
        audit_salt=secrets.token_bytes(32),
        resource_lock=(InMemoryActionResourceLock() if local_guards else None),
    )
    return dependencies, {
        "actions": {
            "mode": "development_test_only",
            "store": store_label,
            "store_durable": store_durable,
            "approval_authority": "in_memory_trusted_host",
            "audit": "logging_required",
            "local_development_action_guards": (
                "process_local_only" if local_guards else "disabled"
            ),
            "allowed_capabilities": sorted(policy.capability_allowlist or ()),
            "allowed_effects": sorted(policy.allowed_effects),
            "max_risk": policy.max_risk,
        }
    }


def _resolve_independent_cli_secrets(
    references: Mapping[str, str],
) -> dict[str, Any]:
    """Resolve env-only SecretRefs and reject shared names or secret material."""

    from acc_runtime.credentials import SecretRef, resolve_secret

    names = list(references.values())
    if len(set(names)) != len(names):
        raise ValueError("deployment SecretRefs must be independent")
    resolved = {
        field: resolve_secret(SecretRef(reference), os.environ)
        for field, reference in references.items()
    }
    values = [secret.get_secret_value() for secret in resolved.values()]
    if len(set(values)) != len(values):
        raise ValueError("deployment secret values must be independent")
    return resolved


def _gateway_session_vault(
    arguments: argparse.Namespace,
) -> tuple[Any | None, dict[str, object]]:
    """Build an explicitly configured single-node session vault."""

    from acc_runtime.gateway import GatewaySessionVaultConfig
    from acc_runtime.runtime import RuntimeConfigurationError

    path = cast(str | None, getattr(arguments, "session_vault_path", None))
    key_ref = cast(str | None, getattr(arguments, "session_vault_key_ref", None))
    salt_ref = cast(str | None, getattr(arguments, "session_vault_salt_ref", None))
    options = (path, key_ref, salt_ref)
    if all(value is None for value in options):
        return None, {}
    if any(value is None for value in options):
        raise RuntimeConfigurationError(
            "SQLite session vault requires path, key SecretRef, and salt SecretRef.",
            details={"reason": "session_vault_configuration_incomplete"},
        )
    assert path is not None and key_ref is not None and salt_ref is not None
    references = {"session_vault_key": key_ref, "session_vault_salt": salt_ref}
    for field, attribute in (
        ("action_store_secret", "action_store_secret_ref"),
        ("action_store_salt", "action_store_salt_ref"),
        ("operator_secret", "action_operator_secret_ref"),
    ):
        reference = cast(str | None, getattr(arguments, attribute, None))
        if reference is not None:
            references[field] = reference
    try:
        secrets_by_field = _resolve_independent_cli_secrets(references)
        config = GatewaySessionVaultConfig(
            db_path=path,
            kek=secrets_by_field["session_vault_key"],
            deployment_salt=secrets_by_field["session_vault_salt"]
            .get_secret_value()
            .encode("utf-8"),
        )
    except (TypeError, ValueError, OSError, LookupError):
        raise RuntimeConfigurationError(
            "SQLite session vault configuration is invalid.",
            details={"reason": "session_vault_configuration_invalid"},
        ) from None
    return config, {"session_vault": {"mode": "sqlite_single_node", "durable": True}}


def _production_action_dependencies(
    arguments: argparse.Namespace,
) -> tuple[Any, dict[str, object], Any]:
    """Build the explicit durable, single-node production Action profile."""

    from acc_runtime.actions import (
        ActionRuntimeDependencies,
        SQLiteActionAuditSink,
        SQLiteActionStore,
        SQLiteApprovalAuthority,
    )
    from acc_runtime.deployment import DeploymentPolicy
    from acc_runtime.gateway import GatewaySessionVaultConfig
    from acc_runtime.runtime import RuntimeConfigurationError

    forbidden = bool(
        getattr(arguments, "development_actions", False)
        or getattr(arguments, "local_development_action_guards", False)
        or getattr(arguments, "development_action_operator_approval", False)
        or getattr(arguments, "action_operator_secret_ref", None)
        or getattr(arguments, "development_action_store", "memory") != "memory"
    )
    if forbidden:
        raise RuntimeConfigurationError(
            "Production Actions cannot use development Action or local operator modes.",
            details={"reason": "production_actions_development_mode_forbidden"},
        )
    capabilities = tuple(cast(Sequence[str], getattr(arguments, "action_capability", ())))
    effects = tuple(cast(Sequence[str], getattr(arguments, "action_effect", ())))
    maximum_risk = cast(str | None, getattr(arguments, "action_max_risk", None))
    if not capabilities or not effects or maximum_risk is None:
        raise RuntimeConfigurationError(
            "Production Actions require explicit capability, effect, and risk ceilings.",
            details={"reason": "production_actions_ceiling_incomplete"},
        )
    fields = {
        "action_store_path": "action_store_path",
        "action_store_secret": "action_store_secret_ref",
        "action_store_salt": "action_store_salt_ref",
        "session_vault_path": "session_vault_path",
        "session_vault_key": "session_vault_key_ref",
        "session_vault_salt": "session_vault_salt_ref",
        "approval_path": "approval_db_path",
        "approval_secret": "approval_secret_ref",
        "approval_salt": "approval_salt_ref",
        "audit_path": "audit_db_path",
        "audit_secret": "audit_secret_ref",
        "audit_salt": "audit_salt_ref",
    }
    configured = {
        field: cast(str | None, getattr(arguments, attribute, None))
        for field, attribute in fields.items()
    }
    if any(value is None for value in configured.values()):
        raise RuntimeConfigurationError(
            "Production Actions require complete Store, session vault, approval, "
            "and audit SQLite configuration.",
            details={"reason": "production_actions_configuration_incomplete"},
        )
    values = cast(dict[str, str], configured)
    references = {key: value for key, value in values.items() if not key.endswith("_path")}
    production_operator_ref = cast(
        str | None,
        getattr(arguments, "production_action_operator_secret_ref", None),
    )
    if production_operator_ref is not None:
        references["production_operator_secret"] = production_operator_ref
    try:
        resolved = _resolve_independent_cli_secrets(references)
        paths = [str(Path(values[key]).resolve()) for key in fields if key.endswith("_path")]
        if len(set(paths)) != len(paths):
            raise ValueError("production SQLite databases must use distinct paths")
        store = SQLiteActionStore(
            values["action_store_path"],
            operator_secret=resolved["action_store_secret"],
            deployment_salt=resolved["action_store_salt"].get_secret_value().encode("utf-8"),
        )
        authority = SQLiteApprovalAuthority(
            values["approval_path"],
            authority_secret=resolved["approval_secret"],
            deployment_salt=resolved["approval_salt"].get_secret_value().encode("utf-8"),
        )
        audit_sink = SQLiteActionAuditSink(
            values["audit_path"],
            operator_secret=resolved["audit_secret"],
            deployment_salt=resolved["audit_salt"].get_secret_value().encode("utf-8"),
        )
        vault = GatewaySessionVaultConfig(
            db_path=values["session_vault_path"],
            kek=resolved["session_vault_key"],
            deployment_salt=resolved["session_vault_salt"].get_secret_value().encode("utf-8"),
        )
    except (TypeError, ValueError, OSError, LookupError):
        raise RuntimeConfigurationError(
            "Production Action SQLite configuration is invalid.",
            details={"reason": "production_actions_configuration_invalid"},
        ) from None
    policy = DeploymentPolicy(
        allowed_effects=frozenset(cast(Any, effects)),
        max_risk=cast(Any, maximum_risk),
        capability_allowlist=frozenset(capabilities),
        require_durable_action_store=True,
        action_audit_mode="required",
        action_sandbox_mode="disabled",
    )
    dependencies = ActionRuntimeDependencies(
        deployment_policy=policy,
        store=store,
        approval_authority=authority,
        audit_sink=audit_sink,
        audit_salt=hashlib.sha256(
            b"acc-action-audit-pseudonym-v1\0"
            + resolved["audit_salt"].get_secret_value().encode("utf-8")
        ).digest(),
    )
    dependencies.validate_production(session_vault=vault)
    return (
        dependencies,
        {
            "actions": {
                "mode": "production_single_node",
                "store": "sqlite",
                "store_durable": True,
                "approval_authority": "sqlite_durable",
                "audit": "sqlite_durable_required",
                "allowed_capabilities": sorted(policy.capability_allowlist or ()),
                "allowed_effects": sorted(policy.allowed_effects),
                "max_risk": policy.max_risk,
            },
            "session_vault": {"mode": "sqlite_single_node", "durable": True},
        },
        vault,
    )


def _development_operator_approval(
    arguments: argparse.Namespace,
) -> tuple[Any | None, dict[str, object]]:
    from acc_runtime.credentials import SecretRef, resolve_secret
    from acc_runtime.gateway.operator import (
        OPERATOR_APPROVAL_BODY_LIMIT,
        LocalDevelopmentOperatorApprovalConfig,
    )
    from acc_runtime.runtime import RuntimeConfigurationError

    enabled = bool(getattr(arguments, "development_action_operator_approval", False))
    reference = cast(str | None, getattr(arguments, "action_operator_secret_ref", None))
    if not enabled:
        if reference is not None:
            raise RuntimeConfigurationError(
                "Operator SecretRef requires explicit development operator approval.",
                details={"reason": "operator_approval_opt_in_required"},
            )
        return None, {}
    if not bool(getattr(arguments, "development_actions", False)) or reference is None:
        raise RuntimeConfigurationError(
            "Development operator approval requires --development-actions and a SecretRef.",
            details={"reason": "operator_approval_configuration_incomplete"},
        )
    try:
        checked_ref = SecretRef(reference)
        secret = resolve_secret(checked_ref, os.environ)
        config = LocalDevelopmentOperatorApprovalConfig(
            secret=secret,
            secret_ref=reference,
        )
    except (TypeError, ValueError):
        raise RuntimeConfigurationError(
            "Development operator approval SecretRef is invalid or unavailable.",
            details={"reason": "operator_approval_secret_invalid"},
        ) from None
    return config, {
        "operator_approval": {
            "mode": "local_development_loopback_only",
            "path": "/operator/actions/approve",
            "secret_ref": reference,
            "request_body_limit": OPERATOR_APPROVAL_BODY_LIMIT,
        }
    }


def _production_operator_approval(
    arguments: argparse.Namespace,
) -> tuple[Any | None, dict[str, object]]:
    from acc_runtime.credentials import SecretRef, resolve_secret
    from acc_runtime.gateway.operator import (
        OPERATOR_APPROVAL_BODY_LIMIT,
        ProductionOperatorApprovalConfig,
    )
    from acc_runtime.runtime import RuntimeConfigurationError

    enabled = bool(getattr(arguments, "production_action_operator_approval", False))
    reference = cast(
        str | None,
        getattr(arguments, "production_action_operator_secret_ref", None),
    )
    if not enabled:
        if reference is not None:
            raise RuntimeConfigurationError(
                "Production operator SecretRef requires explicit operator approval.",
                details={"reason": "production_operator_opt_in_required"},
            )
        return None, {}
    if (
        not bool(getattr(arguments, "production_actions", False))
        or reference is None
        or bool(getattr(arguments, "development_action_operator_approval", False))
        or getattr(arguments, "action_operator_secret_ref", None) is not None
    ):
        raise RuntimeConfigurationError(
            "Production operator approval requires production Actions "
            "and an independent SecretRef.",
            details={"reason": "production_operator_configuration_incomplete"},
        )
    existing_refs = [
        cast(str, value)
        for name in (
            "action_store_secret_ref",
            "action_store_salt_ref",
            "session_vault_key_ref",
            "session_vault_salt_ref",
            "approval_secret_ref",
            "approval_salt_ref",
            "audit_secret_ref",
            "audit_salt_ref",
        )
        if (value := getattr(arguments, name, None)) is not None
    ]
    try:
        if reference in existing_refs or len(existing_refs) != len(set(existing_refs)):
            raise ValueError
        checked_ref = SecretRef(reference)
        secret = resolve_secret(checked_ref, os.environ)
        existing_values = [
            resolve_secret(SecretRef(item), os.environ).get_secret_value() for item in existing_refs
        ]
        if secret.get_secret_value() in existing_values or len(existing_values) != len(
            set(existing_values)
        ):
            raise ValueError
        config = ProductionOperatorApprovalConfig(secret=secret, secret_ref=reference)
    except (TypeError, ValueError, LookupError):
        raise RuntimeConfigurationError(
            "Production operator approval SecretRef is invalid, unavailable, or reused.",
            details={"reason": "production_operator_secret_invalid"},
        ) from None
    return config, {
        "operator_approval": {
            "mode": "production_loopback_process_bound",
            "path": "/operator/actions/approve",
            "request_body_limit": OPERATOR_APPROVAL_BODY_LIMIT,
            "restart_behavior": "prepared_actions_must_be_reprepared",
        }
    }


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
