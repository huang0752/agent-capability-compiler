"""Load and validate a complete ACC project without executing it."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from acc_core.diagnostics import Diagnostic
from acc_core.io import ProjectIOError, load_project_object
from acc_core.models import (
    Capability,
    EnvironmentSecretCredentials,
    Eval,
    GatewaySessionCredentials,
    Operation,
    PasswordBearerAuthConfig,
    Policy,
    Project,
    StrictModel,
)

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


@dataclass(slots=True)
class ValidationReport:
    """Validated contracts plus deterministic diagnostics."""

    project: Project | None = None
    operations: dict[str, Operation] = field(default_factory=dict)
    operation_paths: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Capability] = field(default_factory=dict)
    policies: dict[str, Policy] = field(default_factory=dict)
    evals: dict[str, Eval] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


def _pointer(location: tuple[int | str, ...]) -> str:
    if not location:
        return ""
    tokens = [str(token).replace("~", "~0").replace("/", "~1") for token in location]
    return "/" + "/".join(tokens)


def _validation_diagnostic(
    error: Mapping[str, Any],
    *,
    relative_path: str,
    model_type: type[StrictModel],
) -> Diagnostic:
    location = tuple(error.get("loc", ()))
    if model_type is Operation and location == ("evidence",):
        return Diagnostic(
            code="ACC_OPERATION_EVIDENCE_MISSING",
            severity="error",
            message="Operation requires at least one evidence reference.",
            path=relative_path,
            pointer="/evidence",
        )
    return Diagnostic(
        code="ACC_SCHEMA_INVALID",
        severity="error",
        message=str(error.get("msg", "Document does not match its schema.")),
        path=relative_path,
        pointer=_pointer(location),
    )


def _load_model[ModelT: StrictModel](
    root: Path,
    relative_path: str,
    model_type: type[ModelT],
    diagnostics: list[Diagnostic],
) -> ModelT | None:
    try:
        document = load_project_object(root, relative_path)
        return model_type.model_validate(document)
    except ProjectIOError as exc:
        diagnostics.append(
            Diagnostic(
                code=exc.code,
                severity="error",
                message=str(exc),
                path=relative_path,
                pointer=None,
            )
        )
    except ValidationError as exc:
        diagnostics.extend(
            _validation_diagnostic(
                error,
                relative_path=relative_path,
                model_type=model_type,
            )
            for error in exc.errors(include_url=False)
        )
    return None


def _document_paths(root: Path, directory: str, diagnostics: list[Diagnostic]) -> list[str]:
    target = root / directory
    if not target.exists():
        return []
    if target.is_symlink():
        diagnostics.append(
            Diagnostic(
                code="ACC_IO_SYMLINK_REJECTED",
                severity="error",
                message=f"Symbolic links are forbidden in project paths: {directory}",
                path=directory,
                pointer=None,
            )
        )
        return []
    if not target.is_dir():
        diagnostics.append(
            Diagnostic(
                code="ACC_PROJECT_DIRECTORY_INVALID",
                severity="error",
                message=f"Expected a project directory: {directory}",
                path=directory,
                pointer=None,
            )
        )
        return []

    paths: list[str] = []
    for entry in sorted(target.iterdir(), key=lambda item: item.name):
        relative_path = f"{directory}/{entry.name}"
        if entry.is_symlink():
            diagnostics.append(
                Diagnostic(
                    code="ACC_IO_SYMLINK_REJECTED",
                    severity="error",
                    message=f"Symbolic links are forbidden in project paths: {relative_path}",
                    path=relative_path,
                    pointer=None,
                )
            )
        elif not entry.is_file() or entry.suffix.lower() not in _DOCUMENT_SUFFIXES:
            diagnostics.append(
                Diagnostic(
                    code="ACC_PROJECT_FILE_UNKNOWN",
                    severity="error",
                    message=f"Unknown project document: {relative_path}",
                    path=relative_path,
                    pointer=None,
                )
            )
        else:
            paths.append(relative_path)
    return paths


def _load_collection[ModelT: StrictModel](
    root: Path,
    directory: str,
    model_type: type[ModelT],
    duplicate_code: str,
    diagnostics: list[Diagnostic],
    relative_paths: dict[str, str] | None = None,
) -> dict[str, ModelT]:
    documents: dict[str, ModelT] = {}
    for relative_path in _document_paths(root, directory, diagnostics):
        model = _load_model(root, relative_path, model_type, diagnostics)
        if model is None:
            continue
        identifier = getattr(model, "id", None)
        if not isinstance(identifier, str):
            continue
        if identifier in documents:
            diagnostics.append(
                Diagnostic(
                    code=duplicate_code,
                    severity="error",
                    message=f"Duplicate {model_type.__name__} id: {identifier}",
                    path=relative_path,
                    pointer="/id",
                )
            )
            continue
        documents[identifier] = model
        if relative_paths is not None:
            relative_paths[identifier] = relative_path
    return documents


def _validate_auth_contract(report: ValidationReport) -> None:
    project = report.project
    if project is None:
        return

    auth = project.provider.auth
    transport = project.runtime.transport[0]
    if auth is None:
        if transport != "stdio":
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_AUTH_TRANSPORT_INCOMPATIBLE",
                    severity="error",
                    message=(
                        "streamable_http requires password_bearer authentication "
                        "with gateway_session credentials."
                    ),
                    path="project.yaml",
                    pointer="/provider/auth",
                )
            )
        else:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_AUTH_LEGACY_CREDENTIAL",
                    severity="warning",
                    message=(
                        "Legacy Operation-level credentials remain supported for stdio; "
                        "migrate authentication to provider.auth."
                    ),
                    path="project.yaml",
                    pointer="/provider",
                )
            )
        for operation_id, operation in sorted(report.operations.items()):
            if operation.http.credential_ref is None:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_AUTH_CREDENTIAL_REQUIRED",
                        severity="error",
                        message=(
                            "Legacy authentication requires an Operation-level credential_ref."
                        ),
                        path=report.operation_paths[operation_id],
                        pointer="/http/credential_ref",
                    )
                )
        return

    for operation_id, operation in sorted(report.operations.items()):
        if operation.http.credential_ref is not None:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_AUTH_CREDENTIAL_CONFLICT",
                    severity="error",
                    message=(
                        "Operation credential_ref is forbidden when provider.auth is configured."
                    ),
                    path=report.operation_paths[operation_id],
                    pointer="/http/credential_ref",
                )
            )

    password_auth = auth if isinstance(auth, PasswordBearerAuthConfig) else None
    compatible = (
        transport == "streamable_http"
        and password_auth is not None
        and isinstance(password_auth.credentials, GatewaySessionCredentials)
    ) or (
        transport == "stdio"
        and (
            password_auth is None
            or isinstance(password_auth.credentials, EnvironmentSecretCredentials)
        )
    )
    if not compatible:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_AUTH_TRANSPORT_INCOMPATIBLE",
                severity="error",
                message=(
                    "stdio accepts none, bearer_secret, or password_bearer with "
                    "environment_secret; streamable_http accepts only password_bearer "
                    "with gateway_session."
                ),
                path="project.yaml",
                pointer="/provider/auth",
            )
        )


def validate_project(project_root: str | Path = ".") -> ValidationReport:
    """Validate all Milestone 1 documents under ``project_root``."""

    root = Path(project_root)
    report = ValidationReport()
    report.project = _load_model(root, "project.yaml", Project, report.diagnostics)
    report.operations = _load_collection(
        root,
        "operations",
        Operation,
        "ACC_OPERATION_ID_DUPLICATE",
        report.diagnostics,
        report.operation_paths,
    )
    report.capabilities = _load_collection(
        root,
        "capabilities",
        Capability,
        "ACC_CAPABILITY_ID_DUPLICATE",
        report.diagnostics,
    )
    report.policies = _load_collection(
        root,
        "policies",
        Policy,
        "ACC_POLICY_ID_DUPLICATE",
        report.diagnostics,
    )
    report.evals = _load_collection(
        root,
        "evals",
        Eval,
        "ACC_EVAL_ID_DUPLICATE",
        report.diagnostics,
    )
    _validate_auth_contract(report)
    return report


__all__ = ["ValidationReport", "validate_project"]
