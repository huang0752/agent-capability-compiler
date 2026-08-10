"""Load and validate a complete ACC project without executing it."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from acc_core.contracts import SourceContract
from acc_core.contracts.fidelity import analyze_operation_schema_fidelity
from acc_core.diagnostics import Diagnostic
from acc_core.io import ProjectIOError, load_project_object
from acc_core.models import (
    ActionOperationV2,
    Capability,
    EnvironmentSecretCredentials,
    Eval,
    GatewaySessionCredentials,
    Operation,
    PasswordBearerAuthConfig,
    Policy,
    Project,
    ReadOperationV2,
    StrictModel,
)
from acc_core.quality import CapabilityQuality
from acc_core.quality.output_size import analyze_output_budget

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


@dataclass(slots=True)
class ValidationReport:
    """Validated contracts plus deterministic diagnostics."""

    project: Project | None = None
    operations: dict[str, Operation] = field(default_factory=dict)
    operation_paths: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Capability] = field(default_factory=dict)
    source_contracts: dict[str, SourceContract] = field(default_factory=dict)
    source_contract_paths: dict[str, str] = field(default_factory=dict)
    capability_quality: dict[str, CapabilityQuality] = field(default_factory=dict)
    capability_quality_paths: dict[str, str] = field(default_factory=dict)
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


def _require_current_format(
    document: Mapping[str, Any],
    *,
    relative_path: str,
    diagnostics: list[Diagnostic],
) -> bool:
    if document.get("schema_version") == "2":
        return True
    diagnostics.append(
        Diagnostic(
            code="ACC_FORMAT_VERSION_UNSUPPORTED",
            severity="error",
            message="ACC accepts only the current top-level format: schema_version 2.",
            path=relative_path,
            pointer="/schema_version",
        )
    )
    return False


def _validation_diagnostic(
    error: Mapping[str, Any],
    *,
    relative_path: str,
    model_type: type[StrictModel],
) -> Diagnostic:
    location = tuple(error.get("loc", ()))
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
        if not _require_current_format(
            document,
            relative_path=relative_path,
            diagnostics=diagnostics,
        ):
            return None
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


def _load_adapter[ModelT](
    root: Path,
    relative_path: str,
    adapter: TypeAdapter[ModelT],
    diagnostics: list[Diagnostic],
) -> ModelT | None:
    """Load one discriminated public document through a TypeAdapter."""

    try:
        document = load_project_object(root, relative_path)
        if not _require_current_format(
            document,
            relative_path=relative_path,
            diagnostics=diagnostics,
        ):
            return None
        return adapter.validate_python(document)
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
        for error in exc.errors(include_url=False):
            location = tuple(error.get("loc", ()))
            if location and location[0] in {"read", "action"}:
                location = location[1:]
            if relative_path.startswith("operations/") and location == ("evidence",):
                diagnostics.append(
                    Diagnostic(
                        code="ACC_OPERATION_EVIDENCE_MISSING",
                        severity="error",
                        message="Operation requires at least one evidence reference.",
                        path=relative_path,
                        pointer="/evidence",
                    )
                )
                continue
            diagnostics.append(
                Diagnostic(
                    code="ACC_SCHEMA_INVALID",
                    severity="error",
                    message=str(error.get("msg", "Document does not match its schema.")),
                    path=relative_path,
                    pointer=_pointer(location),
                )
            )
    return None


def _load_project_document(root: Path, diagnostics: list[Diagnostic]) -> Project | None:
    """Load only the current Project format with a stable version diagnostic."""

    relative_path = "project.yaml"
    try:
        document = load_project_object(root, relative_path)
        if not _require_current_format(
            document,
            relative_path=relative_path,
            diagnostics=diagnostics,
        ):
            return None
        return Project.model_validate(document)
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
                model_type=Project,
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


def _load_adapter_collection[ModelT](
    root: Path,
    directory: str,
    adapter: TypeAdapter[ModelT],
    *,
    identifier_field: str,
    duplicate_code: str,
    diagnostics: list[Diagnostic],
    relative_paths: dict[str, str] | None = None,
) -> dict[str, ModelT]:
    """Load a collection of discriminated or sidecar documents."""

    documents: dict[str, ModelT] = {}
    for relative_path in _document_paths(root, directory, diagnostics):
        model = _load_adapter(root, relative_path, adapter, diagnostics)
        if model is None:
            continue
        identifier = getattr(model, identifier_field, None)
        if not isinstance(identifier, str):
            continue
        if identifier in documents:
            diagnostics.append(
                Diagnostic(
                    code=duplicate_code,
                    severity="error",
                    message=f"Duplicate {identifier_field}: {identifier}",
                    path=relative_path,
                    pointer=f"/{identifier_field}",
                )
            )
            continue
        documents[identifier] = model
        if relative_paths is not None:
            relative_paths[identifier] = relative_path
    return documents


def _validate_v2_sidecar_closure(report: ValidationReport) -> None:
    """Require complete one-to-one quality sidecars for the current Project."""

    for operation_id in sorted(set(report.operations) - set(report.source_contracts)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_SOURCE_CONTRACT_MISSING",
                severity="error",
                message="The current Project requires one SourceContract per Operation.",
                path=report.operation_paths.get(operation_id),
                pointer=None,
            )
        )
    for operation_id in sorted(set(report.source_contracts) - set(report.operations)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_SOURCE_CONTRACT_ORPHAN",
                severity="error",
                message="SourceContract must reference an existing Operation.",
                path=report.source_contract_paths.get(operation_id),
                pointer="/operation_id",
            )
        )
    for _capability_id in sorted(set(report.capabilities) - set(report.capability_quality)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_QUALITY_MISSING",
                severity="error",
                message="The current Project requires one CapabilityQuality per Capability.",
                path=None,
                pointer=None,
            )
        )
    for capability_id in sorted(set(report.capability_quality) - set(report.capabilities)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_QUALITY_ORPHAN",
                severity="error",
                message="CapabilityQuality must reference an existing Capability.",
                path=report.capability_quality_paths.get(capability_id),
                pointer="/capability_id",
            )
        )
    for operation_id in sorted(set(report.operations) & set(report.source_contracts)):
        operation = report.operations[operation_id]
        contract = report.source_contracts[operation_id]
        contract_path = report.source_contract_paths.get(operation_id)
        for index, claim in enumerate(contract.provenance):
            if claim.evidence not in operation.evidence:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_SCHEMA_PROVENANCE_EVIDENCE_MISMATCH",
                        severity="error",
                        message="Schema provenance must use Evidence bound to its Operation.",
                        path=contract_path,
                        pointer=f"/provenance/{index}/evidence",
                    )
                )
        semantics = contract.action_semantics
        if isinstance(operation, ReadOperationV2):
            if semantics is not None:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_ACTION_SEMANTICS_FORBIDDEN",
                        severity="error",
                        message="A read Operation cannot declare Action semantics.",
                        path=contract_path,
                        pointer="/action_semantics",
                    )
                )
        elif isinstance(operation, ActionOperationV2):
            if semantics is None:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_ACTION_SEMANTICS_MISSING",
                        severity="error",
                        message="An Action Operation requires evidence-backed Action semantics.",
                        path=contract_path,
                        pointer="/action_semantics",
                    )
                )
            else:
                if semantics.evidence not in operation.evidence:
                    report.diagnostics.append(
                        Diagnostic(
                            code="ACC_ACTION_SEMANTICS_EVIDENCE_MISMATCH",
                            severity="error",
                            message="Action semantics must use Evidence bound to its Operation.",
                            path=contract_path,
                            pointer="/action_semantics/evidence",
                        )
                    )
                expected_semantics = {
                    "method": operation.http.method,
                    "effect": operation.http.safety.effect,
                    "risk": operation.http.safety.risk,
                    "reversibility": operation.http.safety.reversibility,
                    "retry": operation.http.safety.retry,
                    "idempotency": operation.http.safety.idempotency,
                    "concurrency": operation.http.safety.concurrency,
                }
                for field_name, expected in expected_semantics.items():
                    if getattr(semantics, field_name) != expected:
                        report.diagnostics.append(
                            Diagnostic(
                                code="ACC_ACTION_SEMANTICS_MISMATCH",
                                severity="error",
                                message=(
                                    "Action semantics must exactly match the Operation HTTP "
                                    f"safety contract: {field_name}."
                                ),
                                path=contract_path,
                                pointer=f"/action_semantics/{field_name}",
                            )
                        )
        report.diagnostics.extend(
            analyze_operation_schema_fidelity(
                operation,
                contract,
                operation_path=report.operation_paths.get(operation_id),
            )
        )
    for capability_id in sorted(set(report.capabilities) & set(report.capability_quality)):
        capability = report.capabilities[capability_id]
        quality = report.capability_quality[capability_id]
        report.diagnostics.extend(
            analyze_output_budget(
                capability_id,
                capability.output_schema,
                quality.output_budget,
                quality_path=report.capability_quality_paths.get(capability_id),
            )
        )


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
        return

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
    report.project = _load_project_document(root, report.diagnostics)
    report.operations = _load_adapter_collection(
        root,
        "operations",
        TypeAdapter(Operation),
        identifier_field="id",
        duplicate_code="ACC_OPERATION_ID_DUPLICATE",
        diagnostics=report.diagnostics,
        relative_paths=report.operation_paths,
    )
    report.capabilities = _load_adapter_collection(
        root,
        "capabilities",
        TypeAdapter(Capability),
        identifier_field="id",
        duplicate_code="ACC_CAPABILITY_ID_DUPLICATE",
        diagnostics=report.diagnostics,
    )
    report.source_contracts = _load_adapter_collection(
        root,
        "source-contracts",
        TypeAdapter(SourceContract),
        identifier_field="operation_id",
        duplicate_code="ACC_SOURCE_CONTRACT_DUPLICATE",
        diagnostics=report.diagnostics,
        relative_paths=report.source_contract_paths,
    )
    report.capability_quality = _load_adapter_collection(
        root,
        "capability-quality",
        TypeAdapter(CapabilityQuality),
        identifier_field="capability_id",
        duplicate_code="ACC_CAPABILITY_QUALITY_DUPLICATE",
        diagnostics=report.diagnostics,
        relative_paths=report.capability_quality_paths,
    )
    _validate_v2_sidecar_closure(report)
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
