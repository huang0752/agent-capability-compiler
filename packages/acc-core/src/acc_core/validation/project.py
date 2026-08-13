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
from acc_core.domains import (
    CapabilityCandidateLedger,
    DomainChangeRequest,
    DomainDecision,
    DomainMap,
    analyze_domain_readiness,
    capability_candidate_ledger_digest,
    domain_decision_digest,
)
from acc_core.interactions.models import (
    CapabilityInteractionContract,
    UIInteractionInventory,
)
from acc_core.interactions.validate import analyze_interaction_fidelity
from acc_core.io import ProjectIOError, load_project_object
from acc_core.models import (
    ActionOperationV2,
    Capability,
    EnvironmentSecretCredentials,
    Eval,
    Evidence,
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
from acc_core.scope import ScopeInventory

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


@dataclass(slots=True)
class ValidationReport:
    """Validated contracts plus deterministic diagnostics."""

    project: Project | None = None
    operations: dict[str, Operation] = field(default_factory=dict)
    operation_paths: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Capability] = field(default_factory=dict)
    capability_paths: dict[str, str] = field(default_factory=dict)
    source_contracts: dict[str, SourceContract] = field(default_factory=dict)
    source_contract_paths: dict[str, str] = field(default_factory=dict)
    capability_quality: dict[str, CapabilityQuality] = field(default_factory=dict)
    capability_quality_paths: dict[str, str] = field(default_factory=dict)
    policies: dict[str, Policy] = field(default_factory=dict)
    evals: dict[str, Eval] = field(default_factory=dict)
    scope_inventory: ScopeInventory | None = None
    scope_inventory_path: str | None = None
    ui_interaction_inventory: UIInteractionInventory | None = None
    ui_interaction_inventory_path: str | None = None
    interaction_contracts: dict[str, CapabilityInteractionContract] = field(default_factory=dict)
    interaction_contract_paths: dict[str, str] = field(default_factory=dict)
    evidence_registry: dict[str, Evidence] = field(default_factory=dict)
    evidence_paths: dict[str, str] = field(default_factory=dict)
    domain_map: DomainMap | None = None
    domain_map_path: str | None = None
    capability_candidate_ledger: CapabilityCandidateLedger | None = None
    capability_candidate_ledger_path: str | None = None
    domain_decisions: dict[tuple[str, int], DomainDecision] = field(default_factory=dict)
    domain_decision_paths: dict[tuple[str, int], str] = field(default_factory=dict)
    domain_change_requests: dict[str, DomainChangeRequest] = field(default_factory=dict)
    domain_change_request_paths: dict[str, str] = field(default_factory=dict)
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
    if not target.exists():
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


def _load_domain_decisions(root: Path, report: ValidationReport) -> None:
    for relative_path in _document_paths(root, "domain-decisions", report.diagnostics):
        decision = _load_model(
            root,
            relative_path,
            DomainDecision,
            report.diagnostics,
        )
        if decision is None:
            continue
        key = (decision.domain_id, decision.revision)
        if key in report.domain_decisions:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DECISION_DUPLICATE",
                    severity="error",
                    message="A domain decision revision may be declared only once.",
                    path=relative_path,
                    pointer="/revision",
                )
            )
            continue
        report.domain_decisions[key] = decision
        report.domain_decision_paths[key] = relative_path


def _load_evidence_registry(root: Path, report: ValidationReport) -> None:
    """Load strict Evidence cores while retaining forward-compatible audit artifacts."""

    core_fields = set(Evidence.model_fields)
    for relative_path in _document_paths(root, "evidence", report.diagnostics):
        try:
            document = load_project_object(root, relative_path)
            core = {name: document[name] for name in core_fields if name in document}
            evidence = Evidence.model_validate(core)
        except ProjectIOError as exc:
            report.diagnostics.append(
                Diagnostic(
                    code=exc.code,
                    severity="error",
                    message=str(exc),
                    path=relative_path,
                    pointer=None,
                )
            )
            continue
        except ValidationError as exc:
            report.diagnostics.extend(
                _validation_diagnostic(
                    error,
                    relative_path=relative_path,
                    model_type=Evidence,
                )
                for error in exc.errors(include_url=False)
            )
            continue
        if evidence.source_id in report.evidence_registry:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_EVIDENCE_SOURCE_ID_DUPLICATE",
                    severity="error",
                    message="Evidence source_id may be declared only once.",
                    path=relative_path,
                    pointer="/source_id",
                )
            )
            continue
        report.evidence_registry[evidence.source_id] = evidence
        report.evidence_paths[evidence.source_id] = relative_path


def _decision_for_ref(
    report: ValidationReport,
    domain_id: str,
    revision: int,
    digest: str,
) -> tuple[DomainDecision | None, bool]:
    decision = report.domain_decisions.get((domain_id, revision))
    return decision, decision is not None and domain_decision_digest(decision) == digest


def _decision_ref_key(value: object) -> tuple[object, object, object]:
    return (
        getattr(value, "domain_id", None),
        getattr(value, "revision", None),
        getattr(value, "decision_digest", None),
    )


def _require_evidence(
    report: ValidationReport,
    evidence_ref: str,
    *,
    digest: str | None,
    path: str | None,
    pointer: str | None,
) -> None:
    evidence = report.evidence_registry.get(evidence_ref)
    if evidence is None:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_EVIDENCE_UNKNOWN",
                severity="error",
                message="Domain evidence reference must resolve through evidence/.",
                path=path,
                pointer=pointer,
            )
        )
    elif digest is not None and evidence.digest != digest:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_EVIDENCE_DIGEST_MISMATCH",
                severity="error",
                message="Domain evidence digest must equal the independent Evidence artifact.",
                path=path,
                pointer=pointer,
            )
        )


def _candidate_evidence_refs(candidate: object) -> set[str]:
    claims = getattr(candidate, "claims", None)
    refs: set[str] = set()
    if claims is not None:
        for field_name in claims.__class__.model_fields:
            claim = getattr(claims, field_name)
            refs.update(claim.evidence_refs)
    ineligibility = getattr(candidate, "ineligibility_claim", None)
    if ineligibility is not None:
        refs.update(ineligibility.evidence_refs)
    return refs


def validate_proposed_domain_decision(
    report: ValidationReport,
    decision: DomainDecision,
    path: str,
    *,
    require_next_revision: bool = True,
) -> list[Diagnostic]:
    """Validate one proposed decision against the already typed Project closure."""

    diagnostics: list[Diagnostic] = []
    domain_map = report.domain_map
    ledger = report.capability_candidate_ledger
    if domain_map is None or ledger is None:
        return [
            Diagnostic(
                code="ACC_DOMAIN_PROJECT_INVALID",
                severity="error",
                message="Domain decision validation requires typed domain sidecars.",
                path=path,
                pointer=None,
            )
        ]
    domains = {item.id: item for item in domain_map.domains}
    candidates = {item.id: item for item in ledger.candidates}
    domain = domains.get(decision.domain_id)
    if domain is None:
        return [
            Diagnostic(
                code="ACC_DOMAIN_DECISION_DOMAIN_UNKNOWN",
                severity="error",
                message="DomainDecision references an unknown domain.",
                path=path,
                pointer="/domain_id",
            )
        ]
    if require_next_revision:
        revisions = [
            revision for domain_id, revision in report.domain_decisions if domain_id == domain.id
        ]
        expected_revision = max(revisions, default=0) + 1
        if decision.revision != expected_revision:
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_REVIEW_REVISION_INVALID",
                    severity="error",
                    message="Review revision must be the next domain decision revision.",
                    path=path,
                    pointer="/revision",
                )
            )
    if decision.candidate_ledger_digest != capability_candidate_ledger_digest(ledger):
        diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_DECISION_LEDGER_DIGEST_MISMATCH",
                severity="error",
                message="DomainDecision must bind the canonical candidate ledger digest.",
                path=path,
                pointer="/candidate_ledger_digest",
            )
        )
    if decision.candidate_snapshot_ids != domain.candidate_ids:
        diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_DECISION_CANDIDATE_SNAPSHOT_MISMATCH",
                severity="error",
                message="DomainDecision candidate snapshot must equal its domain denominator.",
                path=path,
                pointer="/candidate_snapshot_ids",
            )
        )
    for index, disposition in enumerate(decision.candidate_dispositions):
        candidate = candidates.get(disposition.candidate_id)
        if candidate is None or candidate.domain_id != domain.id:
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DECISION_CANDIDATE_UNKNOWN",
                    severity="error",
                    message="Candidate disposition must reference a candidate in this domain.",
                    path=path,
                    pointer=f"/candidate_dispositions/{index}/candidate_id",
                )
            )
        for capability_id in disposition.materialized_capability_ids:
            if capability_id not in report.capabilities:
                diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_MATERIALIZED_CAPABILITY_UNKNOWN",
                        severity="error",
                        message="Materialized Capability must exist in the Project.",
                        path=path,
                        pointer=f"/candidate_dispositions/{index}/materialized_capability_ids",
                    )
                )
    dependency_ids = [item.domain_id for item in decision.dependency_decisions]
    if dependency_ids != domain.dependency_domain_ids:
        diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_DEPENDENCY_SNAPSHOT_MISMATCH",
                severity="error",
                message="Decision dependencies must equal the DomainMap dependency set.",
                path=path,
                pointer="/dependency_decisions",
            )
        )
    for index, dependency in enumerate(decision.dependency_decisions):
        target, exact = _decision_for_ref(
            report, dependency.domain_id, dependency.revision, dependency.decision_digest
        )
        dependency_domain = domains.get(dependency.domain_id)
        pointer = f"/dependency_decisions/{index}"
        if not exact:
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DEPENDENCY_DECISION_UNKNOWN",
                    severity="error",
                    message="Dependency decision reference must resolve with an exact digest.",
                    path=path,
                    pointer=pointer,
                )
            )
        if (
            dependency_domain is None
            or dependency_domain.active_decision_ref is None
            or _decision_ref_key(dependency_domain.active_decision_ref)
            != _decision_ref_key(dependency)
        ):
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DEPENDENCY_ACTIVE_DECISION_MISMATCH",
                    severity="error",
                    message="Dependency snapshot must bind the active dependency decision.",
                    path=path,
                    pointer=pointer,
                )
            )
        if target is None or target.status != "completed" or target.user_confirmation is None:
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DEPENDENCY_NOT_COMPLETED",
                    severity="error",
                    message="Dependency decision must be completed and confirmed.",
                    path=path,
                    pointer=pointer,
                )
            )
    snapshot = {item.evidence_ref: item.digest for item in decision.evidence_snapshot}
    for index, item in enumerate(decision.evidence_snapshot):
        evidence = report.evidence_registry.get(item.evidence_ref)
        if evidence is None:
            code = "ACC_DOMAIN_EVIDENCE_UNKNOWN"
        elif evidence.digest != item.digest:
            code = "ACC_DOMAIN_EVIDENCE_DIGEST_MISMATCH"
        else:
            continue
        diagnostics.append(
            Diagnostic(
                code=code,
                severity="error",
                message="Decision Evidence must resolve with its independent digest.",
                path=path,
                pointer=f"/evidence_snapshot/{index}",
            )
        )
    required_evidence = set(domain.evidence_refs)
    for candidate_id in domain.candidate_ids:
        candidate = candidates.get(candidate_id)
        if candidate is not None:
            required_evidence.update(_candidate_evidence_refs(candidate))
    if not required_evidence <= set(snapshot):
        diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_EVIDENCE_SNAPSHOT_INCOMPLETE",
                severity="error",
                message="Decision Evidence must cover the domain candidate denominator.",
                path=path,
                pointer="/evidence_snapshot",
            )
        )
    confirmation = decision.user_confirmation
    if confirmation is not None:
        evidence = report.evidence_registry.get(confirmation.source_evidence_ref)
        if (
            evidence is None
            or evidence.digest != confirmation.source_text_digest
            or snapshot.get(confirmation.source_evidence_ref) != confirmation.source_text_digest
        ):
            diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH",
                    severity="error",
                    message="UserConfirmation must bind registered Evidence exactly.",
                    path=path,
                    pointer="/user_confirmation/source_evidence_ref",
                )
            )
    business_goals = {
        candidate.business_intent
        for item in domain.candidate_ids
        if (candidate := candidates.get(item)) is not None
    }
    if not set(decision.policy.goals) <= business_goals:
        diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_REVIEW_GOAL_UNKNOWN",
                severity="error",
                message="Decision goals must match Candidate business intents.",
                path=path,
                pointer="/policy/goals",
            )
        )
    return diagnostics


def _validate_domain_sidecar_closure(
    report: ValidationReport,
    *,
    domain_map_declared: bool,
    candidate_ledger_declared: bool,
) -> None:
    domain_map = report.domain_map
    ledger = report.capability_candidate_ledger
    dependent_sidecars_declared = bool(report.domain_decisions or report.domain_change_requests)
    if (domain_map_declared or dependent_sidecars_declared) and not candidate_ledger_declared:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_CANDIDATE_LEDGER_MISSING",
                severity="error",
                message="domain-map.yaml requires capability-candidates.yaml.",
                path="domain-map.yaml",
                pointer=None,
            )
        )
    if (candidate_ledger_declared or dependent_sidecars_declared) and not domain_map_declared:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_MAP_MISSING",
                severity="error",
                message="capability-candidates.yaml requires domain-map.yaml.",
                path="capability-candidates.yaml",
                pointer=None,
            )
        )
    if domain_map is None or ledger is None:
        return

    domains = {domain.id: domain for domain in domain_map.domains}
    candidates = {candidate.id: candidate for candidate in ledger.candidates}
    classified = {
        candidate_id: domain.id
        for domain in domain_map.domains
        for candidate_id in domain.candidate_ids
    }
    mapped_ids = set(classified) | set(domain_map.unclassified_candidate_ids)
    candidate_ids = set(candidates)
    for _candidate_id in sorted(mapped_ids - candidate_ids):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_CANDIDATE_MISSING",
                severity="error",
                message="DomainMap references a candidate missing from the candidate ledger.",
                path=report.domain_map_path,
                pointer=None,
            )
        )
    for _candidate_id in sorted(candidate_ids - mapped_ids):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_DOMAIN_CANDIDATE_ORPHAN",
                severity="error",
                message="Every candidate ledger entry must be classified or unclassified.",
                path=report.capability_candidate_ledger_path,
                pointer=None,
            )
        )
    for candidate_id in sorted(candidate_ids & mapped_ids):
        expected_domain = classified.get(candidate_id)
        if candidates[candidate_id].domain_id != expected_domain:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_CANDIDATE_DOMAIN_MISMATCH",
                    severity="error",
                    message="Candidate domain_id must exactly match its DomainMap assignment.",
                    path=report.capability_candidate_ledger_path,
                    pointer=None,
                )
            )

    for domain in domain_map.domains:
        for evidence_ref in domain.evidence_refs:
            _require_evidence(
                report,
                evidence_ref,
                digest=None,
                path=report.domain_map_path,
                pointer="/domains",
            )
    for candidate in ledger.candidates:
        for evidence_ref in sorted(_candidate_evidence_refs(candidate)):
            _require_evidence(
                report,
                evidence_ref,
                digest=None,
                path=report.capability_candidate_ledger_path,
                pointer="/candidates",
            )

    ledger_digest = capability_candidate_ledger_digest(ledger)

    for key, decision in sorted(report.domain_decisions.items()):
        path = report.domain_decision_paths.get(key)
        decision_domain = domains.get(decision.domain_id)
        if decision_domain is None:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DECISION_DOMAIN_UNKNOWN",
                    severity="error",
                    message="DomainDecision references an unknown domain.",
                    path=path,
                    pointer="/domain_id",
                )
            )
            continue
        if decision.candidate_ledger_digest != ledger_digest:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DECISION_LEDGER_DIGEST_MISMATCH",
                    severity="error",
                    message="DomainDecision must bind the canonical candidate ledger digest.",
                    path=path,
                    pointer="/candidate_ledger_digest",
                )
            )
        if decision.candidate_snapshot_ids != decision_domain.candidate_ids:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DECISION_CANDIDATE_SNAPSHOT_MISMATCH",
                    severity="error",
                    message="DomainDecision candidate snapshot must equal its domain denominator.",
                    path=path,
                    pointer="/candidate_snapshot_ids",
                )
            )
        for index, disposition in enumerate(decision.candidate_dispositions):
            disposition_candidate = candidates.get(disposition.candidate_id)
            if (
                disposition_candidate is None
                or disposition_candidate.domain_id != decision.domain_id
            ):
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_DECISION_CANDIDATE_UNKNOWN",
                        severity="error",
                        message="Candidate disposition must reference a candidate in this domain.",
                        path=path,
                        pointer=f"/candidate_dispositions/{index}/candidate_id",
                    )
                )
            for capability_id in disposition.materialized_capability_ids:
                if capability_id not in report.capabilities:
                    report.diagnostics.append(
                        Diagnostic(
                            code="ACC_DOMAIN_MATERIALIZED_CAPABILITY_UNKNOWN",
                            severity="error",
                            message="Materialized Capability must exist in the Project.",
                            path=path,
                            pointer=f"/candidate_dispositions/{index}/materialized_capability_ids",
                        )
                    )
        dependency_ids = [item.domain_id for item in decision.dependency_decisions]
        if dependency_ids != decision_domain.dependency_domain_ids:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_DEPENDENCY_SNAPSHOT_MISMATCH",
                    severity="error",
                    message="Decision dependencies must equal the DomainMap dependency set.",
                    path=path,
                    pointer="/dependency_decisions",
                )
            )
        for index, dependency in enumerate(decision.dependency_decisions):
            _target, exact = _decision_for_ref(
                report,
                dependency.domain_id,
                dependency.revision,
                dependency.decision_digest,
            )
            if not exact:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_DEPENDENCY_DECISION_UNKNOWN",
                        severity="error",
                        message="Dependency decision reference must resolve with an exact digest.",
                        path=path,
                        pointer=f"/dependency_decisions/{index}",
                    )
                )
            dependency_domain = domains.get(dependency.domain_id)
            if (
                dependency_domain is None
                or dependency_domain.active_decision_ref is None
                or _decision_ref_key(dependency_domain.active_decision_ref)
                != _decision_ref_key(dependency)
            ):
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_DEPENDENCY_ACTIVE_DECISION_MISMATCH",
                        severity="error",
                        message=(
                            "Dependency snapshot must bind the dependency domain's active decision."
                        ),
                        path=path,
                        pointer=f"/dependency_decisions/{index}",
                    )
                )
        snapshot_by_ref = {item.evidence_ref: item.digest for item in decision.evidence_snapshot}
        for index, evidence_snapshot in enumerate(decision.evidence_snapshot):
            _require_evidence(
                report,
                evidence_snapshot.evidence_ref,
                digest=evidence_snapshot.digest,
                path=path,
                pointer=f"/evidence_snapshot/{index}",
            )
        required_evidence = set(decision_domain.evidence_refs)
        for candidate_id in decision_domain.candidate_ids:
            evidence_candidate = candidates.get(candidate_id)
            if evidence_candidate is not None:
                required_evidence.update(_candidate_evidence_refs(evidence_candidate))
        if not required_evidence <= set(snapshot_by_ref):
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_EVIDENCE_SNAPSHOT_INCOMPLETE",
                    severity="error",
                    message="Decision evidence snapshot must cover every domain candidate claim.",
                    path=path,
                    pointer="/evidence_snapshot",
                )
            )
        confirmation = decision.user_confirmation
        if confirmation is not None:
            _require_evidence(
                report,
                confirmation.source_evidence_ref,
                digest=confirmation.source_text_digest,
                path=path,
                pointer="/user_confirmation/source_evidence_ref",
            )
            confirmation_evidence = report.evidence_registry.get(confirmation.source_evidence_ref)
            if (
                confirmation_evidence is None
                or confirmation_evidence.digest != confirmation.source_text_digest
                or snapshot_by_ref.get(confirmation.source_evidence_ref)
                != confirmation.source_text_digest
            ):
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH",
                        severity="error",
                        message="UserConfirmation must bind an exact Evidence snapshot digest.",
                        path=path,
                        pointer="/user_confirmation/source_evidence_ref",
                    )
                )

    existing_decision_diagnostics = {
        (item.code, item.path, item.pointer) for item in report.diagnostics
    }
    for key, decision in sorted(report.domain_decisions.items()):
        path = report.domain_decision_paths.get(key) or "domain-decisions"
        for diagnostic in validate_proposed_domain_decision(
            report, decision, path, require_next_revision=False
        ):
            diagnostic_key = (diagnostic.code, diagnostic.path, diagnostic.pointer)
            if diagnostic_key not in existing_decision_diagnostics:
                report.diagnostics.append(diagnostic)
                existing_decision_diagnostics.add(diagnostic_key)

    for domain in domain_map.domains:
        active = domain.active_decision_ref
        if active is None:
            continue
        active_decision, exact = _decision_for_ref(
            report,
            active.domain_id,
            active.revision,
            active.decision_digest,
        )
        if not exact:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_ACTIVE_DECISION_MISMATCH",
                    severity="error",
                    message=(
                        "Active decision reference must resolve to its exact revision and digest."
                    ),
                    path=report.domain_map_path,
                    pointer="/domains",
                )
            )
            continue
        assert active_decision is not None
        allowed_statuses = {"completed"} if domain.status == "completed" else {"completed", "stale"}
        if (
            domain.status in {"completed", "stale"}
            and active_decision.status not in allowed_statuses
        ):
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_ACTIVE_DECISION_STATUS_MISMATCH",
                    severity="error",
                    message="Domain status must agree with the referenced active decision status.",
                    path=report.domain_map_path,
                    pointer="/domains",
                )
            )
        if any(
            decision.domain_id == domain.id
            and decision.revision > active.revision
            and decision.status == "completed"
            for decision in report.domain_decisions.values()
        ):
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_ACTIVE_DECISION_SUPERSEDED",
                    severity="error",
                    message="Active decision cannot precede a newer completed revision.",
                    path=report.domain_map_path,
                    pointer="/domains",
                )
            )

    for request_id, request in sorted(report.domain_change_requests.items()):
        path = report.domain_change_request_paths.get(request_id)
        request_domain = domains.get(request.domain_id)
        if request_domain is None:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_CHANGE_DOMAIN_UNKNOWN",
                    severity="error",
                    message="DomainChangeRequest references an unknown domain.",
                    path=path,
                    pointer="/domain_id",
                )
            )
        _previous, previous_exact = _decision_for_ref(
            report,
            request.previous_decision.domain_id,
            request.previous_decision.revision,
            request.previous_decision.decision_digest,
        )
        if not previous_exact:
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_CHANGE_PREVIOUS_DECISION_MISMATCH",
                    severity="error",
                    message="Change request previous decision must resolve exactly.",
                    path=path,
                    pointer="/previous_decision",
                )
            )
        if (
            request.status in {"proposed", "confirmed"}
            and request_domain is not None
            and (
                request_domain.active_decision_ref is None
                or _decision_ref_key(request.previous_decision)
                != _decision_ref_key(request_domain.active_decision_ref)
            )
        ):
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_DOMAIN_CHANGE_PREVIOUS_NOT_ACTIVE",
                    severity="error",
                    message="Proposed or confirmed change must start from the active decision.",
                    path=path,
                    pointer="/previous_decision",
                )
            )
        applied_decision: DomainDecision | None = None
        if request.applied_decision_ref is not None:
            applied_decision, applied_exact = _decision_for_ref(
                report,
                request.applied_decision_ref.domain_id,
                request.applied_decision_ref.revision,
                request.applied_decision_ref.decision_digest,
            )
            if not applied_exact:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_CHANGE_APPLIED_DECISION_MISMATCH",
                        severity="error",
                        message="Applied decision reference must resolve exactly.",
                        path=path,
                        pointer="/applied_decision_ref",
                    )
                )
        for candidate_id in request.affected_candidate_ids:
            affected_candidate = candidates.get(candidate_id)
            if affected_candidate is None or affected_candidate.domain_id != request.domain_id:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_CHANGE_CANDIDATE_UNKNOWN",
                        severity="error",
                        message="Affected candidate must exist in the changed domain.",
                        path=path,
                        pointer="/affected_candidate_ids",
                    )
                )
        for capability_id in request.affected_capability_ids:
            if capability_id not in report.capabilities:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_CHANGE_CAPABILITY_UNKNOWN",
                        severity="error",
                        message="Affected Capability must exist in the Project.",
                        path=path,
                        pointer="/affected_capability_ids",
                    )
                )
        for index, evidence in enumerate(request.changed_evidence):
            registered = report.evidence_registry.get(evidence.evidence_ref)
            pointer = f"/changed_evidence/{index}/evidence_ref"
            if registered is None:
                _require_evidence(
                    report,
                    evidence.evidence_ref,
                    digest=None,
                    path=path,
                    pointer=pointer,
                )
            elif registered.digest not in {
                digest
                for digest in (evidence.old_digest, evidence.new_digest)
                if digest is not None
            }:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_EVIDENCE_DIGEST_MISMATCH",
                        severity="error",
                        message=("Changed Evidence must bind an exact before or after digest."),
                        path=path,
                        pointer=pointer,
                    )
                )
        confirmation = request.confirmation
        if confirmation is not None:
            _require_evidence(
                report,
                confirmation.source_evidence_ref,
                digest=confirmation.source_text_digest,
                path=path,
                pointer="/confirmation/source_evidence_ref",
            )
            confirmation_evidence = report.evidence_registry.get(confirmation.source_evidence_ref)
            if (
                confirmation_evidence is None
                or confirmation_evidence.digest != confirmation.source_text_digest
                or (
                    request.status == "applied"
                    and (
                        applied_decision is None
                        or not any(
                            item.evidence_ref == confirmation.source_evidence_ref
                            and item.digest == confirmation.source_text_digest
                            for item in applied_decision.evidence_snapshot
                        )
                    )
                )
            ):
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_DOMAIN_CONFIRMATION_EVIDENCE_MISMATCH",
                        severity="error",
                        message="UserConfirmation must bind an exact Evidence snapshot digest.",
                        path=path,
                        pointer="/confirmation/source_evidence_ref",
                    )
                )

    for domain_index, domain in enumerate(domain_map.domains):
        domain_decisions = sorted(
            (
                decision
                for decision in report.domain_decisions.values()
                if decision.domain_id == domain.id
            ),
            key=lambda item: item.revision,
        )
        if domain.active_decision_ref is None:
            readiness_decision = domain_decisions[-1] if domain_decisions else None
        else:
            readiness_active_decision, exact = _decision_for_ref(
                report,
                domain.active_decision_ref.domain_id,
                domain.active_decision_ref.revision,
                domain.active_decision_ref.decision_digest,
            )
            if not exact:
                readiness_active_decision = None
            readiness_decision = readiness_active_decision
        dependency_decisions: dict[str, DomainDecision] = {}
        for dependency_id in domain.dependency_domain_ids:
            dependency_domain = domains.get(dependency_id)
            if dependency_domain is None or dependency_domain.active_decision_ref is None:
                continue
            target, exact = _decision_for_ref(
                report,
                dependency_domain.active_decision_ref.domain_id,
                dependency_domain.active_decision_ref.revision,
                dependency_domain.active_decision_ref.decision_digest,
            )
            if exact and target is not None:
                dependency_decisions[dependency_id] = target
        readiness = analyze_domain_readiness(
            domain=domain,
            candidate_ledger=ledger,
            decision=readiness_decision,
            dependency_decisions=dependency_decisions,
        )
        decision_path = (
            report.domain_decision_paths.get(
                (readiness_decision.domain_id, readiness_decision.revision)
            )
            if readiness_decision is not None
            else report.domain_map_path
        )
        for diagnostic in readiness.diagnostics:
            path = (
                report.capability_candidate_ledger_path
                if diagnostic.pointer is not None and diagnostic.pointer.startswith("/candidates/")
                else decision_path
            )
            readiness_pointer: str | None = diagnostic.pointer
            if (
                readiness_decision is None
                and readiness_pointer is not None
                and readiness_pointer.startswith("/dependency_domain_ids/")
            ):
                readiness_pointer = f"/domains/{domain_index}{readiness_pointer}"
            report.diagnostics.append(
                diagnostic.model_copy(update={"path": path, "pointer": readiness_pointer})
            )


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


def _validate_application_success_contract(report: ValidationReport) -> None:
    """Reject operations whose success body cannot satisfy a provider envelope contract."""

    project = report.project
    if project is None or project.provider.application_success is None:
        return
    for operation_id in sorted(report.operations):
        operation = report.operations[operation_id]
        if operation.http.success.body == "json":
            continue
        report.diagnostics.append(
            Diagnostic(
                code="ACC_APPLICATION_SUCCESS_BODY_INCOMPATIBLE",
                severity="error",
                message=(
                    "provider application_success requires every operation success body to be json"
                ),
                path=report.operation_paths.get(operation_id),
                pointer="/http/success/body",
            )
        )


def _validate_interaction_sidecar_closure(report: ValidationReport) -> None:
    """Require exact Capability and interaction closure for a declared UI denominator."""

    inventory = report.ui_interaction_inventory
    contracts = report.interaction_contracts
    if inventory is None:
        if contracts:
            first_id = sorted(contracts)[0]
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_UI_INTERACTION_INVENTORY_MISSING",
                    severity="error",
                    message="InteractionContracts require ui-interaction-inventory.yaml.",
                    path=report.interaction_contract_paths.get(first_id),
                    pointer=None,
                )
            )
        return

    if inventory.scope.mode == "none":
        for capability_id in sorted(contracts):
            report.diagnostics.append(
                Diagnostic(
                    code="ACC_UI_INTERACTION_CONTRACT_ORPHAN",
                    severity="error",
                    message="A mode=none UI inventory cannot have InteractionContracts.",
                    path=report.interaction_contract_paths.get(capability_id),
                    pointer="/capability_id",
                )
            )
        return

    for capability_id in sorted(set(report.capabilities) - set(contracts)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_UI_INTERACTION_CONTRACT_MISSING",
                severity="error",
                message=(
                    "A discovered or complete UI inventory requires one "
                    "InteractionContract per Capability."
                ),
                path=report.capability_paths.get(capability_id),
                pointer=None,
            )
        )
    for capability_id in sorted(set(contracts) - set(report.capabilities)):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_UI_INTERACTION_CONTRACT_ORPHAN",
                severity="error",
                message="InteractionContract must reference an existing Capability.",
                path=report.interaction_contract_paths.get(capability_id),
                pointer="/capability_id",
            )
        )

    known_interactions = {interaction.id for interaction in inventory.interactions}
    classified: set[str] = set()
    for capability_id, contract in sorted(contracts.items()):
        contract_path = report.interaction_contract_paths.get(capability_id)
        for index, interaction_id in enumerate(contract.interaction_ids):
            if interaction_id not in known_interactions:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_UI_INTERACTION_REFERENCE_UNKNOWN",
                        severity="error",
                        message="InteractionContract references an unknown UI interaction.",
                        path=contract_path,
                        pointer=f"/interaction_ids/{index}",
                    )
                )
                continue
            classified.add(interaction_id)
        for index, omission in enumerate(contract.omissions):
            if omission.interaction_id not in known_interactions:
                report.diagnostics.append(
                    Diagnostic(
                        code="ACC_UI_INTERACTION_REFERENCE_UNKNOWN",
                        severity="error",
                        message="InteractionContract omits an unknown UI interaction.",
                        path=contract_path,
                        pointer=f"/omissions/{index}/interaction_id",
                    )
                )
                continue
            classified.add(omission.interaction_id)
    for _interaction_id in sorted(known_interactions - classified):
        report.diagnostics.append(
            Diagnostic(
                code="ACC_UI_INTERACTION_UNCLASSIFIED",
                severity="error",
                message="Every discovered UI interaction must be adopted or explicitly omitted.",
                path=report.ui_interaction_inventory_path,
                pointer=None,
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
        relative_paths=report.capability_paths,
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
    scope_inventory_path = "scope-inventory.yaml"
    if (root / scope_inventory_path).exists() or (root / scope_inventory_path).is_symlink():
        report.scope_inventory = _load_model(
            root,
            scope_inventory_path,
            ScopeInventory,
            report.diagnostics,
        )
        if report.scope_inventory is not None:
            report.scope_inventory_path = scope_inventory_path
    inventory_path = "ui-interaction-inventory.yaml"
    if (root / inventory_path).exists() or (root / inventory_path).is_symlink():
        report.ui_interaction_inventory = _load_model(
            root,
            inventory_path,
            UIInteractionInventory,
            report.diagnostics,
        )
        if report.ui_interaction_inventory is not None:
            report.ui_interaction_inventory_path = inventory_path
    report.interaction_contracts = _load_adapter_collection(
        root,
        "interaction-contracts",
        TypeAdapter(CapabilityInteractionContract),
        identifier_field="capability_id",
        duplicate_code="ACC_UI_INTERACTION_CONTRACT_DUPLICATE",
        diagnostics=report.diagnostics,
        relative_paths=report.interaction_contract_paths,
    )
    _load_evidence_registry(root, report)
    domain_map_path = "domain-map.yaml"
    domain_map_declared = (root / domain_map_path).exists() or (root / domain_map_path).is_symlink()
    if domain_map_declared:
        report.domain_map_path = domain_map_path
        report.domain_map = _load_model(
            root,
            domain_map_path,
            DomainMap,
            report.diagnostics,
        )
    candidate_ledger_path = "capability-candidates.yaml"
    candidate_ledger_declared = (root / candidate_ledger_path).exists() or (
        root / candidate_ledger_path
    ).is_symlink()
    if candidate_ledger_declared:
        report.capability_candidate_ledger_path = candidate_ledger_path
        report.capability_candidate_ledger = _load_model(
            root,
            candidate_ledger_path,
            CapabilityCandidateLedger,
            report.diagnostics,
        )
    _load_domain_decisions(root, report)
    report.domain_change_requests = _load_collection(
        root,
        "domain-change-requests",
        DomainChangeRequest,
        "ACC_DOMAIN_CHANGE_REQUEST_DUPLICATE",
        report.diagnostics,
        report.domain_change_request_paths,
    )
    _validate_domain_sidecar_closure(
        report,
        domain_map_declared=domain_map_declared,
        candidate_ledger_declared=candidate_ledger_declared,
    )
    _validate_v2_sidecar_closure(report)
    _validate_interaction_sidecar_closure(report)
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
    _validate_application_success_contract(report)
    if report.ui_interaction_inventory is not None and report.scope_inventory is None:
        report.diagnostics.append(
            Diagnostic(
                code="ACC_UI_SCOPE_INVENTORY_MISSING",
                severity="error",
                message="UI interaction fidelity requires scope-inventory.yaml.",
                path=report.ui_interaction_inventory_path,
                pointer=None,
            )
        )
    if (
        report.project is not None
        and report.scope_inventory is not None
        and report.ui_interaction_inventory is not None
    ):
        interaction_report = analyze_interaction_fidelity(
            project=report.project,
            scope_inventory=report.scope_inventory,
            ui_inventory=report.ui_interaction_inventory,
            contracts=report.interaction_contracts,
            capabilities=report.capabilities,
            operations=report.operations,
            policies=report.policies,
        )
        report.diagnostics.extend(interaction_report.diagnostics)
    return report


__all__ = ["ValidationReport", "validate_project", "validate_proposed_domain_decision"]
