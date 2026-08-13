"""Deterministic, read-only workflow commands for Agent Usage projects."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import TypeAdapter, ValidationError

from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.io import ProjectIOError, is_path_link, load_project_object
from acc_core.usage.acceptance import verify_mcp_release_acceptance
from acc_core.usage.impact import UsageImpactReport, UsageSnapshot, analyze_usage_impact
from acc_core.usage.models import (
    AgentUsageRelease,
    DomainUsageContract,
    DomainUsageIndex,
    Identifier,
    McpReleaseAcceptance,
    UsageDomainDecision,
)
from acc_core.usage.packaging import UsagePackageSigner, build_usage_package
from acc_core.usage.project import UsageProjectReport, validate_usage_project
from acc_core.usage.verification import VerifiedUsageReleaseBundle
from acc_core.usage.verification_artifact import (
    UsageVerificationArtifactError,
    load_usage_verification_artifact,
)

EXIT_SUCCESS = 0
EXIT_INPUT = 3

_USAGE_DIRECTORIES = (
    "domain-decisions",
    "domain-usage-contracts",
    "releases",
    "scenarios",
    "usage-evidence/client",
    "usage-evidence/mcp",
    "usage-evidence/runtime_observation",
    "usage-evidence/service",
    "usage-evidence/test",
)
_MANIFEST_FIELDS = frozenset(
    {
        "domain_id",
        "direct_dependency_domain_ids",
        "client_include_paths",
        "service_include_paths",
        "test_include_paths",
        "mcp_evidence_refs",
        "runtime_observation_refs",
    }
)
_MANIFEST_LIST_FIELDS = _MANIFEST_FIELDS - {"domain_id"}
_SCAN_EXPECTED_MISSING_DIAGNOSTICS = frozenset({("ACC_IO_NOT_FOUND", "source-snapshot.yaml")})
_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


def _diagnostic(code: str, message: str, *, path: str | None = None) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity="error",
        message=message,
        path=path,
        pointer=None,
    )


def _success(command: str, result: Mapping[str, Any]) -> tuple[int, ResultEnvelope]:
    return EXIT_SUCCESS, ResultEnvelope(
        ok=True,
        command=command,
        result=dict(result),
        diagnostics=[],
    )


def _failure(command: str, diagnostic: Diagnostic) -> tuple[int, ResultEnvelope]:
    return EXIT_INPUT, ResultEnvelope(
        ok=False,
        command=command,
        result=None,
        diagnostics=[diagnostic],
    )


def _contains_symlink(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if is_path_link(current):
            return True
        if not current.exists():
            return False
    return False


def _init_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage init"
    target = Path(str(arguments.path)).expanduser().absolute()
    if _contains_symlink(target):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_PROJECT_SYMLINK",
                "Usage project destinations cannot contain symbolic links.",
            ),
        )
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_PROJECT_EXISTS",
                "Usage project directory already contains files.",
            ),
        )
    try:
        target.mkdir(parents=True, exist_ok=True)
        for relative_path in _USAGE_DIRECTORIES:
            (target / relative_path).mkdir(parents=True)
    except OSError:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_INIT_FAILED",
                "Usage project directories could not be initialized.",
            ),
        )
    return _success(command, {"initialized": True})


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _baseline_matches(
    acceptance: McpReleaseAcceptance,
    index: DomainUsageIndex,
    contract: DomainUsageContract,
    snapshot_digest: str,
) -> bool:
    return (
        index.mcp_release_id == acceptance.release_id
        and index.pack_digest == acceptance.pack_digest == contract.pack_digest
        and index.ir_digest == acceptance.ir_digest == contract.ir_digest
        and index.tool_schema_digest == acceptance.tool_schema_digest == contract.tool_schema_digest
        and index.test_report_digest == acceptance.test_report_digest == contract.test_report_digest
        and index.source_snapshot_digest == contract.source_snapshot_digest == snapshot_digest
    )


def _latest_decision(report: UsageProjectReport, domain_id: str) -> UsageDomainDecision | None:
    return max(
        (
            decision
            for (decision_domain, _revision), decision in report.decisions.items()
            if decision_domain == domain_id
        ),
        key=lambda decision: decision.revision,
        default=None,
    )


def _review_closure(
    report: UsageProjectReport, domain_id: str
) -> tuple[DomainUsageContract, UsageDomainDecision, str] | None:
    acceptance = report.acceptance
    index = report.domain_index
    snapshot = report.source_snapshot
    contract = report.domain_contracts.get(domain_id)
    decision = _latest_decision(report, domain_id)
    if (
        acceptance is None
        or index is None
        or snapshot is None
        or contract is None
        or decision is None
        or domain_id not in index.domain_ids
        or domain_id not in acceptance.accepted_domain_ids
    ):
        return None
    snapshot_digest = _canonical_digest(snapshot.model_dump(mode="json"))
    contract_digest = _canonical_digest(contract.model_dump(mode="json"))
    goal_ids = {goal.id for goal in contract.business_goals}
    route_by_id = {route.id: route for route in contract.tool_routes}
    selected_routes = {
        route_id: route_by_id[route_id]
        for route_id in decision.included_route_ids
        if route_id in route_by_id
    }
    if (
        not _baseline_matches(acceptance, index, contract, snapshot_digest)
        or decision.disposition != "accepted"
        or decision.contract_digest != contract_digest
        or not set(decision.business_goal_ids) <= goal_ids
        or set(selected_routes) != set(decision.included_route_ids)
        or {route.business_goal_id for route in selected_routes.values()}
        != set(decision.business_goal_ids)
    ):
        return None
    return contract, decision, snapshot_digest


def _release_closure(report: UsageProjectReport, domain_id: str) -> bool:
    review = _review_closure(report, domain_id)
    acceptance = report.acceptance
    index = report.domain_index
    if review is None or acceptance is None or index is None:
        return False
    contract, decision, snapshot_digest = review
    references = [
        reference for reference in index.published_releases if reference.domain_id == domain_id
    ]
    if len(references) != 1:
        return False
    release = report.releases.get(references[0].usage_release_id)
    if release is None:
        return False
    scenario_ids = set(release.scenario_ids)
    scenarios = [report.scenarios.get(scenario_id) for scenario_id in release.scenario_ids]
    return _exact_release_matches(
        release,
        acceptance=acceptance,
        contract=contract,
        decision=decision,
        snapshot_digest=snapshot_digest,
        scenarios=scenarios,
        scenario_ids=scenario_ids,
    )


def _exact_release_matches(
    release: AgentUsageRelease,
    *,
    acceptance: McpReleaseAcceptance,
    contract: DomainUsageContract,
    decision: UsageDomainDecision,
    snapshot_digest: str,
    scenarios: Sequence[object | None],
    scenario_ids: set[str],
) -> bool:
    selected_routes = set(decision.included_route_ids)
    return (
        release.domain_id == decision.domain_id
        and release.release_status == "released"
        and release.mcp_release_id == acceptance.release_id
        and release.pack_digest == acceptance.pack_digest
        and release.ir_digest == acceptance.ir_digest
        and release.tool_schema_digest == acceptance.tool_schema_digest
        and release.test_report_digest == acceptance.test_report_digest
        and release.source_snapshot_digest == snapshot_digest
        and release.contract_digest == decision.contract_digest
        and release.decision_digest == decision.decision_digest
        and set(release.business_goal_ids) == set(decision.business_goal_ids)
        and set(release.route_ids) == selected_routes
        and set(contract.required_scenario_ids) <= scenario_ids
        and all(
            scenario is not None
            and getattr(scenario, "domain_id", None) == decision.domain_id
            and getattr(scenario, "route_id", None) in selected_routes
            for scenario in scenarios
        )
        and release.verification.source_usage_traced
        and release.verification.usage_contract_verified
        and release.verification.headless_agent_verified
        and release.verification.real_mcp_verified
        and release.verification.user_accepted
    )


def status_usage_domains(report: UsageProjectReport) -> Mapping[str, Any]:
    """Return deterministic domain progress without exposing evidence or identities."""

    index = report.domain_index
    if index is None:
        return {"domains": [], "next_domain": None}
    domain_rows: list[dict[str, Any]] = []
    next_domain: str | None = None
    dependency_ids_by_domain = {domain.id: domain.dependency_domain_ids for domain in index.domains}
    release_state = {
        domain_id: _release_closure(report, domain_id) for domain_id in index.domain_ids
    }
    for domain_id in index.preferred_order:
        if release_state[domain_id]:
            state = "released"
        elif _review_closure(report, domain_id) is not None:
            state = "reviewed"
        elif domain_id in report.domain_contracts:
            state = "scanned"
        else:
            state = "pending"
        dependency_ready = all(
            release_state[dependency_id] for dependency_id in dependency_ids_by_domain[domain_id]
        )
        if next_domain is None and state != "released" and dependency_ready:
            next_domain = domain_id
        domain_rows.append(
            {
                "domain_id": domain_id,
                "state": state,
                "dependency_ready": dependency_ready,
            }
        )
    return {"domains": domain_rows, "next_domain": next_domain}


def _status_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage status"
    report = validate_usage_project(Path(str(arguments.path)).expanduser().absolute())
    if not report.ok:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_STATUS_PROJECT_INVALID",
                "Usage status is unavailable while project validation has errors.",
            ),
        )
    if report.domain_index is None:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_STATUS_UNAVAILABLE",
                "Usage status requires a valid domain index.",
                path="domain-index.yaml",
            ),
        )
    return _success(command, status_usage_domains(report))


def _safe_manifest_path(value: str) -> bool:
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return bool(
        value
        and "\\" not in value
        and not posix.is_absolute()
        and not windows.is_absolute()
        and not windows.drive
        and ".." not in posix.parts
        and "." not in posix.parts
    )


def _safe_manifest_identifier(value: str) -> bool:
    try:
        _IDENTIFIER_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        return False
    return True


def _manifest_valid(
    value: object,
    domain_id: str,
    *,
    accepted_domain_ids: set[str],
    indexed_domain_ids: set[str],
) -> bool:
    if not isinstance(value, Mapping) or set(value) != _MANIFEST_FIELDS:
        return False
    if value.get("domain_id") != domain_id:
        return False
    for field in _MANIFEST_LIST_FIELDS:
        items = value.get(field)
        if (
            not isinstance(items, list)
            or not all(isinstance(item, str) and item for item in items)
            or items != sorted(set(items))
        ):
            return False
        if field.endswith("_include_paths") and not all(
            _safe_manifest_path(item) for item in items
        ):
            return False
        if field.endswith("_refs") and not all(_safe_manifest_identifier(item) for item in items):
            return False
    dependencies = value.get("direct_dependency_domain_ids")
    return (
        isinstance(dependencies, list)
        and domain_id not in dependencies
        and set(dependencies) <= accepted_domain_ids
        and set(dependencies) <= indexed_domain_ids
    )


def _scan_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage scan"
    if not bool(arguments.check):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_CHECK_REQUIRED",
                "The Usage scan foundation only supports read-only --check.",
            ),
        )
    root = Path(str(arguments.project)).expanduser().absolute()
    domain_id = str(arguments.domain)
    report = validate_usage_project(root)
    blocking_diagnostics = [
        diagnostic
        for diagnostic in report.diagnostics
        if diagnostic.severity == "error"
        and (diagnostic.code, diagnostic.path) not in _SCAN_EXPECTED_MISSING_DIAGNOSTICS
    ]
    if blocking_diagnostics:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_SCAN_PROJECT_INVALID",
                "Usage scan is unavailable while project validation has safety or schema errors.",
            ),
        )
    if (
        report.project is None
        or report.acceptance is None
        or report.domain_index is None
        or domain_id not in report.acceptance.accepted_domain_ids
        or domain_id not in report.domain_index.domain_ids
    ):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_SCAN_PREREQUISITE_MISSING",
                "Usage scan check requires a typed acceptance covering the selected domain.",
            ),
        )
    try:
        manifest = load_project_object(root, "usage-scan-manifest.yaml")
    except ProjectIOError:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_SCAN_MANIFEST_INVALID",
                "Usage scan check requires a safe, valid domain manifest.",
                path="usage-scan-manifest.yaml",
            ),
        )
    if not _manifest_valid(
        manifest,
        domain_id,
        accepted_domain_ids=set(report.acceptance.accepted_domain_ids),
        indexed_domain_ids=set(report.domain_index.domain_ids),
    ):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_SCAN_MANIFEST_INVALID",
                "Usage scan check requires a safe, valid domain manifest.",
                path="usage-scan-manifest.yaml",
            ),
        )
    return _success(
        command,
        {"domain_id": domain_id, "manifest_valid": True, "ready": True},
    )


def check_usage_domain_review(report: UsageProjectReport, domain_id: str) -> tuple[Diagnostic, ...]:
    """Check the typed decision, accepted baseline, contract, goals, and routes."""

    if _review_closure(report, domain_id) is not None:
        return ()
    return (
        _diagnostic(
            "ACC_USAGE_REVIEW_CLOSURE_INVALID",
            "Usage review requires an exact typed decision and contract closure.",
        ),
    )


def _review_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage review"
    if not bool(arguments.check):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_CHECK_REQUIRED",
                "Usage review is read-only and requires --check.",
            ),
        )
    domain_id = str(arguments.domain)
    report = validate_usage_project(Path(str(arguments.project)).expanduser().absolute())
    diagnostics = check_usage_domain_review(report, domain_id)
    if diagnostics:
        return _failure(command, diagnostics[0])
    return _success(
        command,
        {"decision_valid": True, "domain_id": domain_id, "review_valid": True},
    )


def _project_root(value: object) -> Path:
    return Path(str(value)).expanduser().absolute()


def _confined_path(root: Path, value: object) -> tuple[Path, str] | None:
    """Resolve an explicit path lexically inside a non-symlinked Usage project."""

    if _contains_symlink(root) or not root.is_dir():
        return None
    raw = Path(str(value)).expanduser()
    candidate = raw if raw.is_absolute() else root / raw
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if not relative.parts or ".." in relative.parts or _contains_symlink(candidate):
        return None
    return candidate, relative.as_posix()


def _safe_input_path(root: Path, value: object) -> Path | None:
    raw = Path(str(value)).expanduser()
    candidate = (raw if raw.is_absolute() else root / raw).absolute()
    if _contains_symlink(candidate) or not candidate.is_file():
        return None
    return candidate


def _atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _contains_symlink(path) or path.is_symlink():
        raise OSError("unsafe output path")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        if _contains_symlink(path) or path.is_symlink():
            raise OSError("unsafe output path")
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _unsafe_output(command: str) -> tuple[int, ResultEnvelope]:
    return _failure(
        command,
        _diagnostic(
            "ACC_USAGE_OUTPUT_UNSAFE",
            "Usage output must be an explicit non-symlink path inside the Usage project.",
        ),
    )


def _external_regular_path(value: object) -> Path | None:
    path = Path(str(value)).expanduser().absolute()
    if _contains_symlink(path) or not path.is_file():
        return None
    return path


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _verified_usage_bundle(
    arguments: argparse.Namespace,
    *,
    command: str,
    root: Path,
    domain_id: str,
    report: UsageProjectReport,
) -> tuple[VerifiedUsageReleaseBundle | None, Diagnostic | None]:
    artifact = _external_regular_path(arguments.verification_artifact)
    trust_store = _external_regular_path(arguments.verification_trust_store)
    pack = _external_regular_path(arguments.accepted_pack)
    tools_path = _external_regular_path(arguments.accepted_tools)
    test_report = _external_regular_path(arguments.accepted_test_report)
    if None in (artifact, trust_store, pack, tools_path, test_report):
        return None, _diagnostic(
            "ACC_USAGE_VERIFICATION_INPUT_INVALID",
            "Verification inputs must be stable regular non-link files.",
        )
    assert artifact is not None
    assert trust_store is not None
    assert pack is not None
    assert tools_path is not None
    assert test_report is not None
    source_root = root
    if report.project is not None:
        source_root = (root / report.project.source_workspace.path).absolute()
    acc_root = pack.parent.parent if pack.parent.name == "dist" else pack.parent
    if any(_within(trust_store, item) for item in (root, source_root, acc_root)):
        return None, _diagnostic(
            "ACC_USAGE_VERIFICATION_TRUST_LOCATION_INVALID",
            "Verification trust store must be outside Usage, source, and ACC project roots.",
        )
    if report.acceptance is None:
        return None, _diagnostic(
            "ACC_USAGE_VERIFICATION_ACCEPTANCE_MISSING", "Accepted MCP release is missing."
        )
    try:
        tools = json.loads(tools_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, _diagnostic(
            "ACC_USAGE_VERIFICATION_INPUT_INVALID", "Accepted tool snapshot is invalid."
        )
    accepted = verify_mcp_release_acceptance(
        acceptance=report.acceptance,
        pack_path=pack,
        tool_snapshot=tools,
        test_report_path=test_report,
    )
    if not accepted.ok or not accepted.trusted:
        return None, _diagnostic(accepted.code, accepted.message)
    try:
        bundle = load_usage_verification_artifact(
            artifact,
            trust_store=trust_store,
            report=report,
            acceptance=report.acceptance,
            domain_id=domain_id,
        )
    except UsageVerificationArtifactError as exc:
        return None, _diagnostic(exc.code, str(exc))
    return bundle, None


def _build_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage build"
    root = _project_root(arguments.project)
    domain_id = str(arguments.domain)
    output = _confined_path(root, arguments.output)
    if output is None:
        return _unsafe_output(command)
    required_inputs = (
        "verification_artifact",
        "verification_trust_store",
        "accepted_pack",
        "accepted_tools",
        "accepted_test_report",
        "package_signing_secret_env",
    )
    if any(not getattr(arguments, name, None) for name in required_inputs):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_BUILD_EVIDENCE_NOT_PROVISIONED",
                "Usage build requires a trusted verification artifact and configured signer.",
            ),
        )
    report = validate_usage_project(root)
    if not report.ok:
        return _failure(
            command,
            _diagnostic("ACC_USAGE_BUILD_PROJECT_INVALID", "Usage project is invalid."),
        )
    bundle, diagnostic = _verified_usage_bundle(
        arguments, command=command, root=root, domain_id=domain_id, report=report
    )
    if diagnostic is not None or bundle is None:
        return _failure(
            command,
            diagnostic
            or _diagnostic("ACC_USAGE_VERIFICATION_UNTRUSTED", "Untrusted verification."),
        )
    secret_name = str(arguments.package_signing_secret_env)
    encoded_secret = os.environ.get(secret_name)
    try:
        secret = base64.b64decode(encoded_secret or "", validate=True)
        signer = UsagePackageSigner(secret)
        result = build_usage_package(root, output[0], verified_releases=(bundle,), signer=signer)
    except (OSError, TypeError, ValueError):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_BUILD_SIGNING_FAILED",
                "Usage package signing secret or output is invalid.",
            ),
        )
    return _success(
        command,
        {"domain_id": domain_id, "output": output[1], "sha256": result.sha256},
    )


def _test_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage test"
    if not bool(arguments.check):
        return _failure(
            command,
            _diagnostic("ACC_USAGE_CHECK_REQUIRED", "Usage test requires read-only --check."),
        )
    root = _project_root(arguments.project)
    domain_id = str(arguments.domain)
    report = validate_usage_project(root)
    review = _review_closure(report, domain_id)
    if not report.ok or review is None or report.domain_index is None:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_TEST_PREREQUISITE_INVALID",
                "Usage test requires a valid accepted domain review closure.",
            ),
        )
    release_claim = False
    for reference in report.domain_index.published_releases:
        if reference.domain_id == domain_id:
            release = report.releases.get(reference.usage_release_id)
            release_claim = bool(release and release.verification.real_mcp_verified)
    # No live runner is part of acc-core. Serialized release claims are never
    # upgraded into fresh headless or real-transport evidence by this command.
    return _success(
        command,
        {
            "domain_id": domain_id,
            "headless_agent": "not_provisioned",
            "real_mcp": "not_provisioned",
            "release_claims_real_mcp": release_claim,
            "review_closure": "passed",
        },
    )


def _impact_document(impact: UsageImpactReport, *, output: str | None) -> dict[str, object]:
    domains = [
        {
            "action_capability_ids": list(item.action_capability_ids),
            "capability_ids": list(item.capability_ids),
            "contract_digest_after": item.contract_digest_after,
            "contract_digest_before": item.contract_digest_before,
            "domain_id": item.domain_id,
            "evidence_source_ids": list(item.evidence_source_ids),
            "route_ids": list(item.route_ids),
            "scenario_ids": list(item.scenario_ids),
            "status": item.status.value,
            "step_ids": list(item.step_ids),
            "tool_names": list(item.tool_names),
            "upstream_domain_ids": list(item.upstream_domain_ids),
        }
        for item in impact.domains
    ]
    return {
        "domains": domains,
        "graph_status": impact.graph_status,
        "output": output,
        "pack_digest_after": impact.pack_digest_after,
        "pack_digest_before": impact.pack_digest_before,
        "source_snapshot_digest_after": impact.source_snapshot_digest_after,
        "source_snapshot_digest_before": impact.source_snapshot_digest_before,
        "test_report_digest_after": impact.test_report_digest_after,
        "test_report_digest_before": impact.test_report_digest_before,
        "tool_schema_digest_after": impact.tool_schema_digest_after,
        "tool_schema_digest_before": impact.tool_schema_digest_before,
    }


def _impact_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage impact"
    root = _project_root(arguments.project)
    if not _safe_manifest_path(str(arguments.change_set)):
        return _failure(
            command,
            _diagnostic("ACC_USAGE_CHANGE_SET_INVALID", "Usage change set path is unsafe."),
        )
    report = validate_usage_project(root)
    if not report.ok:
        return _failure(
            command,
            _diagnostic("ACC_USAGE_IMPACT_PROJECT_INVALID", "Usage impact project is invalid."),
        )
    try:
        document = load_project_object(root, str(arguments.change_set))
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema_version", "before", "after"}
            or document["schema_version"] != "2"
        ):
            raise ValueError
        before = UsageSnapshot.model_validate(document["before"])
        after = UsageSnapshot.model_validate(document["after"])
        impact = analyze_usage_impact(before=before, after=after, report=report)
    except (ProjectIOError, ValidationError, ValueError, TypeError):
        return _failure(
            command,
            _diagnostic("ACC_USAGE_CHANGE_SET_INVALID", "Usage change set is invalid."),
        )
    output_value = getattr(arguments, "output", None)
    output: tuple[Path, str] | None = None
    if output_value is not None:
        output = _confined_path(root, output_value)
        if output is None:
            return _unsafe_output(command)
    result = _impact_document(impact, output=None if output is None else output[1])
    if output is not None:
        try:
            contents = (
                json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            _atomic_write(output[0], contents)
        except (OSError, TypeError, ValueError):
            return _failure(
                command,
                _diagnostic("ACC_USAGE_IMPACT_WRITE_FAILED", "Usage impact output failed."),
            )
    return _success(command, result)


def _release_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage release"
    if not bool(arguments.check):
        return _failure(
            command,
            _diagnostic("ACC_USAGE_CHECK_REQUIRED", "Usage release requires read-only --check."),
        )
    root = _project_root(arguments.project)
    domain_id = str(arguments.domain)
    report = validate_usage_project(root)
    release: AgentUsageRelease | None = None
    if report.domain_index is not None:
        for reference in report.domain_index.published_releases:
            if reference.domain_id == domain_id:
                release = report.releases.get(reference.usage_release_id)
    if release is None or not report.ok or not _release_closure(report, domain_id):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_RELEASE_GATES_FAILED",
                "Usage release requires every independent required verification gate.",
            ),
        )
    required_inputs = (
        "verification_artifact",
        "verification_trust_store",
        "accepted_pack",
        "accepted_tools",
        "accepted_test_report",
    )
    if any(not getattr(arguments, name, None) for name in required_inputs):
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_RELEASE_EVIDENCE_NOT_PROVISIONED",
                "Trace-derived Usage release evidence is not provisioned for CLI verification.",
            ),
        )
    bundle, diagnostic = _verified_usage_bundle(
        arguments, command=command, root=root, domain_id=domain_id, report=report
    )
    if diagnostic is not None or bundle is None:
        return _failure(
            command,
            diagnostic
            or _diagnostic("ACC_USAGE_VERIFICATION_UNTRUSTED", "Untrusted verification."),
        )
    return _success(
        command,
        {
            "domain_id": domain_id,
            "release_id": bundle.release.usage_release_id,
            "verification": "trusted_artifact",
        },
    )


def _export_usage(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    command = "usage export"
    root = _project_root(arguments.project)
    package_path = _safe_input_path(root, arguments.package)
    output = _confined_path(root, arguments.output)
    if output is None:
        return _unsafe_output(command)
    if package_path is None:
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_PACKAGE_INPUT_UNSAFE",
                "Usage export requires a regular non-symlink Agent Usage package.",
            ),
        )
    if str(arguments.adapter) != "generic-markdown":
        return _failure(
            command,
            _diagnostic(
                "ACC_USAGE_ADAPTER_UNSUPPORTED",
                "The requested Agent Usage adapter is not available.",
            ),
        )
    del package_path, output
    return _failure(
        command,
        _diagnostic(
            "ACC_USAGE_EXPORT_TRUST_NOT_PROVISIONED",
            "Usage export requires an explicit trusted signer or public-key root.",
        ),
    )


def handle_usage_command(arguments: argparse.Namespace) -> tuple[int, ResultEnvelope]:
    """Route one Usage command without invoking Capability compile, pack, or run."""

    handlers = {
        "build": _build_usage,
        "export": _export_usage,
        "impact": _impact_usage,
        "init": _init_usage,
        "release": _release_usage,
        "status": _status_usage,
        "scan": _scan_usage,
        "review": _review_usage,
        "test": _test_usage,
    }
    return handlers[str(arguments.usage_command)](arguments)


__all__ = [
    "check_usage_domain_review",
    "handle_usage_command",
    "status_usage_domains",
]
