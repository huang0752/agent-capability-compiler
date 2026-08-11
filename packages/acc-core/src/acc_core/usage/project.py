"""Safely load and validate an independent Agent Usage project."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, TypeVar, cast

from pydantic import ValidationError

from acc_core.diagnostics import Diagnostic
from acc_core.io import ProjectIOError, load_project_object, resolve_project_path
from acc_core.models import Evidence, StrictModel
from acc_core.usage.models import (
    AgentUsageProject,
    AgentUsageRelease,
    DomainUsageContract,
    DomainUsageIndex,
    McpReleaseAcceptance,
    SourceSnapshot,
    UsageDomainDecision,
    UsageScenario,
)

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}
type _EvidenceLayerId = Literal["client", "service", "test", "mcp", "runtime_observation"]
_EVIDENCE_LAYERS: frozenset[_EvidenceLayerId] = frozenset(
    {"client", "service", "test", "mcp", "runtime_observation"}
)
_EVIDENCE_AUDIT_FIELDS = {"client_surface", "domain_id", "size_bytes", "source_layer"}
_CLIENT_SURFACES = {"web", "mobile", "desktop", "cli", "automation", "other"}
_SENSITIVE_KEY = re.compile(
    r"(^|[._-])(authorization|cookie|credential|jwt|password|secret|token)([._-]|$)",
    re.IGNORECASE,
)
_ModelT = TypeVar("_ModelT", bound=StrictModel)


@dataclass(frozen=True, slots=True)
class _EvidenceAudit:
    domain_id: str
    source_layer: _EvidenceLayerId
    client_surface: str | None
    size_bytes: int
    path: str


@dataclass(frozen=True, slots=True)
class UsageProjectReport:
    """Typed Usage documents and stable, secret-safe diagnostics."""

    root: Path
    project: AgentUsageProject | None
    acceptance: McpReleaseAcceptance | None
    source_snapshot: SourceSnapshot | None
    domain_index: DomainUsageIndex | None
    domain_contracts: Mapping[str, DomainUsageContract]
    scenarios: Mapping[str, UsageScenario]
    decisions: Mapping[tuple[str, int], UsageDomainDecision]
    releases: Mapping[str, AgentUsageRelease]
    evidence_registry: Mapping[str, Evidence]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


def _pointer(location: tuple[int | str, ...]) -> str:
    if not location:
        return ""
    tokens = [str(token).replace("~", "~0").replace("/", "~1") for token in location]
    return "/" + "/".join(tokens)


class _UsageProjectLoader:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.diagnostics: list[Diagnostic] = []
        self.paths: dict[tuple[str, object], str] = {}

    def _error(
        self,
        code: str,
        message: str,
        *,
        path: str | None,
        pointer: str | None = None,
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                severity="error",
                message=message,
                path=path,
                pointer=pointer,
            )
        )

    def _load_model(
        self,
        relative_path: str,
        model_type: type[_ModelT],
        *,
        invalid_code: str = "ACC_USAGE_SCHEMA_INVALID",
    ) -> _ModelT | None:
        try:
            document = load_project_object(self.root, relative_path)
            return model_type.model_validate(document)
        except ProjectIOError as exc:
            self._error(exc.code, str(exc), path=relative_path)
        except ValidationError as exc:
            for error in exc.errors(include_url=False, include_input=False):
                self._error(
                    invalid_code,
                    str(error.get("msg", "Document does not match its schema.")),
                    path=relative_path,
                    pointer=_pointer(tuple(error.get("loc", ()))),
                )
        return None

    def _document_paths(self, directory: str) -> list[str]:
        try:
            target = resolve_project_path(self.root, directory)
        except ProjectIOError as exc:
            self._error(exc.code, str(exc), path=directory)
            return []
        if not target.exists():
            return []
        if not target.is_dir():
            self._error(
                "ACC_USAGE_PROJECT_DIRECTORY_INVALID",
                "Expected a one-level Usage document directory.",
                path=directory,
            )
            return []

        paths: list[str] = []
        try:
            entries = sorted(target.iterdir(), key=lambda item: item.name)
        except OSError:
            self._error(
                "ACC_IO_ERROR",
                "Cannot inspect Usage project directory.",
                path=directory,
            )
            return []
        for entry in entries:
            relative_path = f"{directory}/{entry.name}"
            if entry.is_symlink():
                self._error(
                    "ACC_IO_SYMLINK_REJECTED",
                    "Symbolic links are forbidden in Usage project paths.",
                    path=relative_path,
                )
            elif not entry.is_file() or entry.suffix.lower() not in _DOCUMENT_SUFFIXES:
                self._error(
                    "ACC_USAGE_PROJECT_FILE_UNKNOWN",
                    "Unknown or nested Usage project document.",
                    path=relative_path,
                )
            else:
                paths.append(relative_path)
        return paths

    def _load_collection(
        self,
        directory: str,
        model_type: type[_ModelT],
        *,
        identity: Any,
        duplicate_code: str,
        invalid_code: str = "ACC_USAGE_SCHEMA_INVALID",
    ) -> dict[Any, _ModelT]:
        documents: dict[Any, _ModelT] = {}
        for relative_path in self._document_paths(directory):
            document = self._load_model(relative_path, model_type, invalid_code=invalid_code)
            if document is None:
                continue
            identifier = identity(document)
            if identifier in documents:
                self._error(
                    duplicate_code,
                    f"Duplicate {model_type.__name__} identity.",
                    path=relative_path,
                )
                continue
            documents[identifier] = document
            self.paths[(directory, identifier)] = relative_path
        return documents

    def _load_usage_evidence(self) -> tuple[dict[str, Evidence], dict[str, _EvidenceAudit]]:
        directory = "usage-evidence"
        try:
            target = resolve_project_path(self.root, directory)
        except ProjectIOError as exc:
            self._error(exc.code, str(exc), path=directory)
            return {}, {}
        if not target.exists():
            return {}, {}
        if not target.is_dir():
            self._error(
                "ACC_USAGE_PROJECT_DIRECTORY_INVALID",
                "Expected the Usage Evidence layer directory.",
                path=directory,
            )
            return {}, {}

        documents: dict[str, Evidence] = {}
        audits: dict[str, _EvidenceAudit] = {}
        try:
            layer_entries = sorted(target.iterdir(), key=lambda item: item.name)
        except OSError:
            self._error(
                "ACC_IO_ERROR",
                "Cannot inspect Usage Evidence directory.",
                path=directory,
            )
            return {}, {}
        for layer_entry in layer_entries:
            layer_path = f"{directory}/{layer_entry.name}"
            if layer_entry.is_symlink():
                self._error(
                    "ACC_IO_SYMLINK_REJECTED",
                    "Symbolic links are forbidden in Usage Evidence paths.",
                    path=layer_path,
                )
                continue
            if layer_entry.name not in _EVIDENCE_LAYERS or not layer_entry.is_dir():
                self._error(
                    "ACC_USAGE_EVIDENCE_LAYER_UNKNOWN",
                    "Usage Evidence must use a fixed platform-neutral source layer.",
                    path=layer_path,
                )
                continue
            try:
                evidence_entries = sorted(layer_entry.iterdir(), key=lambda item: item.name)
            except OSError:
                self._error(
                    "ACC_IO_ERROR",
                    "Cannot inspect Usage Evidence directory.",
                    path=layer_path,
                )
                continue
            for entry in evidence_entries:
                relative_path = f"{layer_path}/{entry.name}"
                if entry.is_symlink():
                    self._error(
                        "ACC_IO_SYMLINK_REJECTED",
                        "Symbolic links are forbidden in Usage Evidence paths.",
                        path=relative_path,
                    )
                    continue
                if not entry.is_file() or entry.suffix.lower() not in _DOCUMENT_SUFFIXES:
                    self._error(
                        "ACC_USAGE_PROJECT_FILE_UNKNOWN",
                        "Unknown or nested Usage Evidence document.",
                        path=relative_path,
                    )
                    continue
                try:
                    raw = load_project_object(self.root, relative_path)
                except ProjectIOError as exc:
                    self._error(exc.code, str(exc), path=relative_path)
                    continue
                extra_fields = set(raw) - set(Evidence.model_fields)
                if any(_SENSITIVE_KEY.search(field) for field in extra_fields):
                    self._error(
                        "ACC_USAGE_EVIDENCE_SECRET_REJECTED",
                        "Usage Evidence contains a secret-like audit field.",
                        path=relative_path,
                    )
                    continue
                if not extra_fields <= _EVIDENCE_AUDIT_FIELDS:
                    self._error(
                        "ACC_USAGE_EVIDENCE_AUDIT_INVALID",
                        "Usage Evidence contains a non-allowlisted audit field.",
                        path=relative_path,
                    )
                    continue
                domain_id = raw.get("domain_id")
                source_layer = raw.get("source_layer")
                size_bytes = raw.get("size_bytes")
                client_surface = raw.get("client_surface")
                audit_valid = (
                    isinstance(domain_id, str)
                    and bool(domain_id)
                    and source_layer == layer_entry.name
                    and isinstance(size_bytes, int)
                    and not isinstance(size_bytes, bool)
                    and size_bytes >= 0
                    and (
                        ("client_surface" not in raw and client_surface is None)
                        or (
                            source_layer == "client"
                            and isinstance(client_surface, str)
                            and client_surface in _CLIENT_SURFACES
                        )
                    )
                )
                if not audit_valid:
                    self._error(
                        "ACC_USAGE_EVIDENCE_AUDIT_INVALID",
                        "Usage Evidence audit fields do not match their source layer.",
                        path=relative_path,
                    )
                    continue
                assert isinstance(domain_id, str)
                assert source_layer in _EVIDENCE_LAYERS
                assert isinstance(size_bytes, int) and not isinstance(size_bytes, bool)
                assert client_surface is None or isinstance(client_surface, str)
                core = {key: value for key, value in raw.items() if key in Evidence.model_fields}
                try:
                    evidence = Evidence.model_validate(core)
                except ValidationError as exc:
                    for error in exc.errors(include_url=False, include_input=False):
                        self._error(
                            "ACC_USAGE_SCHEMA_INVALID",
                            str(error.get("msg", "Document does not match its schema.")),
                            path=relative_path,
                            pointer=_pointer(tuple(error.get("loc", ()))),
                        )
                    continue
                if evidence.source_id in documents:
                    self._error(
                        "ACC_USAGE_EVIDENCE_DUPLICATE",
                        "Duplicate Evidence identity.",
                        path=relative_path,
                        pointer="/source_id",
                    )
                    continue
                documents[evidence.source_id] = evidence
                audits[evidence.source_id] = _EvidenceAudit(
                    domain_id=domain_id,
                    source_layer=cast("_EvidenceLayerId", source_layer),
                    client_surface=client_surface,
                    size_bytes=size_bytes,
                    path=relative_path,
                )
                self.paths[(directory, evidence.source_id)] = relative_path
        return documents, audits

    def _empty_report(self, project: AgentUsageProject | None) -> UsageProjectReport:
        return UsageProjectReport(
            root=self.root,
            project=project,
            acceptance=None,
            source_snapshot=None,
            domain_index=None,
            domain_contracts=MappingProxyType({}),
            scenarios=MappingProxyType({}),
            decisions=MappingProxyType({}),
            releases=MappingProxyType({}),
            evidence_registry=MappingProxyType({}),
            diagnostics=tuple(self.diagnostics),
        )

    def load_and_validate(self) -> UsageProjectReport:
        project = self._load_model(
            "project.yaml",
            AgentUsageProject,
            invalid_code="ACC_USAGE_PROJECT_INVALID",
        )
        if project is None:
            return self._empty_report(project)

        acceptance = self._load_model("mcp-release-acceptance.yaml", McpReleaseAcceptance)
        source_snapshot = self._load_model("source-snapshot.yaml", SourceSnapshot)
        domain_index = self._load_model("domain-index.yaml", DomainUsageIndex)
        contracts = self._load_collection(
            "domain-usage-contracts",
            DomainUsageContract,
            identity=lambda value: value.domain_id,
            duplicate_code="ACC_USAGE_CONTRACT_DUPLICATE",
        )
        scenarios = self._load_collection(
            "scenarios",
            UsageScenario,
            identity=lambda value: value.scenario_id,
            duplicate_code="ACC_USAGE_SCENARIO_DUPLICATE",
        )
        decisions = self._load_collection(
            "domain-decisions",
            UsageDomainDecision,
            identity=lambda value: (value.domain_id, value.revision),
            duplicate_code="ACC_USAGE_DECISION_DUPLICATE",
        )
        releases = self._load_collection(
            "releases",
            AgentUsageRelease,
            identity=lambda value: value.usage_release_id,
            duplicate_code="ACC_USAGE_RELEASE_DUPLICATE",
        )
        evidence, evidence_audits = self._load_usage_evidence()

        self._validate_closure(
            acceptance=acceptance,
            source_snapshot=source_snapshot,
            domain_index=domain_index,
            contracts=contracts,
            scenarios=scenarios,
            decisions=decisions,
            releases=releases,
            evidence=evidence,
            evidence_audits=evidence_audits,
        )
        return UsageProjectReport(
            root=self.root,
            project=project,
            acceptance=acceptance,
            source_snapshot=source_snapshot,
            domain_index=domain_index,
            domain_contracts=MappingProxyType(contracts),
            scenarios=MappingProxyType(scenarios),
            decisions=MappingProxyType(decisions),
            releases=MappingProxyType(releases),
            evidence_registry=MappingProxyType(evidence),
            diagnostics=tuple(self.diagnostics),
        )

    def _validate_closure(
        self,
        *,
        acceptance: McpReleaseAcceptance | None,
        source_snapshot: SourceSnapshot | None,
        domain_index: DomainUsageIndex | None,
        contracts: Mapping[str, DomainUsageContract],
        scenarios: Mapping[str, UsageScenario],
        decisions: Mapping[tuple[str, int], UsageDomainDecision],
        releases: Mapping[str, AgentUsageRelease],
        evidence: Mapping[str, Evidence],
        evidence_audits: Mapping[str, _EvidenceAudit],
    ) -> None:
        # Cross-document validation is intentionally centralized here. Field-level
        # contracts remain in models.py and the Capability validator is never called.
        if acceptance is None or source_snapshot is None or domain_index is None:
            return
        snapshot_payload = json.dumps(
            source_snapshot.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        snapshot_digest = "sha256:" + hashlib.sha256(snapshot_payload).hexdigest()
        baseline_matches = (
            domain_index.mcp_release_id == acceptance.release_id
            and domain_index.pack_digest == acceptance.pack_digest
            and domain_index.ir_digest == acceptance.ir_digest
            and domain_index.tool_schema_digest == acceptance.tool_schema_digest
            and domain_index.test_report_digest == acceptance.test_report_digest
        )
        if not baseline_matches:
            self._error(
                "ACC_USAGE_BASELINE_MISMATCH",
                "Domain index does not bind the exact accepted MCP baseline.",
                path="domain-index.yaml",
            )
        if domain_index.source_snapshot_digest != snapshot_digest:
            self._error(
                "ACC_USAGE_SOURCE_SNAPSHOT_MISMATCH",
                "Domain index does not bind the loaded source snapshot.",
                path="domain-index.yaml",
                pointer="/source_snapshot_digest",
            )
        layers_by_id = {layer.source_layer: layer for layer in source_snapshot.evidence_layers}
        artifacts_by_layer: dict[_EvidenceLayerId, list[dict[str, str]]] = {}
        for source_id, audit in evidence_audits.items():
            artifacts_by_layer.setdefault(audit.source_layer, []).append(
                {"source_id": source_id, "digest": evidence[source_id].digest}
            )
            snapshot_layer = layers_by_id.get(audit.source_layer)
            if (
                audit.source_layer == "client"
                and audit.client_surface is not None
                and snapshot_layer is not None
                and snapshot_layer.client_surface != audit.client_surface
            ):
                self._error(
                    "ACC_USAGE_EVIDENCE_AUDIT_INVALID",
                    "Client Evidence surface does not match the source snapshot.",
                    path=audit.path,
                    pointer="/client_surface",
                )
        for layer_id, layer in layers_by_id.items():
            artifacts = sorted(
                artifacts_by_layer.get(layer_id, []),
                key=lambda item: item["source_id"],
            )
            if layer.status != "provided":
                if artifacts:
                    self._error(
                        "ACC_USAGE_EVIDENCE_LAYER_STATUS_INVALID",
                        "Unknown or not-applicable evidence layers cannot contain artifacts.",
                        path="source-snapshot.yaml",
                        pointer="/evidence_layers",
                    )
                continue
            layer_payload = json.dumps(
                artifacts,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            layer_digest = "sha256:" + hashlib.sha256(layer_payload).hexdigest()
            if not artifacts or layer.digest != layer_digest:
                self._error(
                    "ACC_USAGE_EVIDENCE_LAYER_DIGEST_MISMATCH",
                    "Provided evidence layer does not match its loaded artifact identities.",
                    path="source-snapshot.yaml",
                    pointer="/evidence_layers",
                )
        for layer_id in artifacts_by_layer:
            if layer_id not in layers_by_id:
                self._error(
                    "ACC_USAGE_EVIDENCE_LAYER_STATUS_INVALID",
                    "Evidence artifact layer is absent from the source snapshot.",
                    path="source-snapshot.yaml",
                    pointer="/evidence_layers",
                )
        accepted_domains = set(acceptance.accepted_domain_ids)
        for domain_id in domain_index.domain_ids:
            if domain_id not in accepted_domains:
                self._error(
                    "ACC_USAGE_DOMAIN_NOT_ACCEPTED",
                    "Usage domain is outside the accepted MCP release scope.",
                    path="domain-index.yaml",
                    pointer="/domain_ids",
                )

        indexed_domains = set(domain_index.domain_ids)
        published_domains = set(domain_index.published_domain_ids)
        active_release_by_domain = {
            reference.domain_id: reference.usage_release_id
            for reference in domain_index.published_releases
        }
        for domain_id in contracts:
            if domain_id not in indexed_domains:
                self._error(
                    "ACC_USAGE_CONTRACT_ORPHAN",
                    "Usage contract domain is absent from the domain index.",
                    path=self.paths.get(("domain-usage-contracts", domain_id)),
                    pointer="/domain_id",
                )
        for scenario_id, scenario in scenarios.items():
            if scenario.domain_id not in contracts:
                self._error(
                    "ACC_USAGE_SCENARIO_ORPHAN",
                    "Usage scenario has no matching domain contract.",
                    path=self.paths.get(("scenarios", scenario_id)),
                    pointer="/domain_id",
                )

        decisions_by_domain: dict[str, list[UsageDomainDecision]] = {}
        for key, decision in decisions.items():
            decisions_by_domain.setdefault(decision.domain_id, []).append(decision)
            if decision.domain_id not in indexed_domains:
                self._error(
                    "ACC_USAGE_DECISION_ORPHAN",
                    "Usage decision domain is absent from the domain index.",
                    path=self.paths.get(("domain-decisions", key)),
                    pointer="/domain_id",
                )
        for release_id, release in releases.items():
            if release.domain_id not in indexed_domains:
                self._error(
                    "ACC_USAGE_RELEASE_ORPHAN",
                    "Usage release domain is absent from the domain index.",
                    path=self.paths.get(("releases", release_id)),
                    pointer="/domain_id",
                )

        for domain_id, contract in contracts.items():
            if (
                contract.pack_digest != acceptance.pack_digest
                or contract.ir_digest != acceptance.ir_digest
                or contract.tool_schema_digest != acceptance.tool_schema_digest
                or contract.test_report_digest != acceptance.test_report_digest
            ):
                self._error(
                    "ACC_USAGE_BASELINE_MISMATCH",
                    "Usage contract does not bind the exact accepted MCP baseline.",
                    path=self.paths.get(("domain-usage-contracts", domain_id)),
                )
            if contract.source_snapshot_digest != snapshot_digest:
                self._error(
                    "ACC_USAGE_SOURCE_SNAPSHOT_MISMATCH",
                    "Usage contract does not bind the loaded source snapshot.",
                    path=self.paths.get(("domain-usage-contracts", domain_id)),
                    pointer="/source_snapshot_digest",
                )
            route_ids = {route.id for route in contract.tool_routes}
            for scenario_id in contract.required_scenario_ids:
                required_scenario = scenarios.get(scenario_id)
                if required_scenario is None or required_scenario.domain_id != domain_id:
                    self._error(
                        "ACC_USAGE_SCENARIO_UNKNOWN",
                        "Required Usage scenario is missing or belongs to another domain.",
                        path=self.paths.get(("domain-usage-contracts", domain_id)),
                        pointer="/required_scenario_ids",
                    )
                elif required_scenario.route_id not in route_ids:
                    self._error(
                        "ACC_USAGE_SCENARIO_UNKNOWN",
                        "Required Usage scenario references an unknown route.",
                        path=self.paths.get(("scenarios", scenario_id)),
                        pointer="/route_id",
                    )
            evidence_ids = set(evidence)
            for claim_index, claim in enumerate(contract.evidence_claims):
                unresolved = any(
                    reference.source_id not in evidence_ids
                    or evidence[reference.source_id].digest != reference.digest
                    or evidence_audits[reference.source_id].domain_id != domain_id
                    or evidence_audits[reference.source_id].source_layer != claim.source_layer
                    for reference in claim.evidence_refs
                )
                if unresolved:
                    self._error(
                        "ACC_USAGE_EVIDENCE_CLAIM_UNRESOLVED",
                        "Usage evidence claim references an unknown Evidence identity.",
                        path=self.paths.get(("domain-usage-contracts", domain_id)),
                        pointer=f"/evidence_claims/{claim_index}/evidence_refs",
                    )

        for domain_id in sorted(published_domains):
            published_contract = contracts.get(domain_id)
            if published_contract is None:
                self._error(
                    "ACC_USAGE_CONTRACT_MISSING",
                    "Indexed Usage domain has no contract.",
                    path="domain-index.yaml",
                    pointer="/domain_ids",
                )
            current_decision = max(
                decisions_by_domain.get(domain_id, []),
                key=lambda item: item.revision,
                default=None,
            )
            contract_digest: str | None = None
            goal_ids: set[str] = set()
            published_route_ids: set[str] = set()
            if published_contract is not None:
                contract_payload = json.dumps(
                    published_contract.model_dump(mode="json"),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                contract_digest = "sha256:" + hashlib.sha256(contract_payload).hexdigest()
                goal_ids = {goal.id for goal in published_contract.business_goals}
                published_route_ids = {route.id for route in published_contract.tool_routes}
            if (
                published_contract is None
                or current_decision is None
                or current_decision.disposition != "accepted"
                or current_decision.contract_digest != contract_digest
                or not set(current_decision.business_goal_ids) <= goal_ids
                or not set(current_decision.included_route_ids) <= published_route_ids
            ):
                self._error(
                    "ACC_USAGE_DECISION_MISSING",
                    "Published Usage domain requires a current accepted, contract-bound decision.",
                    path="domain-index.yaml",
                    pointer="/published_releases",
                )
            active_release_id = active_release_by_domain[domain_id]
            domain_release = releases.get(active_release_id)
            selected_goal_ids = (
                set(current_decision.business_goal_ids)
                if current_decision is not None and current_decision.disposition == "accepted"
                else set()
            )
            selected_route_ids = (
                set(current_decision.included_route_ids)
                if current_decision is not None and current_decision.disposition == "accepted"
                else set()
            )
            release_scenarios = (
                [scenarios.get(scenario_id) for scenario_id in domain_release.scenario_ids]
                if domain_release is not None
                else []
            )
            if (
                domain_release is None
                or domain_release.domain_id != domain_id
                or domain_release.release_status != "released"
                or domain_release.mcp_release_id != acceptance.release_id
                or domain_release.pack_digest != acceptance.pack_digest
                or domain_release.ir_digest != acceptance.ir_digest
                or domain_release.tool_schema_digest != acceptance.tool_schema_digest
                or domain_release.test_report_digest != acceptance.test_report_digest
                or domain_release.source_snapshot_digest != snapshot_digest
                or published_contract is None
                or current_decision is None
                or current_decision.disposition != "accepted"
                or domain_release.contract_digest != contract_digest
                or domain_release.decision_digest != current_decision.decision_digest
                or set(domain_release.business_goal_ids) != selected_goal_ids
                or set(domain_release.route_ids) != selected_route_ids
                or not set(published_contract.required_scenario_ids)
                <= set(domain_release.scenario_ids)
                or any(
                    scenario is None
                    or scenario.domain_id != domain_id
                    or scenario.route_id not in selected_route_ids
                    for scenario in release_scenarios
                )
            ):
                self._error(
                    "ACC_USAGE_RELEASE_GATE_FAILED",
                    "Published Usage domain requires its exact active release.",
                    path="domain-index.yaml",
                    pointer="/published_releases",
                )


def validate_usage_project(project_root: str | Path = ".") -> UsageProjectReport:
    """Load one independent Usage project without invoking Capability validation."""

    return _UsageProjectLoader(Path(project_root)).load_and_validate()


__all__ = ["UsageProjectReport", "validate_usage_project"]
