"""Deterministic, secret-safe staleness analysis for Agent Usage domains."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, JsonValue, field_validator, model_validator

from acc_core.models import Sha256Digest, StrictModel
from acc_core.usage.project import UsageProjectReport


def _sorted_unique(values: Sequence[str], *, name: str) -> list[str]:
    if values != sorted(set(values)):
        raise ValueError(f"{name} must be sorted and unique")
    return list(values)


class UsageToolSchema(StrictModel):
    """Bounded public input/output schemas captured from one MCP Tool."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]


class UsageSnapshot(StrictModel):
    """Digest-only baseline plus Tool schemas needed for local impact analysis."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    schema_version: Literal["2"]
    pack_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    test_report_digest: Sha256Digest
    source_snapshot_digest: Sha256Digest
    contract_digests: dict[str, Sha256Digest]
    capability_ids: list[str]
    tool_schemas: dict[str, UsageToolSchema]
    evidence_digests: dict[str, Sha256Digest]
    action_proof_digests: dict[str, Sha256Digest]

    @field_validator("capability_ids")
    @classmethod
    def validate_capability_ids(cls, value: list[str]) -> list[str]:
        return _sorted_unique(value, name="capability_ids")

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        mappings: tuple[tuple[str, Mapping[str, object]], ...] = (
            ("contract_digests", self.contract_digests),
            ("tool_schemas", self.tool_schemas),
            ("evidence_digests", self.evidence_digests),
            ("action_proof_digests", self.action_proof_digests),
        )
        for name, values in mappings:
            if any(not key or key != key.strip() for key in values):
                raise ValueError(f"{name} keys must be non-empty normalized identifiers")
        return self


class UsageImpactStatus(StrEnum):
    UNAFFECTED = "unaffected"
    REVALIDATE = "revalidate"
    REGENERATE = "regenerate"
    BLOCKED = "blocked"


_PRECEDENCE = {
    UsageImpactStatus.UNAFFECTED: 0,
    UsageImpactStatus.REVALIDATE: 1,
    UsageImpactStatus.REGENERATE: 2,
    UsageImpactStatus.BLOCKED: 3,
}


def _maximum_status(*statuses: UsageImpactStatus) -> UsageImpactStatus:
    return max(statuses, key=_PRECEDENCE.__getitem__)


@dataclass(frozen=True, slots=True)
class UsageDomainImpact:
    """One domain result containing identities and digests, never source values."""

    domain_id: str
    status: UsageImpactStatus
    contract_digest_before: str | None
    contract_digest_after: str | None
    scenario_ids: tuple[str, ...]
    route_ids: tuple[str, ...]
    step_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    action_capability_ids: tuple[str, ...]
    tool_names: tuple[str, ...]
    evidence_source_ids: tuple[str, ...]
    upstream_domain_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UsageImpactReport:
    """Stable local impact projection ordered by domain identity."""

    domains: tuple[UsageDomainImpact, ...]
    graph_status: Literal["valid", "invalid"]
    pack_digest_before: str
    pack_digest_after: str
    tool_schema_digest_before: str
    tool_schema_digest_after: str
    source_snapshot_digest_before: str
    source_snapshot_digest_after: str
    test_report_digest_before: str
    test_report_digest_after: str

    def domain(self, domain_id: str) -> UsageDomainImpact:
        for item in self.domains:
            if item.domain_id == domain_id:
                return item
        raise KeyError(domain_id)


@dataclass(frozen=True, slots=True)
class _DomainGraph:
    scenario_ids: tuple[str, ...]
    route_ids: tuple[str, ...]
    step_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    action_capability_ids: tuple[str, ...]
    tool_names: tuple[str, ...]
    evidence_source_ids: tuple[str, ...]
    direct_dependency_domain_ids: tuple[str, ...]
    graph_invalid: bool


def _index_dependencies(report: UsageProjectReport) -> tuple[dict[str, tuple[str, ...]], set[str]]:
    """Read the typed DomainIndex dependency graph without creating another authority."""

    index = report.domain_index
    if index is None:
        return {}, set(report.domain_contracts)
    entries = getattr(index, "domains", ())
    dependencies: dict[str, tuple[str, ...]] = {}
    invalid: set[str] = set()
    for entry in entries:
        domain_id = getattr(entry, "id", None)
        direct = getattr(entry, "dependency_domain_ids", None)
        if not isinstance(domain_id, str) or not isinstance(direct, list | tuple):
            continue
        if any(not isinstance(item, str) for item in direct):
            invalid.add(domain_id)
            continue
        if list(direct) != sorted(set(direct)):
            invalid.add(domain_id)
            continue
        dependencies[domain_id] = tuple(direct)
    invalid.update(set(report.domain_contracts) - dependencies.keys())
    if set(dependencies) != set(report.domain_contracts):
        invalid.update(report.domain_contracts)
    return dependencies, invalid


def _build_graph(report: UsageProjectReport) -> tuple[dict[str, _DomainGraph], bool]:
    dependencies, invalid_domains = _index_dependencies(report)
    known_domains = set(report.domain_contracts)
    if not report.ok:
        invalid_domains.update(known_domains)
    if any(scenario.domain_id not in known_domains for scenario in report.scenarios.values()):
        invalid_domains.update(known_domains)
    graph: dict[str, _DomainGraph] = {}
    for domain_id, contract in sorted(report.domain_contracts.items()):
        routes = {route.id: route for route in contract.tool_routes}
        scenarios = {
            scenario.scenario_id: scenario
            for scenario in report.scenarios.values()
            if scenario.domain_id == domain_id
        }
        scenario_ids = tuple(
            sorted(
                scenario.scenario_id
                for scenario in scenarios.values()
                if scenario.route_id in routes
            )
        )
        capability_ids = tuple(
            sorted({step.capability_id for route in routes.values() for step in route.steps})
        )
        step_ids = tuple(sorted({step.id for route in routes.values() for step in route.steps}))
        action_capability_ids = tuple(
            sorted(
                {
                    step.capability_id
                    for route in routes.values()
                    for step in route.steps
                    if step.action_phase is not None
                }
            )
        )
        tool_names = tuple(
            sorted({step.tool_name for route in routes.values() for step in route.steps})
        )
        evidence_source_ids = tuple(
            sorted(
                {
                    evidence.source_id
                    for claim in contract.evidence_claims
                    for evidence in claim.evidence_refs
                }
            )
        )
        direct = dependencies.get(domain_id, ())
        scenario_graph_invalid = not set(contract.required_scenario_ids) <= scenarios.keys() or any(
            scenario.route_id not in routes for scenario in scenarios.values()
        )
        evidence_graph_invalid = any(
            reference.source_id not in report.evidence_registry
            or report.evidence_registry[reference.source_id].digest != reference.digest
            for claim in contract.evidence_claims
            for reference in claim.evidence_refs
        )
        graph[domain_id] = _DomainGraph(
            scenario_ids=scenario_ids,
            route_ids=tuple(sorted(routes)),
            step_ids=step_ids,
            capability_ids=capability_ids,
            action_capability_ids=action_capability_ids,
            tool_names=tool_names,
            evidence_source_ids=evidence_source_ids,
            direct_dependency_domain_ids=direct,
            graph_invalid=(
                domain_id in invalid_domains
                or contract.domain_id != domain_id
                or any(item not in known_domains or item == domain_id for item in direct)
                or scenario_graph_invalid
                or evidence_graph_invalid
            ),
        )
    return graph, bool(graph) and not any(item.graph_invalid for item in graph.values())


_UNSUPPORTED_SCHEMA_KEYS = frozenset(
    {"$dynamicRef", "$ref", "allOf", "anyOf", "if", "not", "oneOf", "then", "else"}
)


def _schema_supported(value: JsonValue) -> bool:
    pending: list[JsonValue] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if _UNSUPPORTED_SCHEMA_KEYS & item.keys():
                return False
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return True


def _object_shape(schema: Mapping[str, JsonValue]) -> tuple[dict[str, JsonValue], set[str]] | None:
    if not _schema_supported(dict(schema)) or schema.get("type") != "object":
        return None
    properties = schema.get("properties")
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        return None
    required_ids: set[str] = set()
    for item in required:
        if not isinstance(item, str):
            return None
        required_ids.add(item)
    if not required_ids <= properties.keys():
        return None
    return properties, required_ids


def _classify_tool_schema(before: UsageToolSchema, after: UsageToolSchema) -> UsageImpactStatus:
    if before == after:
        return UsageImpactStatus.UNAFFECTED
    before_input = _object_shape(before.input_schema)
    after_input = _object_shape(after.input_schema)
    before_output = _object_shape(before.output_schema)
    after_output = _object_shape(after.output_schema)
    if any(item is None for item in (before_input, after_input, before_output, after_output)):
        return UsageImpactStatus.BLOCKED
    assert before_input is not None
    assert after_input is not None
    assert before_output is not None
    assert after_output is not None
    if before.input_schema != after.input_schema:
        return UsageImpactStatus.REGENERATE
    before_properties, before_required = before_output
    after_properties, after_required = after_output
    retained = set(before_properties)
    additions = set(after_properties) - retained
    if (
        retained <= after_properties.keys()
        and all(before_properties[key] == after_properties[key] for key in retained)
        and before_required == after_required
        and not (additions & after_required)
    ):
        return UsageImpactStatus.REVALIDATE
    return UsageImpactStatus.REGENERATE


def _direct_status(
    *,
    domain_id: str,
    graph: _DomainGraph,
    before: UsageSnapshot,
    after: UsageSnapshot,
) -> UsageImpactStatus:
    if graph.graph_invalid:
        return UsageImpactStatus.BLOCKED
    before_contract = before.contract_digests.get(domain_id)
    after_contract = after.contract_digests.get(domain_id)
    status = UsageImpactStatus.UNAFFECTED
    if before_contract is None or after_contract is None:
        status = UsageImpactStatus.BLOCKED
    elif before_contract != after_contract:
        status = UsageImpactStatus.REGENERATE

    before_capabilities = set(before.capability_ids)
    after_capabilities = set(after.capability_ids)
    if any(
        capability_id not in before_capabilities or capability_id not in after_capabilities
        for capability_id in graph.capability_ids
    ):
        status = UsageImpactStatus.BLOCKED

    for tool_name in graph.tool_names:
        before_schema = before.tool_schemas.get(tool_name)
        after_schema = after.tool_schemas.get(tool_name)
        schema_status = (
            UsageImpactStatus.BLOCKED
            if before_schema is None or after_schema is None
            else _classify_tool_schema(before_schema, after_schema)
        )
        status = _maximum_status(status, schema_status)

    for source_id in graph.evidence_source_ids:
        before_evidence = before.evidence_digests.get(source_id)
        after_evidence = after.evidence_digests.get(source_id)
        if before_evidence is None or after_evidence is None or before_evidence != after_evidence:
            status = UsageImpactStatus.BLOCKED
    for capability_id in graph.capability_ids:
        before_proof = before.action_proof_digests.get(capability_id)
        after_proof = after.action_proof_digests.get(capability_id)
        proof_required = capability_id in graph.action_capability_ids
        if (
            proof_required and (before_proof is None or after_proof is None)
        ) or before_proof != after_proof:
            status = UsageImpactStatus.BLOCKED

    global_revalidation = any(
        before_digest != after_digest
        for before_digest, after_digest in (
            (before.pack_digest, after.pack_digest),
            (before.tool_schema_digest, after.tool_schema_digest),
            (before.source_snapshot_digest, after.source_snapshot_digest),
            (before.test_report_digest, after.test_report_digest),
        )
    )
    if global_revalidation:
        status = _maximum_status(status, UsageImpactStatus.REVALIDATE)
    return status


def analyze_usage_impact(
    *,
    before: UsageSnapshot,
    after: UsageSnapshot,
    report: UsageProjectReport,
) -> UsageImpactReport:
    """Classify local Usage changes with blocked-first dependency propagation."""

    graph, graph_valid = _build_graph(report)
    statuses = {
        domain_id: _direct_status(
            domain_id=domain_id,
            graph=domain_graph,
            before=before,
            after=after,
        )
        for domain_id, domain_graph in graph.items()
    }
    upstream: dict[str, set[str]] = defaultdict(set)
    dependents: dict[str, set[str]] = defaultdict(set)
    for domain_id, domain_graph in graph.items():
        for dependency_id in domain_graph.direct_dependency_domain_ids:
            dependents[dependency_id].add(domain_id)

    pending = deque(sorted(graph))
    while pending:
        changed_domain_id = pending.popleft()
        if statuses[changed_domain_id] is UsageImpactStatus.UNAFFECTED:
            continue
        for dependent_id in sorted(dependents[changed_domain_id]):
            propagated = _maximum_status(statuses[dependent_id], statuses[changed_domain_id])
            upstream[dependent_id].add(changed_domain_id)
            upstream[dependent_id].update(upstream[changed_domain_id])
            if propagated != statuses[dependent_id]:
                statuses[dependent_id] = propagated
                pending.append(dependent_id)

    domains = tuple(
        UsageDomainImpact(
            domain_id=domain_id,
            status=statuses[domain_id],
            contract_digest_before=before.contract_digests.get(domain_id),
            contract_digest_after=after.contract_digests.get(domain_id),
            scenario_ids=domain_graph.scenario_ids,
            route_ids=domain_graph.route_ids,
            step_ids=domain_graph.step_ids,
            capability_ids=domain_graph.capability_ids,
            action_capability_ids=domain_graph.action_capability_ids,
            tool_names=domain_graph.tool_names,
            evidence_source_ids=domain_graph.evidence_source_ids,
            upstream_domain_ids=tuple(sorted(upstream[domain_id])),
        )
        for domain_id, domain_graph in sorted(graph.items())
    )
    return UsageImpactReport(
        domains=domains,
        graph_status="valid" if graph_valid else "invalid",
        pack_digest_before=before.pack_digest,
        pack_digest_after=after.pack_digest,
        tool_schema_digest_before=before.tool_schema_digest,
        tool_schema_digest_after=after.tool_schema_digest,
        source_snapshot_digest_before=before.source_snapshot_digest,
        source_snapshot_digest_after=after.source_snapshot_digest,
        test_report_digest_before=before.test_report_digest,
        test_report_digest_after=after.test_report_digest,
    )


__all__ = [
    "UsageDomainImpact",
    "UsageImpactReport",
    "UsageImpactStatus",
    "UsageSnapshot",
    "UsageToolSchema",
    "analyze_usage_impact",
]
