"""Independent interaction coverage axes without aggregate usability claims."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any, Literal, cast

from acc_core.coverage.models import (
    ClientAdapterEvidenceCoverage,
    ClientAdapterObservation,
    InteractionFidelityAxisCoverage,
    InteractionTraceCoverage,
    RelatedDataEdgeCoverage,
    RelatedDataGraphCoverage,
    StateScenarioCoverage,
    SurfaceDispositionCoverage,
)
from acc_core.interactions.compile import InteractionCompilationError, compile_interactions
from acc_core.interactions.models import (
    CapabilityInteractionContract,
    InteractionDimension,
    UIInteraction,
)
from acc_core.interactions.validate import analyze_interaction_fidelity
from acc_core.models import Evidence
from acc_core.scope import ScopeInventory
from acc_core.validation import ValidationReport


def _evidence_key(evidence: Evidence) -> str:
    return json.dumps(
        evidence.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _semantic_fact_key(item: object) -> tuple[str, str] | None:
    if not hasattr(item, "evidence") or not hasattr(item, "model_dump"):
        return None
    model = cast(Any, item)
    semantic = json.dumps(
        model.model_dump(mode="json", exclude={"evidence"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return semantic, _evidence_key(cast(Evidence, model.evidence))


def _empty_axes(
    status: Literal["not_declared", "explicit_none"],
) -> tuple[
    SurfaceDispositionCoverage,
    InteractionTraceCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    RelatedDataGraphCoverage,
    StateScenarioCoverage,
    InteractionFidelityAxisCoverage,
    ClientAdapterEvidenceCoverage,
]:
    fidelity = InteractionFidelityAxisCoverage(
        status=status,
        declared_interaction_ids=[],
        proven_interaction_ids=[],
        unproven_interaction_ids=[],
    )
    return (
        SurfaceDispositionCoverage(
            status=status,
            surface_ids=[],
            adopted_interaction_ids=[],
            omitted_interaction_ids=[],
            unclassified_interaction_ids=[],
        ),
        InteractionTraceCoverage(
            status=status,
            traced_interaction_ids=[],
            broken_interaction_ids=[],
            client_only_interaction_ids=[],
        ),
        fidelity,
        fidelity.model_copy(),
        fidelity.model_copy(),
        fidelity.model_copy(),
        RelatedDataGraphCoverage(
            **fidelity.model_dump(mode="python"),
            nodes=[],
            edges=[],
        ),
        StateScenarioCoverage(
            status=status,
            required_scenario_ids=[],
            headless_verified_interaction_ids=[],
            not_verified_interaction_ids=[],
        ),
        fidelity.model_copy(),
        ClientAdapterEvidenceCoverage(
            status=status,
            verified_interaction_ids=[],
            not_verified_interaction_ids=[],
            verified_adapter_ids=[],
        ),
    )


def _contract_by_interaction(
    contracts: dict[str, CapabilityInteractionContract],
) -> dict[str, list[CapabilityInteractionContract]]:
    result: dict[str, list[CapabilityInteractionContract]] = {}
    for contract in contracts.values():
        for interaction_id in contract.interaction_ids:
            result.setdefault(interaction_id, []).append(contract)
    return result


def _fidelity_axis(
    *,
    interactions: dict[str, UIInteraction],
    contracts_by_interaction: dict[str, list[CapabilityInteractionContract]],
    source_items: Callable[[UIInteraction], Sequence[object]],
    contract_items: Callable[[CapabilityInteractionContract], Sequence[object]],
    broken_capability_ids: set[str],
    dimension: InteractionDimension,
) -> InteractionFidelityAxisCoverage:
    declared: list[str] = []
    proven: list[str] = []
    unproven: list[str] = []
    for interaction_id, interaction in sorted(interactions.items()):
        contracts = contracts_by_interaction.get(interaction_id, [])
        source = tuple(source_items(interaction))
        contract_values = tuple(item for contract in contracts for item in contract_items(contract))
        disposition = next(
            (item for item in interaction.dimension_dispositions if item.dimension == dimension),
            None,
        )
        if not source and not contract_values and disposition is None:
            continue
        declared.append(interaction_id)
        source_facts = {key for item in source if (key := _semantic_fact_key(item)) is not None}
        contract_facts = {
            key for item in contract_values if (key := _semantic_fact_key(item)) is not None
        }
        contract_broken = any(
            contract.capability_id in broken_capability_ids for contract in contracts
        )
        if (
            contracts
            and source_facts <= contract_facts
            and not contract_broken
            and (
                disposition is None
                or disposition.applicability == ("applicable" if source else "not_applicable")
            )
        ):
            proven.append(interaction_id)
        else:
            unproven.append(interaction_id)
    return InteractionFidelityAxisCoverage(
        status="analyzed",
        declared_interaction_ids=declared,
        proven_interaction_ids=proven,
        unproven_interaction_ids=unproven,
    )


def _broken_capabilities(
    report: ValidationReport,
    scope_inventory: ScopeInventory,
) -> dict[str, set[str]]:
    diagnostics = list(report.diagnostics)
    if report.project is not None and report.ui_interaction_inventory is not None:
        diagnostics.extend(
            analyze_interaction_fidelity(
                project=report.project,
                scope_inventory=scope_inventory,
                ui_inventory=report.ui_interaction_inventory,
                contracts=report.interaction_contracts,
                capabilities=report.capabilities,
                operations=report.operations,
                policies=report.policies,
            ).diagnostics
        )
    codes: dict[str, set[str]] = {}
    capability_by_path = {
        report.interaction_contract_paths.get(
            capability_id,
            f"interaction-contracts/{capability_id}.yaml",
        ): capability_id
        for capability_id in report.interaction_contracts
    }
    for diagnostic in diagnostics:
        if diagnostic.path not in capability_by_path:
            continue
        capability_id = capability_by_path[diagnostic.path]
        codes.setdefault(diagnostic.code, set()).add(capability_id)
    return codes


def analyze_interaction_coverage(
    report: ValidationReport,
    scope_inventory: ScopeInventory,
    *,
    client_adapter_observations: Sequence[ClientAdapterObservation] = (),
) -> tuple[
    SurfaceDispositionCoverage,
    InteractionTraceCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    InteractionFidelityAxisCoverage,
    RelatedDataGraphCoverage,
    StateScenarioCoverage,
    InteractionFidelityAxisCoverage,
    ClientAdapterEvidenceCoverage,
]:
    """Return ten independent interaction axes in CoverageReport field order."""

    inventory = report.ui_interaction_inventory
    if inventory is None:
        return _empty_axes("not_declared")
    if inventory.scope.mode == "none":
        return _empty_axes("explicit_none")

    interactions = {item.id: item for item in inventory.interactions}
    contracts_by_interaction = _contract_by_interaction(report.interaction_contracts)
    adopted = set(contracts_by_interaction)
    omitted = {
        omission.interaction_id
        for contract in report.interaction_contracts.values()
        for omission in contract.omissions
    }
    surface = SurfaceDispositionCoverage(
        status="analyzed",
        surface_ids=sorted(item.id for item in inventory.surfaces),
        adopted_interaction_ids=sorted(adopted),
        omitted_interaction_ids=sorted(omitted),
        unclassified_interaction_ids=sorted(set(interactions) - adopted - omitted),
    )

    routes = {route.id: route for route in scope_inventory.routes}
    traced: list[str] = []
    broken: list[str] = []
    client_only: list[str] = []
    for interaction_id, interaction in sorted(interactions.items()):
        if not interaction.route_ids:
            client_only.append(interaction_id)
            continue
        closed = bool(interaction.route_ids) and all(
            route_id in routes and interaction_id in routes[route_id].interaction_ids
            for route_id in interaction.route_ids
        )
        reverse_closed = all(
            route.id in interaction.route_ids
            for route in scope_inventory.routes
            if interaction_id in route.interaction_ids
        )
        (traced if closed and reverse_closed else broken).append(interaction_id)
    trace = InteractionTraceCoverage(
        status="analyzed",
        traced_interaction_ids=traced,
        broken_interaction_ids=broken,
        client_only_interaction_ids=client_only,
    )

    broken_by_code = _broken_capabilities(report, scope_inventory)
    input_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.input_bindings,
        contract_items=lambda contract: [
            *contract.public_input_bindings,
            *contract.trusted_input_bindings,
        ],
        broken_capability_ids=broken_by_code.get("ACC_UI_INPUT_SOURCE_UNRESOLVED", set()),
        dimension="input_bindings",
    )
    default_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.defaults,
        contract_items=lambda contract: contract.defaults,
        broken_capability_ids=broken_by_code.get("ACC_UI_DEFAULT_AUTHORITY_UNPROVEN", set()),
        dimension="defaults",
    )
    option_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.option_sources,
        contract_items=lambda contract: contract.option_sources,
        broken_capability_ids=broken_by_code.get("ACC_UI_OPTION_SOURCE_UNTRACED", set()),
        dimension="option_sources",
    )
    condition_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.conditions,
        contract_items=lambda contract: contract.conditions,
        broken_capability_ids=(
            broken_by_code.get("ACC_UI_CONDITION_AUTHORITY_UNPROVEN", set())
            | broken_by_code.get("ACC_UI_CONDITION_CYCLE", set())
        ),
        dimension="conditions",
    )
    related_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.related_data,
        contract_items=lambda contract: contract.related_data,
        broken_capability_ids=broken_by_code.get("ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN", set()),
        dimension="related_data",
    )
    edges = sorted(
        (
            RelatedDataEdgeCoverage(
                producer=binding.producer_id,
                consumer=contract.capability_id,
                interaction_id=interaction_id,
            )
            for interaction_id, contracts in contracts_by_interaction.items()
            for contract in contracts
            for binding in contract.related_data
        ),
        key=lambda edge: (edge.producer, edge.consumer, edge.interaction_id),
    )
    related_graph = RelatedDataGraphCoverage(
        **related_axis.model_dump(mode="python"),
        nodes=sorted({node for edge in edges for node in (edge.producer, edge.consumer)}),
        edges=edges,
    )
    presentation_axis = _fidelity_axis(
        interactions=interactions,
        contracts_by_interaction=contracts_by_interaction,
        source_items=lambda item: item.result_consumption,
        contract_items=lambda contract: contract.result_consumption,
        broken_capability_ids=broken_by_code.get("ACC_UI_PRESENTATION_FIELD_UNPROVEN", set()),
        dimension="result_consumption",
    )
    required_scenarios = sorted(
        scenario
        for contract in report.interaction_contracts.values()
        for scenario in contract.required_scenarios
    )
    scenario_interactions = sorted(
        interaction_id
        for interaction_id, contracts in contracts_by_interaction.items()
        if any(contract.required_scenarios for contract in contracts)
        or bool(interactions[interaction_id].states)
    )
    state_scenarios = StateScenarioCoverage(
        status="analyzed",
        required_scenario_ids=required_scenarios,
        headless_verified_interaction_ids=[],
        not_verified_interaction_ids=scenario_interactions,
    )
    expected_interaction_ids = sorted(interactions)
    declared_evidence_sources = set(inventory.scope.evidence_sources) | {
        source_id
        for surface_item in inventory.surfaces
        for source_id in surface_item.evidence_sources
    }
    try:
        expected_digest = compile_interactions(report).digest
    except InteractionCompilationError:
        expected_digest = None
    verified_adapters = sorted(
        {
            observation.adapter_id
            for observation in client_adapter_observations
            if expected_digest is not None
            and observation.interaction_digest == expected_digest
            and observation.required_scenarios_passed
            and observation.verified_interaction_ids == expected_interaction_ids
            and observation.verified_scenario_ids == required_scenarios
            and set(observation.evidence_sources) <= declared_evidence_sources
        }
    )
    client_verified = bool(verified_adapters)
    client_adapter = ClientAdapterEvidenceCoverage(
        status="client_adapter_verified" if client_verified else "not_verified",
        verified_interaction_ids=expected_interaction_ids if client_verified else [],
        not_verified_interaction_ids=[] if client_verified else expected_interaction_ids,
        verified_adapter_ids=verified_adapters,
    )
    return (
        surface,
        trace,
        input_axis,
        default_axis,
        option_axis,
        condition_axis,
        related_graph,
        state_scenarios,
        presentation_axis,
        client_adapter,
    )


__all__ = ["analyze_interaction_coverage"]
