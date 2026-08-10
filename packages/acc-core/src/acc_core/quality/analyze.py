"""Platform-neutral constructability and composition quality analysis."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from acc_core.diagnostics import Diagnostic
from acc_core.models import Capability
from acc_core.quality.graph import (
    CapabilityDiscoveryGraph,
    WorkflowCompositionGraph,
    build_capability_discovery_graph,
    build_workflow_composition_graph,
)
from acc_core.quality.models import CapabilityQuality


@dataclass(frozen=True, slots=True)
class CapabilityQualityAnalysis:
    """Deterministic discovery graph, composition counts, and quality findings."""

    graph: CapabilityDiscoveryGraph
    composition_components: dict[str, int]
    diagnostics: tuple[Diagnostic, ...]


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _required_inputs(capability: Capability) -> tuple[str, ...]:
    required = capability.input_schema.get("required", [])
    if not isinstance(required, list):
        return ()
    return tuple(sorted(item for item in required if isinstance(item, str)))


def _is_explicit_compare(
    capability: Capability,
    quality: CapabilityQuality,
) -> bool:
    if quality.intent.action != "compare" or quality.composition.justification is None:
        return False
    selectors = [
        quality.inputs[name]
        for name in _required_inputs(capability)
        if name in quality.inputs and quality.inputs[name].kind == "resource_selector"
    ]
    resource_types = {selector.resource_type for selector in selectors}
    return len(selectors) == 2 and len(resource_types) == 1 and None not in resource_types


def _composition_diagnostics(
    capability_id: str,
    capability: Capability,
    quality: CapabilityQuality,
    graph: WorkflowCompositionGraph,
    *,
    operation_budget: int,
) -> list[Diagnostic]:
    path = f"capabilities/{capability_id}.yaml"
    diagnostics: list[Diagnostic] = []
    component_count = len(graph.components)
    if component_count > 1 and not _is_explicit_compare(capability, quality):
        diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_INDEPENDENT_CALL_FANIN",
                severity="warning",
                message=(
                    "Capability combines independently selected call groups; split them or "
                    "document a supported business relationship."
                ),
                path=path,
                pointer="/workflow",
            )
        )
    if len(graph.calls) > operation_budget:
        diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_OPERATION_BUDGET_EXCEEDED",
                severity="warning",
                message=(
                    f"Capability contains {len(graph.calls)} Operation calls, exceeding the "
                    f"configured analysis budget of {operation_budget}."
                ),
                path=path,
                pointer="/workflow",
            )
        )

    required_selectors = {
        name
        for name in _required_inputs(capability)
        if (metadata := quality.inputs.get(name)) is not None
        and metadata.kind == "resource_selector"
    }
    selector_calls = [
        call for call in graph.calls if set(call.input_references) & required_selectors
    ]
    independent_calls = [
        call for call in graph.calls if not set(call.input_references) & required_selectors
    ]
    if selector_calls and independent_calls:
        diagnostics.append(
            Diagnostic(
                code="ACC_CAPABILITY_LIST_DETAIL_COUPLED",
                severity="warning",
                message=(
                    "Capability couples calls that require a resource selector with calls that "
                    "can run without that selector."
                ),
                path=path,
                pointer="/workflow",
            )
        )
        if any(not call.conditional for call in selector_calls):
            diagnostics.append(
                Diagnostic(
                    code="ACC_CAPABILITY_EMPTY_SUCCESS_PATH_MISSING",
                    severity="warning",
                    message=(
                        "A selector-independent result cannot complete successfully without "
                        "also executing the mandatory selector-dependent call."
                    ),
                    path=path,
                    pointer="/workflow",
                )
            )
    return diagnostics


def _constructability_diagnostics(
    capabilities: Mapping[str, Capability],
    qualities: Mapping[str, CapabilityQuality],
    graph: CapabilityDiscoveryGraph,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    reachable = set(graph.reachable)
    for capability_id, capability in sorted(capabilities.items()):
        quality = qualities.get(capability_id)
        for input_name in _required_inputs(capability):
            metadata = quality.inputs.get(input_name) if quality is not None else None
            unavailable = metadata is None or metadata.acquisition == "upstream_step"
            if metadata is not None and metadata.acquisition == "capability_output":
                unavailable = not bool(set(metadata.producers) & reachable)
            if unavailable:
                diagnostics.append(
                    Diagnostic(
                        code="ACC_CAPABILITY_REQUIRED_SELECTOR_UNDISCOVERABLE",
                        severity="error",
                        message=(
                            f"Required input {input_name!r} has no reachable declared acquisition "
                            "path."
                        ),
                        path=f"capability-quality/{capability_id}.yaml",
                        pointer=f"/inputs/{_escape(input_name)}",
                    )
                )
    for capability_id in graph.dead_ends:
        diagnostics.append(
            Diagnostic(
                code="ACC_COVERAGE_DISCOVERY_DEAD_END",
                severity="error",
                message="Capability is not reachable from any caller-constructible entrypoint.",
                path=f"capability-quality/{capability_id}.yaml",
                pointer="/capability_id",
            )
        )
    return diagnostics


def analyze_capability_quality(
    capabilities: Mapping[str, Capability],
    qualities: Mapping[str, CapabilityQuality],
    *,
    operation_budget: int = 8,
) -> CapabilityQualityAnalysis:
    """Analyze discoverability and composition without provider-specific assumptions."""

    if isinstance(operation_budget, bool) or operation_budget < 1:
        raise ValueError("operation_budget must be a positive integer")

    graph = build_capability_discovery_graph(capabilities, qualities)
    composition_components: dict[str, int] = {}
    diagnostics = _constructability_diagnostics(capabilities, qualities, graph)
    for capability_id, capability in sorted(capabilities.items()):
        quality = qualities.get(capability_id)
        if quality is None:
            continue
        composition_graph = build_workflow_composition_graph(capability, quality)
        composition_components[capability_id] = len(composition_graph.components)
        diagnostics.extend(
            _composition_diagnostics(
                capability_id,
                capability,
                quality,
                composition_graph,
                operation_budget=operation_budget,
            )
        )
    diagnostics.sort(
        key=lambda item: (
            item.path or "",
            item.pointer or "",
            item.code,
            item.message,
        )
    )
    return CapabilityQualityAnalysis(graph, composition_components, tuple(diagnostics))


__all__ = ["CapabilityQualityAnalysis", "analyze_capability_quality"]
