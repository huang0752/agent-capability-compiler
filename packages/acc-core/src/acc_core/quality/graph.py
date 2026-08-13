"""Deterministic workflow-composition and capability-discovery graphs."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import cast

from pydantic import JsonValue

from acc_core.models import (
    ActionCapabilityV2,
    BranchStep,
    CallStep,
    Capability,
    ForeachStep,
    ParallelStep,
    ReadCapabilityV2,
    WorkflowStep,
)
from acc_core.quality.models import CapabilityQuality

_INPUT_REFERENCE = re.compile(r"^\$\.input\.([A-Za-z_][A-Za-z0-9_-]*)")
_STEP_REFERENCE = re.compile(r"^\$\.steps\.([A-Za-z_][A-Za-z0-9_-]*)")


@dataclass(frozen=True, slots=True)
class WorkflowCallNode:
    """One normalized Operation call and the values connecting it to other calls."""

    index: int
    phase: str
    operation_id: str
    step_id: str | None
    input_references: tuple[str, ...]
    step_references: tuple[str, ...]
    conditional: bool


@dataclass(frozen=True, slots=True)
class WorkflowCompositionGraph:
    """Operation calls grouped by shared selectors and prior-step data flow."""

    calls: tuple[WorkflowCallNode, ...]
    components: tuple[tuple[int, ...], ...]


@dataclass(frozen=True, slots=True)
class CapabilityDiscoveryEdge:
    """A declared producer that can supply one consumer input."""

    producer: str
    consumer: str
    input_name: str


@dataclass(frozen=True, slots=True)
class CapabilityDiscoveryGraph:
    """Global reachability from inputs available to a caller or trusted context."""

    nodes: tuple[str, ...]
    edges: tuple[CapabilityDiscoveryEdge, ...]
    entrypoints: tuple[str, ...]
    reachable: tuple[str, ...]
    dead_ends: tuple[str, ...]


def _references(value: JsonValue) -> tuple[set[str], set[str]]:
    inputs: set[str] = set()
    steps: set[str] = set()
    pending: list[JsonValue] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            input_match = _INPUT_REFERENCE.match(current)
            if input_match is not None:
                inputs.add(input_match.group(1))
            step_match = _STEP_REFERENCE.match(current)
            if step_match is not None:
                steps.add(step_match.group(1))
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            pending.extend(current.values())
    return inputs, steps


def _walk_calls(
    workflow: Iterable[WorkflowStep],
    *,
    phase: str,
    inherited_steps: frozenset[str] = frozenset(),
    conditional: bool = False,
) -> list[WorkflowCallNode]:
    calls: list[WorkflowCallNode] = []
    for step in workflow:
        if isinstance(step, CallStep):
            inputs, steps = _references(step.call.arguments)
            calls.append(
                WorkflowCallNode(
                    index=-1,
                    phase=phase,
                    operation_id=step.call.operation,
                    step_id=step.id,
                    input_references=tuple(sorted(inputs)),
                    step_references=tuple(sorted(steps | set(inherited_steps))),
                    conditional=conditional,
                )
            )
        elif isinstance(step, BranchStep):
            condition = step.branch.condition
            condition_value = (
                condition
                if isinstance(condition, str)
                else cast(JsonValue, condition.model_dump(mode="json"))
            )
            _, condition_steps = _references(condition_value)
            inherited = inherited_steps | condition_steps
            calls.extend(
                _walk_calls(
                    step.branch.then_steps,
                    phase=phase,
                    inherited_steps=frozenset(inherited),
                    conditional=True,
                )
            )
            calls.extend(
                _walk_calls(
                    step.branch.else_steps,
                    phase=phase,
                    inherited_steps=frozenset(inherited),
                    conditional=True,
                )
            )
        elif isinstance(step, ParallelStep):
            calls.extend(
                _walk_calls(
                    step.parallel,
                    phase=phase,
                    inherited_steps=inherited_steps,
                    conditional=conditional,
                )
            )
        elif isinstance(step, ForeachStep):
            _, item_steps = _references(step.foreach.items)
            calls.extend(
                _walk_calls(
                    step.foreach.workflow,
                    phase=phase,
                    inherited_steps=frozenset(inherited_steps | item_steps),
                    conditional=True,
                )
            )
    return [
        WorkflowCallNode(
            index=index,
            phase=call.phase,
            operation_id=call.operation_id,
            step_id=call.step_id,
            input_references=call.input_references,
            step_references=call.step_references,
            conditional=call.conditional,
        )
        for index, call in enumerate(calls)
    ]


class _DisjointSet:
    def __init__(self, size: int) -> None:
        self._parents = list(range(size))

    def find(self, index: int) -> int:
        parent = self._parents[index]
        if parent != index:
            self._parents[index] = self.find(parent)
        return self._parents[index]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parents[right_root] = left_root


def build_workflow_composition_graph(
    capability: Capability,
    quality: CapabilityQuality,
) -> WorkflowCompositionGraph:
    """Connect calls only through actual step flow or a shared resource selector."""

    workflows: tuple[tuple[str, list[WorkflowStep]], ...]
    if isinstance(capability, ReadCapabilityV2):
        workflows = (("read", capability.workflow),)
    elif isinstance(capability, ActionCapabilityV2):
        workflows = (
            ("preview", capability.preview_workflow),
            ("commit", capability.commit_workflow),
        )
    else:  # pragma: no cover - the discriminated public union is closed
        raise TypeError("unsupported capability kind")
    calls = [
        WorkflowCallNode(
            index=index,
            phase=call.phase,
            operation_id=call.operation_id,
            step_id=call.step_id,
            input_references=call.input_references,
            step_references=call.step_references,
            conditional=call.conditional,
        )
        for index, call in enumerate(
            call for phase, workflow in workflows for call in _walk_calls(workflow, phase=phase)
        )
    ]
    disjoint = _DisjointSet(len(calls))
    calls_by_step = {
        (call.phase, call.step_id): call.index for call in calls if call.step_id is not None
    }
    selector_names = {
        name for name, metadata in quality.inputs.items() if metadata.kind == "resource_selector"
    }
    calls_by_selector: dict[str, list[int]] = {}
    for call in calls:
        for step_id in call.step_references:
            producer = calls_by_step.get((call.phase, step_id))
            if producer is not None:
                disjoint.union(producer, call.index)
        for input_name in set(call.input_references) & selector_names:
            calls_by_selector.setdefault(input_name, []).append(call.index)
    for indexes in calls_by_selector.values():
        for index in indexes[1:]:
            disjoint.union(indexes[0], index)
    if isinstance(capability, ActionCapabilityV2):
        preview = next((call.index for call in calls if call.phase == "preview"), None)
        commit = next((call.index for call in calls if call.phase == "commit"), None)
        if preview is not None and commit is not None:
            disjoint.union(preview, commit)

    components: dict[int, list[int]] = {}
    for call in calls:
        components.setdefault(disjoint.find(call.index), []).append(call.index)
    normalized = tuple(
        sorted((tuple(sorted(indexes)) for indexes in components.values()), key=lambda item: item)
    )
    return WorkflowCompositionGraph(tuple(calls), normalized)


def _required_inputs(capability: Capability) -> tuple[str, ...]:
    required = capability.input_schema.get("required", [])
    if not isinstance(required, list):
        return ()
    return tuple(sorted(item for item in required if isinstance(item, str)))


def _intrinsic_entrypoint(capability: Capability, quality: CapabilityQuality | None) -> bool:
    if quality is None:
        return not _required_inputs(capability)
    for name in _required_inputs(capability):
        metadata = quality.inputs.get(name)
        if metadata is None or metadata.acquisition in {"capability_output", "upstream_step"}:
            return False
    return True


def build_capability_discovery_graph(
    capabilities: Mapping[str, Capability],
    qualities: Mapping[str, CapabilityQuality],
) -> CapabilityDiscoveryGraph:
    """Resolve declared producer edges and global constructability reachability."""

    nodes = tuple(sorted(capabilities))
    edges = tuple(
        sorted(
            (
                CapabilityDiscoveryEdge(producer, capability_id, input_name)
                for capability_id, quality in qualities.items()
                if capability_id in capabilities
                for input_name, metadata in quality.inputs.items()
                if metadata.acquisition == "capability_output"
                for producer in metadata.producers
                if producer in capabilities
            ),
            key=lambda edge: (edge.producer, edge.consumer, edge.input_name),
        )
    )
    entrypoints = tuple(
        capability_id
        for capability_id in nodes
        if _intrinsic_entrypoint(capabilities[capability_id], qualities.get(capability_id))
    )
    reachable = set(entrypoints)
    changed = True
    while changed:
        changed = False
        for capability_id in nodes:
            if capability_id in reachable:
                continue
            capability = capabilities[capability_id]
            quality = qualities.get(capability_id)
            if quality is None:
                continue
            constructible = True
            for input_name in _required_inputs(capability):
                metadata = quality.inputs.get(input_name)
                if metadata is None or metadata.acquisition == "upstream_step":
                    constructible = False
                    break
                if metadata.acquisition == "capability_output" and not (
                    set(metadata.producers) & reachable
                ):
                    constructible = False
                    break
            if constructible:
                reachable.add(capability_id)
                changed = True
    reachable_nodes = tuple(sorted(reachable))
    return CapabilityDiscoveryGraph(
        nodes=nodes,
        edges=edges,
        entrypoints=entrypoints,
        reachable=reachable_nodes,
        dead_ends=tuple(sorted(set(nodes) - reachable)),
    )


__all__ = [
    "CapabilityDiscoveryEdge",
    "CapabilityDiscoveryGraph",
    "WorkflowCallNode",
    "WorkflowCompositionGraph",
    "build_capability_discovery_graph",
    "build_workflow_composition_graph",
]
