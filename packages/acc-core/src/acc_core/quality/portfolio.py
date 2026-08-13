"""Platform-neutral audit of the Agent-facing tool portfolio."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from acc_core.diagnostics import Diagnostic
from acc_core.models import Capability
from acc_core.quality.models import CapabilityQuality
from acc_core.scope import ScopeInventory

_READ_ANCHORS = {"search", "list", "get", "aggregate", "monitor", "compare", "inspect"}
_MUTATIONS = {"create", "update", "delete", "transition", "execute"}
_ACTION_LIFECYCLE_TOOLS = (
    "acc_action_approve",
    "acc_action_commit",
    "acc_action_status",
)


@dataclass(frozen=True, slots=True)
class PortfolioOverlap:
    left: str
    right: str
    similarity: float
    kind: Literal["duplicate", "high_overlap"]


@dataclass(frozen=True, slots=True)
class ToolPortfolioAnalysis:
    intent_groups: dict[str, tuple[str, ...]]
    operation_dependencies: dict[str, tuple[str, ...]]
    projected_mcp_tool_names: tuple[str, ...]
    projected_mcp_tool_count: int
    projected_mcp_tool_collisions: tuple[str, ...]
    overlaps: tuple[PortfolioOverlap, ...]
    isolated_mutation_ids: tuple[str, ...]
    covered_route_ids: tuple[str, ...]
    uncovered_materialized_route_ids: tuple[str, ...]
    blocked_route_count: int
    diagnostics: tuple[Diagnostic, ...]


def _intent_key(quality: CapabilityQuality) -> str:
    return f"{quality.intent.action}:{','.join(quality.intent.resource_types)}"


def _jaccard(left: set[str], right: set[str]) -> float | None:
    union = left | right
    return None if not union else len(left & right) / len(union)


def _interface_signature(capability: Capability, quality: CapabilityQuality) -> str:
    document = {
        "input_schema": capability.input_schema,
        "output_schema": capability.output_schema,
        "selectors": {
            key: value.model_dump(mode="json", exclude_none=True)
            for key, value in sorted(quality.inputs.items())
        },
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def analyze_tool_portfolio(
    capabilities: Mapping[str, Capability],
    qualities: Mapping[str, CapabilityQuality],
    operation_dependencies: Mapping[str, Sequence[str]],
    scope_inventory: ScopeInventory,
    *,
    tool_budget: int | None = None,
    overlap_threshold: float = 0.75,
) -> ToolPortfolioAnalysis:
    """Audit intent-level tools without assuming one route equals one tool."""

    if tool_budget is not None and (isinstance(tool_budget, bool) or tool_budget < 1):
        raise ValueError("tool_budget must be a positive integer when provided")
    if not 0 < overlap_threshold <= 1:
        raise ValueError("overlap_threshold must be in (0, 1]")

    groups: dict[str, list[str]] = defaultdict(list)
    dependencies = {
        capability_id: tuple(sorted(set(operation_dependencies.get(capability_id, ()))))
        for capability_id in sorted(capabilities)
    }
    for capability_id in sorted(capabilities):
        if (quality := qualities.get(capability_id)) is not None:
            groups[_intent_key(quality)].append(capability_id)
    intent_groups = {key: tuple(value) for key, value in sorted(groups.items())}

    projected_names = [
        f"{capability_id}.prepare" if capability.kind == "action" else capability_id
        for capability_id, capability in sorted(capabilities.items())
    ]
    if any(capability.kind == "action" for capability in capabilities.values()):
        projected_names.extend(_ACTION_LIFECYCLE_TOOLS)
    projected_counts: dict[str, int] = defaultdict(int)
    for name in projected_names:
        projected_counts[name] += 1
    projected_collisions = tuple(
        sorted(name for name, count in projected_counts.items() if count > 1)
    )
    projected_tool_names = tuple(sorted(projected_counts))

    diagnostics: list[Diagnostic] = []
    if projected_collisions:
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_MCP_NAME_COLLISION",
                severity="error",
                message=(
                    "Projected MCP tools/list contains colliding Read, Action prepare, or "
                    "shared lifecycle names. Rename the conflicting Capability."
                ),
                path="capabilities",
                pointer=None,
            )
        )
    projected_tool_count = len(projected_names)
    if tool_budget is not None and projected_tool_count > tool_budget:
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_BUDGET_EXCEEDED",
                severity="warning",
                message=(
                    f"Portfolio has {len(capabilities)} Capabilities and projects "
                    f"{projected_tool_count} MCP tools, exceeding the review budget of "
                    f"{tool_budget}; group by evidenced business intent."
                ),
                path="capabilities",
                pointer=None,
            )
        )

    for intent_key, members in intent_groups.items():
        if not intent_key.startswith("transition:"):
            continue
        action_members = tuple(
            capability_id
            for capability_id in members
            if capabilities[capability_id].kind == "action"
        )
        if len(action_members) < 2:
            continue
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_TRANSITION_FRAGMENTATION",
                severity="warning",
                message=(
                    "Multiple Action tools model the same resource transition intent; prefer "
                    "one bounded target-state selector unless distinct business outcomes are "
                    "evidenced. Const schema differences do not make separate intents."
                ),
                path=f"capability-quality/{action_members[1]}.yaml",
                pointer="/intent",
            )
        )

    overlaps: list[PortfolioOverlap] = []
    for capability_id, capability_dependencies in dependencies.items():
        if capability_dependencies:
            continue
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_DEPENDENCIES_INCOMPLETE",
                severity="warning",
                message=(
                    "Tool has no auditable Operation dependencies; overlap cannot be inferred "
                    "from an empty dependency set."
                ),
                path=f"capabilities/{capability_id}.yaml",
                pointer=None,
            )
        )
    for members in intent_groups.values():
        for offset, left in enumerate(members):
            for right in members[offset + 1 :]:
                left_dependencies = set(dependencies[left])
                right_dependencies = set(dependencies[right])
                similarity = _jaccard(left_dependencies, right_dependencies)
                if similarity is None or similarity < overlap_threshold:
                    continue
                left_quality = qualities[left]
                right_quality = qualities[right]
                if _interface_signature(capabilities[left], left_quality) != _interface_signature(
                    capabilities[right], right_quality
                ):
                    continue
                kind: Literal["duplicate", "high_overlap"] = (
                    "duplicate" if left_dependencies == right_dependencies else "high_overlap"
                )
                overlaps.append(PortfolioOverlap(left, right, similarity, kind))
                diagnostics.append(
                    Diagnostic(
                        code=(
                            "ACC_TOOL_PORTFOLIO_DUPLICATE"
                            if kind == "duplicate"
                            else "ACC_TOOL_PORTFOLIO_HIGH_OVERLAP"
                        ),
                        severity="warning",
                        message=(
                            "Tools share one business intent and substantially overlapping "
                            "Operation dependencies; merge them or prove distinct outcomes."
                        ),
                        path=f"capability-quality/{right}.yaml",
                        pointer="/intent",
                    )
                )

    read_resources = {
        resource
        for quality in qualities.values()
        if quality.intent.action in _READ_ANCHORS
        for resource in quality.intent.resource_types
    }
    isolated_mutations = tuple(
        sorted(
            capability_id
            for capability_id, quality in qualities.items()
            if capability_id in capabilities
            and quality.intent.action in _MUTATIONS
            and not (set(quality.intent.resource_types) & read_resources)
        )
    )
    diagnostics.extend(
        Diagnostic(
            code="ACC_TOOL_PORTFOLIO_ISOLATED_MUTATION",
            severity="warning",
            message=(
                "Mutation tool has no list, search, get, inspect, or monitor entrypoint for the "
                "same resource; prove selector acquisition or add a business read anchor."
            ),
            path=f"capability-quality/{capability_id}.yaml",
            pointer="/intent",
        )
        for capability_id in isolated_mutations
    )

    capability_ids = set(capabilities)
    materialized = [
        route for route in scope_inventory.routes if route.disposition in {"planned", "composed"}
    ]
    covered = tuple(
        sorted(
            route.id
            for route in materialized
            if route.capability_ids and set(route.capability_ids) <= capability_ids
        )
    )
    covered_set = set(covered)
    uncovered = tuple(sorted(route.id for route in materialized if route.id not in covered_set))
    if uncovered:
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_UNDER_COVERED",
                severity="error",
                message=(
                    "Planned or composed business routes are not assigned to existing tools; "
                    "compose by business intent instead of leaving materialized work unreachable."
                ),
                path="scope-inventory.yaml",
                pointer="/routes",
            )
        )
    blocked_count = sum(
        route.disposition == "blocked_on_evidence" for route in scope_inventory.routes
    )
    if scope_inventory.scope.mode == "system_complete" and blocked_count:
        diagnostics.append(
            Diagnostic(
                code="ACC_TOOL_PORTFOLIO_BUSINESS_SURFACE_BLOCKED",
                severity="warning",
                message=(
                    "The system-complete business denominator contains evidence-blocked routes; "
                    "do not hide them by shrinking or inflating the tool portfolio."
                ),
                path="scope-inventory.yaml",
                pointer="/routes",
            )
        )

    diagnostics.sort(key=lambda item: (item.path or "", item.pointer or "", item.code))
    overlaps.sort(key=lambda item: (item.left, item.right))
    return ToolPortfolioAnalysis(
        intent_groups,
        dependencies,
        projected_tool_names,
        projected_tool_count,
        projected_collisions,
        tuple(overlaps),
        isolated_mutations,
        covered,
        uncovered,
        blocked_count,
        tuple(diagnostics),
    )


__all__ = ["PortfolioOverlap", "ToolPortfolioAnalysis", "analyze_tool_portfolio"]
