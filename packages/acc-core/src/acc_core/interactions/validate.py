"""Pure semantic fidelity analysis for platform-neutral interaction contracts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from jsonschema import Draft202012Validator
from referencing.exceptions import Unresolvable

from acc_core.contracts.schema_relation import (
    SchemaRelation,
    compare_operation_input,
    compare_operation_output,
)
from acc_core.diagnostics import Diagnostic
from acc_core.interactions.expressions import (
    AllExpression,
    AnyExpression,
    ConditionExpression,
    LiteralOperand,
    NotExpression,
    PresentExpression,
    ReferenceOperand,
    iter_condition_references,
)
from acc_core.interactions.models import (
    CapabilityInteractionContract,
    InteractionCondition,
    UIInteraction,
    UIInteractionInventory,
)
from acc_core.models import (
    ActionCapabilityV2,
    BranchStep,
    CallStep,
    Capability,
    Evidence,
    ForeachStep,
    JsonObject,
    Operation,
    ParallelStep,
    Policy,
    Project,
)
from acc_core.scope import ScopeInventory

_AUTHORITATIVE_CLAIM_AUTHORITIES = frozenset({"contract", "implementation", "test"})
_NON_ASSERTING_REF_SIBLINGS = frozenset(
    {
        "$anchor",
        "$comment",
        "$defs",
        "$id",
        "$schema",
        "default",
        "deprecated",
        "description",
        "examples",
        "readOnly",
        "title",
        "writeOnly",
    }
)


@dataclass(frozen=True, slots=True)
class InteractionValidationReport:
    """Deterministic interaction facts and stable semantic diagnostics."""

    diagnostics: tuple[Diagnostic, ...]
    interaction_ids: tuple[str, ...]
    dependency_edges: tuple[tuple[str, str], ...]


class _Evidenced(Protocol):
    evidence: Evidence


def _evidence_paths(
    root: str,
    collection_name: str,
    collection: Iterable[_Evidenced],
) -> list[tuple[str, Evidence]]:
    return [
        (f"{root}/{collection_name}/{offset}", item.evidence)
        for offset, item in enumerate(collection)
    ]


def _tokens(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _dereference(root: JsonObject, schema: object) -> JsonObject | None:
    current = schema
    seen: set[str] = set()
    while isinstance(current, dict) and "$ref" in current:
        reference = current.get("$ref")
        if (
            not isinstance(reference, str)
            or not reference.startswith("#/")
            or reference in seen
            or set(current) - {"$ref"} - _NON_ASSERTING_REF_SIBLINGS
        ):
            return None
        seen.add(reference)
        resolved: object = root
        for token in _tokens(reference[1:]):
            if not isinstance(resolved, dict) or token not in resolved:
                return None
            resolved = resolved[token]
        current = resolved
    return current if isinstance(current, dict) else None


def _schema_at_data_pointer(
    schema: JsonObject,
    pointer: str,
    *,
    root_schema: JsonObject | None = None,
) -> JsonObject | None:
    root = root_schema or schema
    current: object = schema
    for token in _tokens(pointer):
        current = _dereference(root, current)
        if current is None:
            return None
        if isinstance(current.get("items"), dict):
            current = current["items"]
            if token.isdecimal():
                continue
            current = _dereference(root, current)
            if current is None:
                return None
        properties = current.get("properties")
        if not isinstance(properties, dict) or not isinstance(properties.get(token), dict):
            return None
        current = properties[token]
    return _dereference(root, current)


def _relative_schema(
    schema: JsonObject,
    pointer: str | None,
    *,
    root_schema: JsonObject | None = None,
) -> JsonObject | None:
    if pointer is None:
        return _dereference(root_schema or schema, schema)
    return _schema_at_data_pointer(schema, pointer, root_schema=root_schema)


def _schema_accepts(root_schema: JsonObject, schema: JsonObject, value: object) -> bool:
    wrapper: JsonObject = {"allOf": [schema]}
    for keyword in ("$defs", "definitions"):
        definitions = root_schema.get(keyword)
        if isinstance(definitions, dict):
            wrapper[keyword] = definitions
    try:
        return Draft202012Validator(wrapper).is_valid(value)
    except Unresolvable:
        return False


def _diagnostic(
    diagnostics: list[Diagnostic],
    code: str,
    message: str,
    *,
    path: str,
    pointer: str,
) -> None:
    diagnostics.append(
        Diagnostic(
            code=code,
            severity="error",
            message=message,
            path=path,
            pointer=pointer,
        )
    )


def _adopted_evidence(
    contract: CapabilityInteractionContract,
    interactions: Mapping[str, UIInteraction],
) -> tuple[Evidence, ...]:
    evidence: list[Evidence] = []
    inventory_positions = {
        interaction_id: index for index, interaction_id in enumerate(interactions)
    }
    for interaction_id in contract.interaction_ids:
        interaction = interactions.get(interaction_id)
        if interaction is not None:
            interaction_index = inventory_positions[interaction_id]
            root = f"/interactions/{interaction_index}"
            fact_paths: list[tuple[str, Evidence]] = [
                (root, claim.evidence) for claim in interaction.evidence_claims
            ]
            fact_paths.extend(_evidence_paths(root, "input_bindings", interaction.input_bindings))
            fact_paths.extend(_evidence_paths(root, "defaults", interaction.defaults))
            fact_paths.extend(_evidence_paths(root, "option_sources", interaction.option_sources))
            fact_paths.extend(_evidence_paths(root, "conditions", interaction.conditions))
            fact_paths.extend(_evidence_paths(root, "related_data", interaction.related_data))
            fact_paths.extend(
                _evidence_paths(
                    root,
                    "result_consumption",
                    interaction.result_consumption,
                )
            )
            fact_paths.extend(_evidence_paths(root, "states", interaction.states))
            for claim in interaction.evidence_claims:
                if claim.authority not in _AUTHORITATIVE_CLAIM_AUTHORITIES:
                    continue
                evidence.extend(
                    fact_evidence
                    for fact_path, fact_evidence in fact_paths
                    if fact_evidence == claim.evidence
                    and (
                        fact_path == claim.target_pointer
                        or fact_path.startswith(f"{claim.target_pointer}/")
                    )
                )
    return tuple(evidence)


def _producer_schemas(
    producer_kind: Literal["capability", "operation"],
    producer_id: str,
    capabilities: Mapping[str, Capability],
    operations: Mapping[str, Operation],
) -> tuple[JsonObject, JsonObject] | None:
    producer = (
        capabilities.get(producer_id)
        if producer_kind == "capability"
        else operations.get(producer_id)
    )
    if producer is None:
        return None
    return producer.input_schema, producer.output_schema


def _condition_type_is_proven(expression: ConditionExpression, input_schema: JsonObject) -> bool:
    stack = [expression]
    while stack:
        node = stack.pop()
        if isinstance(node, (AllExpression, AnyExpression)):
            stack.extend(reversed(node.operands))
            continue
        if isinstance(node, NotExpression):
            stack.append(node.operand)
            continue
        if isinstance(node, PresentExpression):
            operand = node.operand
            if (
                isinstance(operand, ReferenceOperand)
                and _schema_at_data_pointer(input_schema, operand.pointer) is None
            ):
                return False
            continue

        left_schema = (
            _schema_at_data_pointer(input_schema, node.left.pointer)
            if isinstance(node.left, ReferenceOperand)
            else None
        )
        right_schema = (
            _schema_at_data_pointer(input_schema, node.right.pointer)
            if isinstance(node.right, ReferenceOperand)
            else None
        )
        if isinstance(node.left, ReferenceOperand) and left_schema is None:
            return False
        if isinstance(node.right, ReferenceOperand) and right_schema is None:
            return False
        if isinstance(node.left, ReferenceOperand) and isinstance(node.right, LiteralOperand):
            assert left_schema is not None
            if node.operator == "in":
                if not isinstance(node.right.value, list) or not all(
                    _schema_accepts(input_schema, left_schema, item) for item in node.right.value
                ):
                    return False
            elif not _schema_accepts(input_schema, left_schema, node.right.value):
                return False
        if isinstance(node.right, ReferenceOperand) and isinstance(node.left, LiteralOperand):
            assert right_schema is not None
            validation_schema = right_schema
            if node.operator == "in":
                resolved_items = _dereference(input_schema, right_schema.get("items"))
                if right_schema.get("type") != "array" or resolved_items is None:
                    return False
                validation_schema = resolved_items
            if not _schema_accepts(input_schema, validation_schema, node.left.value):
                return False
        if node.operator == "in" and left_schema is not None and right_schema is not None:
            item_schema = _dereference(input_schema, right_schema.get("items"))
            if (
                right_schema.get("type") != "array"
                or item_schema is None
                or compare_operation_output(left_schema, item_schema).relation
                is not SchemaRelation.PROVEN
            ):
                return False
            continue
        if (
            left_schema is not None
            and right_schema is not None
            and compare_operation_output(left_schema, right_schema).relation
            is not SchemaRelation.PROVEN
        ):
            return False
    return True


def _has_condition_cycle(conditions: Iterable[InteractionCondition]) -> bool:
    condition_list = tuple(conditions)
    targets = {condition.target_pointer for condition in condition_list}
    graph = {
        condition.target_pointer: {
            reference
            for reference in iter_condition_references(condition.expression)
            if reference in targets
        }
        for condition in condition_list
    }
    remaining = {node: set(edges) for node, edges in graph.items()}
    ready = sorted(node for node, edges in remaining.items() if not edges)
    while ready:
        completed = ready.pop(0)
        remaining.pop(completed, None)
        newly_ready: list[str] = []
        for node in sorted(remaining):
            edges = remaining[node]
            if completed in edges:
                edges.remove(completed)
                if not edges:
                    newly_ready.append(node)
        ready = sorted(set(ready) | set(newly_ready))
    return bool(remaining)


def _policy_allows_pointer(policy: Policy, pointer: str) -> bool:
    tokens = _tokens(pointer)
    if not tokens:
        return False
    dotted = ".".join(token for token in tokens if not token.isdecimal())
    readable = any(
        dotted == field or dotted.startswith(f"{field}.") for field in policy.readable_fields
    )
    denied = any(
        dotted == field or dotted.startswith(f"{field}.") for field in policy.denied_fields
    )
    return readable and not denied


def _called_operation_ids(capability: Capability) -> frozenset[str]:
    workflows = (
        [capability.preview_workflow, capability.commit_workflow]
        if isinstance(capability, ActionCapabilityV2)
        else [capability.workflow]
    )
    pending = [step for workflow in workflows for step in workflow]
    operation_ids: set[str] = set()
    while pending:
        step = pending.pop()
        if isinstance(step, CallStep):
            operation_ids.add(step.call.operation)
        elif isinstance(step, BranchStep):
            pending.extend(step.branch.then_steps)
            pending.extend(step.branch.else_steps)
        elif isinstance(step, ParallelStep):
            pending.extend(step.parallel)
        elif isinstance(step, ForeachStep):
            pending.extend(step.foreach.workflow)
    return frozenset(operation_ids)


def analyze_interaction_fidelity(
    *,
    project: Project,
    scope_inventory: ScopeInventory,
    ui_inventory: UIInteractionInventory,
    contracts: Mapping[str, CapabilityInteractionContract],
    capabilities: Mapping[str, Capability],
    operations: Mapping[str, Operation],
    policies: Mapping[str, Policy],
) -> InteractionValidationReport:
    """Conservatively prove interaction semantics without loading a client framework."""

    del project  # project identity is part of the public proof boundary, not a UI assumption
    diagnostics: list[Diagnostic] = []
    dependency_edges: set[tuple[str, str]] = set()
    routes = {route.id: route for route in scope_inventory.routes}
    interactions = {interaction.id: interaction for interaction in ui_inventory.interactions}
    interaction_positions = {
        interaction.id: index for index, interaction in enumerate(ui_inventory.interactions)
    }
    claim_source_ids = {
        claim.evidence.source_id
        for interaction in ui_inventory.interactions
        for claim in interaction.evidence_claims
    }
    declared_source_ids = set(ui_inventory.scope.evidence_sources) | {
        source_id for surface in ui_inventory.surfaces for source_id in surface.evidence_sources
    }
    if ui_inventory.interactions and (
        set(ui_inventory.scope.evidence_sources) - claim_source_ids
        or claim_source_ids - declared_source_ids
    ):
        _diagnostic(
            diagnostics,
            "ACC_UI_EVIDENCE_SOURCE_UNRESOLVED",
            "Inventory evidence source IDs and interaction claims must close exactly.",
            path="ui-interaction-inventory.yaml",
            pointer="/scope/evidence_sources",
        )
    for surface_index, surface in enumerate(ui_inventory.surfaces):
        surface_claim_sources = {
            claim.evidence.source_id
            for interaction in ui_inventory.interactions
            if interaction.surface_id == surface.id
            for claim in interaction.evidence_claims
        }
        if set(surface.evidence_sources) - surface_claim_sources:
            _diagnostic(
                diagnostics,
                "ACC_UI_EVIDENCE_SOURCE_UNRESOLVED",
                "Surface evidence source IDs must resolve to its interaction claims.",
                path="ui-interaction-inventory.yaml",
                pointer=f"/surfaces/{surface_index}/evidence_sources",
            )

    for index, interaction in enumerate(ui_inventory.interactions):
        path = "ui-interaction-inventory.yaml"
        subtree = f"/interactions/{index}"
        authoritative_claims = tuple(
            claim
            for claim in interaction.evidence_claims
            if claim.authority in _AUTHORITATIVE_CLAIM_AUTHORITIES
        )
        if not authoritative_claims or any(
            claim.target_pointer != subtree and not claim.target_pointer.startswith(f"{subtree}/")
            for claim in authoritative_claims
        ):
            _diagnostic(
                diagnostics,
                "ACC_UI_INTERACTION_EVIDENCE_MISSING",
                "Interaction requires immutable evidence claims.",
                path=path,
                pointer=f"/interactions/{index}/evidence_claims",
            )
        for route_index, route_id in enumerate(interaction.route_ids):
            if route_id not in routes:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_INTERACTION_ROUTE_UNKNOWN",
                    "Interaction route must exist in Scope Inventory.",
                    path=path,
                    pointer=f"/interactions/{index}/route_ids/{route_index}",
                )
            elif interaction.id not in routes[route_id].interaction_ids:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_INTERACTION_ROUTE_OWNERSHIP_MISMATCH",
                    "Interaction and Scope route ownership must agree bidirectionally.",
                    path=path,
                    pointer=f"/interactions/{index}/route_ids/{route_index}",
                )

    for route_index, route in enumerate(scope_inventory.routes):
        for link_index, interaction_id in enumerate(route.interaction_ids):
            linked_interaction = interactions.get(interaction_id)
            if linked_interaction is None or route.id not in linked_interaction.route_ids:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_INTERACTION_ROUTE_OWNERSHIP_MISMATCH",
                    "Scope route and Interaction ownership must agree bidirectionally.",
                    path="scope-inventory.yaml",
                    pointer=f"/routes/{route_index}/interaction_ids/{link_index}",
                )

    if ui_inventory.scope.mode == "complete":
        classified = {
            interaction_id
            for contract in contracts.values()
            for interaction_id in contract.interaction_ids
        } | {
            omission.interaction_id
            for contract in contracts.values()
            for omission in contract.omissions
        }
        if ui_inventory.summary.unresolved or set(interactions) - classified:
            _diagnostic(
                diagnostics,
                "ACC_UI_SURFACE_COVERAGE_INCOMPLETE",
                "Complete interaction scope cannot contain unresolved or "
                "unclassified interactions.",
                path="ui-interaction-inventory.yaml",
                pointer="/summary/unresolved",
            )

    for capability_id, contract in sorted(contracts.items()):
        path = f"interaction-contracts/{capability_id}.yaml"
        capability = capabilities.get(contract.capability_id)
        if capability is None:
            _diagnostic(
                diagnostics,
                "ACC_UI_INTERACTION_CONTRACT_MISSING",
                "Interaction contract must reference an existing Capability.",
                path=path,
                pointer="/capability_id",
            )
            continue
        policy = policies.get(capability.policy)
        dependency_operation_ids = _called_operation_ids(capability)
        adopted_evidence = _adopted_evidence(contract, interactions)

        for offset, interaction_id in enumerate(contract.interaction_ids):
            if interaction_id not in interactions:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_INTERACTION_CONTRACT_MISSING",
                    "Adopted interaction must exist in the UI inventory.",
                    path=path,
                    pointer=f"/interaction_ids/{offset}",
                )
                continue
            for route_id in interactions[interaction_id].route_ids:
                linked_route = routes.get(route_id)
                if linked_route is not None and not (
                    linked_route.operation_id in dependency_operation_ids
                    or capability_id in linked_route.capability_ids
                ):
                    _diagnostic(
                        diagnostics,
                        "ACC_UI_INTERACTION_ROUTE_CAPABILITY_MISMATCH",
                        "Adopted routes must belong to the Capability or its workflow operations.",
                        path=path,
                        pointer=f"/interaction_ids/{offset}",
                    )

        for offset, binding in enumerate(
            [*contract.public_input_bindings, *contract.trusted_input_bindings]
        ):
            if (
                _schema_at_data_pointer(capability.input_schema, binding.target_pointer) is None
                or binding.evidence not in adopted_evidence
            ):
                _diagnostic(
                    diagnostics,
                    "ACC_UI_INPUT_SOURCE_UNRESOLVED",
                    "Input binding must resolve to an evidenced Capability input.",
                    path=path,
                    pointer=f"/public_input_bindings/{offset}",
                )

        for offset, default in enumerate(contract.defaults):
            target_schema = _schema_at_data_pointer(capability.input_schema, default.target_pointer)
            invalid_literal = (
                default.source_kind == "literal"
                and target_schema is not None
                and not _schema_accepts(
                    capability.input_schema,
                    target_schema,
                    default.value,
                )
            )
            if (
                target_schema is None
                or invalid_literal
                or default.authority == "observation"
                or default.evidence not in adopted_evidence
            ):
                _diagnostic(
                    diagnostics,
                    "ACC_UI_DEFAULT_AUTHORITY_UNPROVEN",
                    "Default value and authority must be evidenced against the Capability input.",
                    path=path,
                    pointer=f"/defaults/{offset}",
                )

        for offset, option in enumerate(contract.option_sources):
            target_schema = _schema_at_data_pointer(capability.input_schema, option.target_pointer)
            proven = target_schema is not None and option.evidence in adopted_evidence
            schemas = (
                _producer_schemas(
                    option.source_kind,
                    option.producer_id,
                    capabilities,
                    operations,
                )
                if option.source_kind != "static" and option.producer_id is not None
                else None
            )
            if option.source_kind == "static":
                proven = (
                    proven
                    and target_schema is not None
                    and all(
                        _schema_accepts(
                            capability.input_schema,
                            target_schema,
                            item.value,
                        )
                        for item in option.static_options
                    )
                )
            elif schemas is None:
                proven = False
            else:
                producer_input, producer_output = schemas
                items_schema = _relative_schema(producer_output, option.items_pointer)
                item_schema = (
                    _dereference(producer_output, items_schema.get("items"))
                    if isinstance(items_schema, dict)
                    and isinstance(items_schema.get("items"), dict)
                    else items_schema
                )
                value_schema = (
                    _relative_schema(
                        item_schema,
                        option.value_pointer,
                        root_schema=producer_output,
                    )
                    if isinstance(item_schema, dict)
                    else None
                )
                label_schema = (
                    _relative_schema(
                        item_schema,
                        option.label_pointer,
                        root_schema=producer_output,
                    )
                    if isinstance(item_schema, dict)
                    else None
                )
                if (
                    value_schema is None
                    or label_schema is None
                    or target_schema is None
                    or compare_operation_output(value_schema, target_schema).relation
                    is not SchemaRelation.PROVEN
                ):
                    proven = False
                for request_binding in option.request_bindings:
                    source_schema = _schema_at_data_pointer(
                        capability.input_schema, request_binding.source_pointer or ""
                    )
                    request_schema = _schema_at_data_pointer(
                        producer_input, request_binding.target_pointer
                    )
                    if (
                        source_schema is None
                        or request_schema is None
                        or compare_operation_input(source_schema, request_schema).relation
                        is not SchemaRelation.PROVEN
                    ):
                        proven = False
                dependency_edges.add((option.producer_id or "", capability_id))
            if not proven:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_OPTION_SOURCE_UNTRACED",
                    "Option producer, mappings, and request bindings must be schema-proven.",
                    path=path,
                    pointer=f"/option_sources/{offset}",
                )

        trusted_bindings = {
            binding.target_pointer: binding for binding in contract.trusted_input_bindings
        }
        trusted_targets = set(trusted_bindings)
        for offset, condition in enumerate(contract.conditions):
            references = set(iter_condition_references(condition.expression))
            if (
                condition.evidence not in adopted_evidence
                or _schema_at_data_pointer(capability.input_schema, condition.target_pointer)
                is None
                or not _condition_type_is_proven(condition.expression, capability.input_schema)
            ):
                _diagnostic(
                    diagnostics,
                    "ACC_UI_CONDITION_AUTHORITY_UNPROVEN",
                    "Condition references and operand types must be evidenced by "
                    "Capability inputs.",
                    path=path,
                    pointer=f"/conditions/{offset}",
                )
            relevant_trusted_bindings = [
                trusted_bindings[pointer] for pointer in sorted(references & trusted_targets)
            ]
            trusted_sources_authorized = bool(relevant_trusted_bindings) and all(
                binding.source_id in dependency_operation_ids
                and binding.source_id in operations
                and bool(operations[binding.source_id].http.scopes)
                for binding in relevant_trusted_bindings
            )
            if (
                condition.target in {"visible", "enabled"}
                and relevant_trusted_bindings
                and not trusted_sources_authorized
            ):
                _diagnostic(
                    diagnostics,
                    "ACC_UI_HIDDEN_NOT_AUTHORIZATION",
                    "Hidden or disabled UI state cannot replace source authorization.",
                    path=path,
                    pointer=f"/conditions/{offset}",
                )
        if _has_condition_cycle(contract.conditions):
            _diagnostic(
                diagnostics,
                "ACC_UI_CONDITION_CYCLE",
                "Condition dependency graph must be acyclic.",
                path=path,
                pointer="/conditions",
            )

        for offset, related in enumerate(contract.related_data):
            schemas = _producer_schemas(
                related.producer_kind,
                related.producer_id,
                capabilities,
                operations,
            )
            proven = schemas is not None and related.evidence in adopted_evidence
            if schemas is not None:
                _, producer_output = schemas
                output_schema = _schema_at_data_pointer(producer_output, related.output_pointer)
                target_schema = _schema_at_data_pointer(
                    capability.input_schema, related.target_pointer
                ) or _schema_at_data_pointer(capability.output_schema, related.target_pointer)
                if (
                    output_schema is None
                    or target_schema is None
                    or (
                        compare_operation_output(output_schema, target_schema).relation
                        is not SchemaRelation.PROVEN
                    )
                ):
                    proven = False
                dependency_edges.add((related.producer_id, capability_id))
            if not proven:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_RELATED_DATA_DEPENDENCY_BROKEN",
                    "Related-data producer and consumer schemas must be compatible.",
                    path=path,
                    pointer=f"/related_data/{offset}",
                )

        for offset, consumption in enumerate(contract.result_consumption):
            source_schema = _schema_at_data_pointer(
                capability.output_schema, consumption.source_pointer
            )
            pointers: list[str] = []
            for field_pointer in consumption.field_pointers:
                if (
                    source_schema is None
                    or _relative_schema(
                        source_schema,
                        field_pointer,
                        root_schema=capability.output_schema,
                    )
                    is None
                ):
                    source_schema = None
                    break
                pointers.append(f"{consumption.source_pointer.rstrip('/')}{field_pointer}")
            if not consumption.field_pointers:
                pointers.append(consumption.source_pointer)
            if (
                source_schema is None
                or policy is None
                or consumption.evidence not in adopted_evidence
                or any(not _policy_allows_pointer(policy, pointer) for pointer in pointers)
            ):
                _diagnostic(
                    diagnostics,
                    "ACC_UI_PRESENTATION_FIELD_UNPROVEN",
                    "Presentation fields must exist in policy-visible Capability output.",
                    path=path,
                    pointer=f"/result_consumption/{offset}",
                )

        if isinstance(capability, ActionCapabilityV2):
            lifecycle = contract.action_lifecycle
            lifecycle_interaction = (
                interactions.get(lifecycle.interaction_id) if lifecycle is not None else None
            )
            lifecycle_root = (
                f"/interactions/{interaction_positions[lifecycle.interaction_id]}"
                if lifecycle is not None and lifecycle.interaction_id in interaction_positions
                else None
            )
            lifecycle_phases = (
                (
                    lifecycle.prepare,
                    lifecycle.approve,
                    lifecycle.commit,
                    lifecycle.status,
                )
                if lifecycle is not None
                else ()
            )
            lifecycle_claims_proven = (
                lifecycle_interaction is not None
                and lifecycle_root is not None
                and all(
                    phase.target_pointer.startswith(f"{lifecycle_root}/")
                    and any(
                        claim.target_pointer == phase.target_pointer
                        and claim.evidence == phase.evidence
                        and claim.authority in _AUTHORITATIVE_CLAIM_AUTHORITIES
                        for claim in lifecycle_interaction.evidence_claims
                    )
                    for phase in lifecycle_phases
                )
            )
            lifecycle_route_proven = lifecycle_interaction is not None and any(
                route is not None
                and route.kind == "action"
                and (
                    route.operation_id in dependency_operation_ids
                    or capability_id in route.capability_ids
                )
                for route in (routes.get(route_id) for route_id in lifecycle_interaction.route_ids)
            )
            lifecycle_proven = (
                lifecycle is not None
                and lifecycle.interaction_id in contract.interaction_ids
                and len(lifecycle_phases) == 4
                and lifecycle_claims_proven
                and lifecycle_route_proven
            )
            if not lifecycle_proven:
                _diagnostic(
                    diagnostics,
                    "ACC_UI_ACTION_LIFECYCLE_REQUIRED",
                    "Action interactions must use prepare, approve, commit, and status lifecycle.",
                    path=path,
                    pointer="/action_lifecycle",
                )

    diagnostics.sort(
        key=lambda item: (
            item.path or "",
            item.pointer or "",
            item.code,
            item.message,
        )
    )
    return InteractionValidationReport(
        diagnostics=tuple(diagnostics),
        interaction_ids=tuple(sorted(interactions)),
        dependency_edges=tuple(sorted(edge for edge in dependency_edges if edge[0])),
    )


__all__ = ["InteractionValidationReport", "analyze_interaction_fidelity"]
