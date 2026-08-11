"""Deterministic proofs for cross-tool Agent Usage contracts."""

from __future__ import annotations

import hashlib
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from jsonschema import Draft202012Validator

from acc_core.contracts.schema_relation import SchemaRelation, compare_operation_output
from acc_core.diagnostics import Diagnostic
from acc_core.interactions.expressions import iter_condition_references
from acc_core.models import JsonObject
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage.acceptance import McpReleaseAcceptanceVerification
from acc_core.usage.models import DomainUsageContract, UsageToolRoute, UsageToolStep
from acc_core.usage.project import UsageProjectReport

_HTTP_FAILURES = frozenset({"unauthorized", "forbidden", "not_found", "timeout"})
_ACTION_PROOF_FIELDS = frozenset(
    {
        "approval_required",
        "effects",
        "maximum_risk",
        "mutation_operation_ids",
        "operation_semantics",
        "required_scopes",
    }
)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class UsageAnalysisReport:
    """Stable, secret-free outcome of deterministic Usage analysis."""

    domain_id: str
    diagnostics: tuple[Diagnostic, ...]
    capability_ids: tuple[str, ...] = ()
    tool_names: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)

    @property
    def trusted(self) -> bool:
        return _is_live_analysis(self)


def _analysis_fingerprint(value: UsageAnalysisReport) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "capability_ids": value.capability_ids,
                "diagnostics": [item.model_dump(mode="json") for item in value.diagnostics],
                "domain_id": value.domain_id,
                "tool_names": value.tool_names,
            }
        )
    ).hexdigest()


def _plain_json(value: Any) -> Any:
    """Thaw verified immutable snapshots without changing canonical JSON content."""

    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


class _Analyzer:
    def __init__(
        self,
        project: UsageProjectReport,
        release: McpReleaseAcceptanceVerification,
        domain_id: str,
    ) -> None:
        self.project = project
        self.release = release
        self.domain_id = domain_id
        self.diagnostics: list[Diagnostic] = []
        self.capability_ids: set[str] = set()
        self.tool_names: set[str] = set()

    def error(self, code: str, message: str, *, pointer: str = "") -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                severity="error",
                message=message,
                path="domain-usage-contracts",
                pointer=pointer,
            )
        )

    def run(self) -> UsageAnalysisReport:
        if not self.project.ok:
            self.error(
                "ACC_USAGE_PROJECT_INVALID",
                "Usage analysis requires a valid independently loaded Usage project.",
            )
            return self.report()
        if (
            not self.release.ok
            or self.release.compiled_ir is None
            or self.release.tool_snapshot is None
        ):
            self.error(
                "ACC_USAGE_ACCEPTED_RELEASE_REQUIRED",
                "A verified accepted MCP release is required for Usage analysis.",
            )
            return self.report()
        if self.domain_id not in self.release.accepted_domain_ids:
            self.error(
                "ACC_USAGE_DOMAIN_NOT_ACCEPTED",
                "The requested domain is not part of the accepted MCP release.",
            )
            return self.report()
        contract = self.project.domain_contracts.get(self.domain_id)
        if contract is None:
            self.error(
                "ACC_USAGE_DOMAIN_CONTRACT_MISSING",
                "The requested domain has no Usage contract.",
            )
            return self.report()

        ir = self.release.compiled_ir
        capabilities = ir.get("capabilities")
        if not isinstance(capabilities, Mapping):
            self.error("ACC_USAGE_COMPILED_IR_INVALID", "Compiled capability inventory is invalid.")
            return self.report()
        tools = self._tools(self.release.tool_snapshot)
        self._verify_interactions(ir)
        self._analyze_contract(contract, capabilities, tools)
        return self.report()

    def report(self) -> UsageAnalysisReport:
        return UsageAnalysisReport(
            domain_id=self.domain_id,
            diagnostics=tuple(self.diagnostics),
            capability_ids=tuple(sorted(self.capability_ids)),
            tool_names=tuple(sorted(self.tool_names)),
        )

    def _tools(self, snapshot: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
        values = snapshot.get("tools")
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            self.error("ACC_USAGE_TOOL_SNAPSHOT_INVALID", "The frozen Tool snapshot is invalid.")
            return {}
        result: dict[str, list[Mapping[str, Any]]] = {}
        for value in values:
            if not isinstance(value, Mapping) or not isinstance(value.get("name"), str):
                self.error(
                    "ACC_USAGE_TOOL_SNAPSHOT_INVALID", "The frozen Tool snapshot is invalid."
                )
                continue
            result.setdefault(cast(str, value["name"]), []).append(value)
        return result

    def _verify_interactions(self, ir: Mapping[str, Any]) -> None:
        value = ir.get("interactions")
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "digest",
            "inventory",
            "contracts",
            "dependencies",
        }:
            self.error(
                "ACC_USAGE_INTERACTION_DIGEST_INVALID",
                "The compiled Interaction attestation is invalid.",
            )
            return
        digest = value.get("digest")
        payload = {key: item for key, item in value.items() if key != "digest"}
        try:
            actual = hashlib.sha256(canonical_json_bytes(_plain_json(payload))).hexdigest()
        except ValueError:
            actual = ""
        if (
            not isinstance(digest, str)
            or digest != actual
            or ir.get("interaction_sha256") != digest
        ):
            self.error(
                "ACC_USAGE_INTERACTION_DIGEST_INVALID",
                "The compiled Interaction attestation is invalid.",
            )

    def _analyze_contract(
        self,
        contract: DomainUsageContract,
        capabilities: Mapping[str, Any],
        tools: Mapping[str, list[Mapping[str, Any]]],
    ) -> None:
        if not contract.business_goals or not contract.tool_routes:
            self.error(
                "ACC_USAGE_ROUTE_EMPTY",
                "A Usage domain must declare a business goal and at least one route.",
            )
            return
        step_by_id = {step.id: step for route in contract.tool_routes for step in route.steps}
        definitions: dict[str, Mapping[str, Any]] = {}
        for route_index, route in enumerate(contract.tool_routes):
            self._analyze_route(
                contract,
                route,
                route_index,
                capabilities,
                tools,
                definitions,
            )
        self._analyze_bindings(contract, step_by_id, definitions)
        self._analyze_defaults(contract, definitions)
        self._analyze_options(contract, definitions)
        self._analyze_related_data(contract, definitions)
        self._analyze_result_consumption(contract, step_by_id, definitions, tools)
        self._analyze_conditions(contract, step_by_id, definitions)
        self._analyze_empty_stops(contract, step_by_id)
        self._analyze_actions(contract, capabilities, tools)

    def _analyze_route(
        self,
        contract: DomainUsageContract,
        route: UsageToolRoute,
        route_index: int,
        capabilities: Mapping[str, Any],
        tools: Mapping[str, list[Mapping[str, Any]]],
        definitions: dict[str, Mapping[str, Any]],
    ) -> None:
        outcomes = {
            outcome
            for branch in contract.error_handling
            if branch.id in route.error_branch_ids
            for outcome in branch.outcomes
        }
        if not outcomes >= _HTTP_FAILURES:
            self.error(
                "ACC_USAGE_ERROR_BRANCH_MISSING",
                "Each route must handle unauthorized, forbidden, not-found, and timeout outcomes.",
                pointer=f"/tool_routes/{route_index}/error_branch_ids",
            )
        for step_index, step in enumerate(route.steps):
            pointer = f"/tool_routes/{route_index}/steps/{step_index}"
            compiled = capabilities.get(step.capability_id)
            if not isinstance(compiled, Mapping):
                self.error(
                    "ACC_USAGE_CAPABILITY_NOT_FOUND",
                    "A route step references an unknown compiled Capability.",
                    pointer=f"{pointer}/capability_id",
                )
                continue
            definition = compiled.get("definition")
            if not isinstance(definition, Mapping):
                self.error(
                    "ACC_USAGE_COMPILED_IR_INVALID",
                    "A compiled Capability definition is invalid.",
                    pointer=f"{pointer}/capability_id",
                )
                continue
            definitions[step.id] = definition
            self.capability_ids.add(step.capability_id)
            candidates = tools.get(step.tool_name, [])
            if len(candidates) != 1:
                self.error(
                    "ACC_USAGE_TOOL_SELECTION_AMBIGUOUS",
                    "A route step must select exactly one frozen Tool by its exact name.",
                    pointer=f"{pointer}/tool_name",
                )
                continue
            tool = candidates[0]
            self.tool_names.add(step.tool_name)
            self._verify_tool_projection(step, definition, tool, pointer)
            self._required_inputs_constructable(contract, step, definition, pointer)

    def _verify_tool_projection(
        self,
        step: UsageToolStep,
        definition: Mapping[str, Any],
        tool: Mapping[str, Any],
        pointer: str,
    ) -> None:
        kind = definition.get("kind")
        expected_name = step.capability_id if kind == "read" else self._action_tool_name(step)
        if expected_name != step.tool_name:
            self.error(
                "ACC_USAGE_TOOL_CAPABILITY_MISMATCH",
                "The exact Tool selection does not match its compiled Capability phase.",
                pointer=f"{pointer}/tool_name",
            )
        input_schema = definition.get("input_schema")
        if step.action_phase in {None, "prepare"} and tool.get("inputSchema") != input_schema:
            self.error(
                "ACC_USAGE_TOOL_SCHEMA_MISMATCH",
                "The frozen Tool input schema does not match the compiled Capability.",
                pointer=f"{pointer}/tool_name",
            )
        if kind == "read":
            output = tool.get("outputSchema")
            projected = (
                output.get("properties", {}).get("result") if isinstance(output, Mapping) else None
            )
            if not _projected_output_matches(projected, definition.get("output_schema")):
                self.error(
                    "ACC_USAGE_TOOL_SCHEMA_MISMATCH",
                    "The frozen Tool output schema does not match the compiled Capability.",
                    pointer=f"{pointer}/tool_name",
                )

    @staticmethod
    def _action_tool_name(step: UsageToolStep) -> str | None:
        if step.action_phase is None:
            return None
        names = {
            "prepare": f"{step.capability_id}.prepare",
            "approve": "acc_action_approve",
            "commit": "acc_action_commit",
            "status": "acc_action_status",
        }
        return names.get(step.action_phase)

    def _required_inputs_constructable(
        self,
        contract: DomainUsageContract,
        step: UsageToolStep,
        definition: Mapping[str, Any],
        pointer: str,
    ) -> None:
        if step.action_phase in {"approve", "commit", "status"}:
            return
        schema = definition.get("input_schema")
        if not isinstance(schema, Mapping):
            self.error("ACC_USAGE_COMPILED_IR_INVALID", "A compiled input schema is invalid.")
            return
        supplied = {
            binding.target_pointer
            for binding in contract.input_bindings
            if binding.consumer_step_id == step.id
        }
        supplied.update(
            default.target_pointer for default in contract.defaults if default.step_id == step.id
        )
        required_pointers = _required_leaf_pointers(schema)
        if required_pointers is None:
            self.error("ACC_USAGE_COMPILED_IR_INVALID", "A compiled input schema is invalid.")
            return
        if any(
            not any(required == target or required.startswith(target + "/") for target in supplied)
            for required in required_pointers
        ):
            self.error(
                "ACC_USAGE_REQUIRED_INPUT_UNCONSTRUCTABLE",
                "A required Tool input is not constructable from declared bindings or defaults.",
                pointer=f"{pointer}/binding_ids",
            )

    def _analyze_bindings(
        self,
        contract: DomainUsageContract,
        step_by_id: Mapping[str, UsageToolStep],
        definitions: Mapping[str, Mapping[str, Any]],
    ) -> None:
        for index, binding in enumerate(contract.input_bindings):
            pointer = f"/input_bindings/{index}"
            if (
                binding.source_kind in {"public_input", "route_input"}
                and binding.value_kind != "public_value"
            ):
                self.error(
                    "ACC_USAGE_TRUST_BOUNDARY_INVALID",
                    "Public input cannot construct trusted Action or approval handles.",
                    pointer=f"{pointer}/value_kind",
                )
            if binding.source_kind == "trusted_context" and binding.value_kind != "approval_handle":
                self.error(
                    "ACC_USAGE_TRUST_BOUNDARY_INVALID",
                    "Trusted context is reserved for the runtime-owned approval handle.",
                    pointer=f"{pointer}/value_kind",
                )
            if binding.source_kind != "prior_step_output":
                continue
            source = definitions.get(cast(str, binding.source_step_id))
            consumer = definitions.get(binding.consumer_step_id)
            if source is None or consumer is None:
                continue
            source_schema = source.get("output_schema")
            target_schema = consumer.get("input_schema")
            if not isinstance(source_schema, Mapping) or not isinstance(target_schema, Mapping):
                self.error("ACC_USAGE_COMPILED_IR_INVALID", "A compiled Tool schema is invalid.")
                continue
            selected_source = _schema_at_pointer(source_schema, binding.source_pointer)
            selected_target = _schema_at_pointer(target_schema, binding.target_pointer)
            if selected_source is None or not _schema_pointer_is_guaranteed(
                source_schema, binding.source_pointer
            ):
                self.error(
                    "ACC_USAGE_BINDING_SOURCE_NOT_GUARANTEED",
                    "A prior-step output binding is not guaranteed by its producer schema.",
                    pointer=f"{pointer}/source_pointer",
                )
                continue
            if selected_target is None:
                self.error(
                    "ACC_USAGE_BINDING_TARGET_INVALID",
                    "A binding target is not declared by its consumer schema.",
                    pointer=f"{pointer}/target_pointer",
                )
                continue
            if binding.mapping is not None:
                self.error(
                    "ACC_USAGE_BINDING_MAPPING_UNPROVEN",
                    "A transformed binding requires an independently proven output schema.",
                    pointer=f"{pointer}/mapping",
                )
                continue
            relation = compare_operation_output(selected_source, selected_target)
            if relation.relation is not SchemaRelation.PROVEN:
                self.error(
                    "ACC_USAGE_BINDING_SCHEMA_UNPROVEN",
                    "A producer output is not proven compatible with its consumer input.",
                    pointer=f"{pointer}/target_pointer",
                )

    def _analyze_empty_stops(
        self,
        contract: DomainUsageContract,
        step_by_id: Mapping[str, UsageToolStep],
    ) -> None:
        for index, option in enumerate(contract.option_sources):
            if option.empty_behavior != "stop":
                continue
            relevant_steps = {option.consumer_step_id}
            if option.producer_step_id is not None:
                relevant_steps.add(option.producer_step_id)
            handled = any(
                branch.behavior == "stop"
                and bool(relevant_steps & set(branch.step_ids))
                and bool({"empty", "empty_result"} & set(branch.outcomes))
                for branch in contract.error_handling
            )
            if not handled:
                self.error(
                    "ACC_USAGE_EMPTY_STOP_UNHANDLED",
                    "An option source with empty-stop semantics needs an explicit empty branch.",
                    pointer=f"/option_sources/{index}/empty_behavior",
                )

    def _analyze_defaults(
        self,
        contract: DomainUsageContract,
        definitions: Mapping[str, Mapping[str, Any]],
    ) -> None:
        bindings = {binding.id: binding for binding in contract.input_bindings}
        for index, default in enumerate(contract.defaults):
            pointer = f"/defaults/{index}"
            definition = definitions.get(default.step_id)
            schema = definition.get("input_schema") if definition else None
            target = (
                _schema_at_pointer(schema, default.target_pointer)
                if isinstance(schema, Mapping)
                else None
            )
            if target is None:
                self.error(
                    "ACC_USAGE_DEFAULT_TARGET_INVALID",
                    "A default target is not declared by its consumer Tool input schema.",
                    pointer=f"{pointer}/target_pointer",
                )
                continue
            assert isinstance(schema, Mapping)
            if default.source == "literal":
                if not Draft202012Validator(target).is_valid(default.value):
                    self.error(
                        "ACC_USAGE_DEFAULT_VALUE_INVALID",
                        "A literal default is rejected by its consumer Tool input schema.",
                        pointer=f"{pointer}/value",
                    )
            elif default.source == "source_default":
                if "default" not in target or not Draft202012Validator(target).is_valid(
                    target.get("default")
                ):
                    self.error(
                        "ACC_USAGE_SOURCE_DEFAULT_UNPROVEN",
                        "A source default requires an explicit valid compiled schema default.",
                        pointer=f"{pointer}/source",
                    )
            else:
                binding = bindings.get(cast(str, default.reference_binding_id))
                if binding is None or binding.consumer_step_id != default.step_id:
                    self.error(
                        "ACC_USAGE_DEFAULT_BINDING_INVALID",
                        "A binding default must reference a binding for the same consumer step.",
                        pointer=f"{pointer}/reference_binding_id",
                    )
                    continue
                binding_target = _schema_at_pointer(schema, binding.target_pointer)
                if (
                    binding_target is None
                    or compare_operation_output(binding_target, target).relation
                    is not SchemaRelation.PROVEN
                ):
                    self.error(
                        "ACC_USAGE_DEFAULT_BINDING_UNPROVEN",
                        "A referenced binding is not proven compatible with the default target.",
                        pointer=f"{pointer}/reference_binding_id",
                    )

    def _analyze_options(
        self,
        contract: DomainUsageContract,
        definitions: Mapping[str, Mapping[str, Any]],
    ) -> None:
        for index, option in enumerate(contract.option_sources):
            pointer = f"/option_sources/{index}"
            consumer = definitions.get(option.consumer_step_id)
            consumer_schema = consumer.get("input_schema") if consumer else None
            target = (
                _schema_at_pointer(consumer_schema, option.target_pointer)
                if isinstance(consumer_schema, Mapping)
                else None
            )
            if target is None:
                self.error(
                    "ACC_USAGE_OPTION_TARGET_INVALID",
                    "An option target is not declared by its consumer Tool input schema.",
                    pointer=f"{pointer}/target_pointer",
                )
                continue
            if option.source == "static":
                if any(
                    not Draft202012Validator(target).is_valid(item.value)
                    for item in option.static_items
                ):
                    self.error(
                        "ACC_USAGE_OPTION_STATIC_VALUE_INVALID",
                        "A static option value is rejected by its consumer Tool input schema.",
                        pointer=f"{pointer}/static_items",
                    )
                continue
            producer = definitions.get(cast(str, option.producer_step_id))
            output = producer.get("output_schema") if producer else None
            if producer is None or not isinstance(output, Mapping):
                continue
            items_schema = _schema_at_pointer(output, cast(str, option.items_pointer))
            if (
                items_schema is None
                or items_schema.get("type") != "array"
                or not isinstance(items_schema.get("items"), Mapping)
                or not _schema_pointer_is_guaranteed(output, cast(str, option.items_pointer))
            ):
                self.error(
                    "ACC_USAGE_OPTION_ITEMS_UNPROVEN",
                    "Producer option items are not guaranteed as a declared array.",
                    pointer=f"{pointer}/items_pointer",
                )
                continue
            item_schema = cast(Mapping[str, Any], items_schema["items"])
            value_schema = _schema_at_pointer(item_schema, cast(str, option.value_pointer))
            label_schema = _schema_at_pointer(item_schema, cast(str, option.label_pointer))
            if (
                value_schema is None
                or label_schema is None
                or not _schema_pointer_is_guaranteed(item_schema, cast(str, option.value_pointer))
                or not _schema_pointer_is_guaranteed(item_schema, cast(str, option.label_pointer))
            ):
                self.error(
                    "ACC_USAGE_OPTION_ITEM_FIELDS_UNPROVEN",
                    "Option value and label fields must be guaranteed by each producer item.",
                    pointer=f"{pointer}/value_pointer",
                )
            elif (
                compare_operation_output(value_schema, target).relation is not SchemaRelation.PROVEN
            ):
                self.error(
                    "ACC_USAGE_OPTION_VALUE_SCHEMA_UNPROVEN",
                    "Producer option values are not proven compatible with the consumer input.",
                    pointer=f"{pointer}/value_pointer",
                )
            self._analyze_option_controls(contract, option, producer, pointer)

    def _analyze_option_controls(
        self,
        contract: DomainUsageContract,
        option: Any,
        producer: Mapping[str, Any],
        pointer: str,
    ) -> None:
        input_schema = producer.get("input_schema")
        if not isinstance(input_schema, Mapping):
            return
        properties = input_schema.get("properties")
        if not isinstance(properties, Mapping):
            properties = {}
        supplied = {
            binding.target_pointer.removeprefix("/").split("/", 1)[0]
            for binding in contract.input_bindings
            if binding.consumer_step_id == option.producer_step_id
        } | {
            default.target_pointer.removeprefix("/").split("/", 1)[0]
            for default in contract.defaults
            if default.step_id == option.producer_step_id
        }
        controls = {
            "search": ({"query", "search", "keyword"}, option.search),
            "paging": ({"page", "cursor", "offset", "limit"}, option.paging),
        }
        for name, (candidates, mode) in controls.items():
            available = candidates & set(properties)
            if mode == "required" and (not available or not available & supplied):
                self.error(
                    "ACC_USAGE_OPTION_CONTROL_UNCONSTRUCTABLE",
                    "A required option search or paging control is not constructable.",
                    pointer=f"{pointer}/{name}",
                )

    def _analyze_related_data(
        self,
        contract: DomainUsageContract,
        definitions: Mapping[str, Mapping[str, Any]],
    ) -> None:
        for index, related in enumerate(contract.related_data):
            pointer = f"/related_data/{index}"
            producer = definitions.get(related.producer_step_id)
            consumer = definitions.get(related.consumer_step_id)
            output = producer.get("output_schema") if producer else None
            input_schema = consumer.get("input_schema") if consumer else None
            source = (
                _schema_at_pointer(output, related.producer_pointer)
                if isinstance(output, Mapping)
                else None
            )
            target = (
                _schema_at_pointer(input_schema, related.target_pointer)
                if isinstance(input_schema, Mapping)
                else None
            )
            if (
                source is None
                or not isinstance(output, Mapping)
                or not _schema_pointer_is_guaranteed(output, related.producer_pointer)
            ):
                self.error(
                    "ACC_USAGE_RELATED_SOURCE_UNPROVEN",
                    "Related producer data is not guaranteed by its public output schema.",
                    pointer=f"{pointer}/producer_pointer",
                )
                continue
            if target is None:
                self.error(
                    "ACC_USAGE_RELATED_TARGET_INVALID",
                    "Related consumer data is not declared by its Tool input schema.",
                    pointer=f"{pointer}/target_pointer",
                )
                continue
            is_array = source.get("type") == "array"
            if (related.cardinality == "many") != is_array:
                self.error(
                    "ACC_USAGE_RELATED_CARDINALITY_UNPROVEN",
                    "Related data cardinality is not proven by the producer schema.",
                    pointer=f"{pointer}/cardinality",
                )
            if compare_operation_output(source, target).relation is not SchemaRelation.PROVEN:
                self.error(
                    "ACC_USAGE_RELATED_SCHEMA_UNPROVEN",
                    "Related producer data is not proven compatible with its consumer input.",
                    pointer=f"{pointer}/target_pointer",
                )

    def _analyze_result_consumption(
        self,
        contract: DomainUsageContract,
        step_by_id: Mapping[str, UsageToolStep],
        definitions: Mapping[str, Mapping[str, Any]],
        tools: Mapping[str, list[Mapping[str, Any]]],
    ) -> None:
        for index, consumption in enumerate(contract.result_consumption):
            step = step_by_id.get(consumption.step_id)
            if step is None:
                continue
            output = _public_output_schema(step, definitions.get(step.id), tools)
            for field_index, field_pointer in enumerate(consumption.field_pointers):
                if (
                    output is None
                    or _schema_at_pointer(output, field_pointer) is None
                    or not _schema_pointer_is_guaranteed(output, field_pointer)
                ):
                    self.error(
                        "ACC_USAGE_RESULT_POINTER_INVALID",
                        "Result consumption must reference a guaranteed public Tool result field.",
                        pointer=(f"/result_consumption/{index}/field_pointers/{field_index}"),
                    )

    def _analyze_conditions(
        self,
        contract: DomainUsageContract,
        step_by_id: Mapping[str, UsageToolStep],
        definitions: Mapping[str, Mapping[str, Any]],
    ) -> None:
        routes = {route.id: route for route in contract.tool_routes}
        for index, condition in enumerate(contract.conditions):
            route = routes.get(condition.route_id)
            if route is None:
                continue
            prior_ids: set[str] = set()
            if condition.step_id is not None:
                pending = list(step_by_id[condition.step_id].depends_on_step_ids)
                while pending:
                    step_id = pending.pop()
                    if step_id not in prior_ids:
                        prior_ids.add(step_id)
                        pending.extend(step_by_id[step_id].depends_on_step_ids)
            public_pointers = {
                binding.source_pointer
                for binding in contract.input_bindings
                if binding.source_kind in {"public_input", "route_input"}
                and binding.consumer_step_id in {step.id for step in route.steps}
            }
            for reference in iter_condition_references(condition.expression):
                matches = int(reference in public_pointers) + sum(
                    1
                    for step_id in prior_ids
                    if (definition := definitions.get(step_id)) is not None
                    and isinstance(definition.get("output_schema"), Mapping)
                    and _schema_pointer_is_guaranteed(
                        cast(Mapping[str, Any], definition["output_schema"]), reference
                    )
                )
                if matches == 0:
                    self.error(
                        "ACC_USAGE_CONDITION_REFERENCE_UNAVAILABLE",
                        "A condition references data unavailable in its route execution scope.",
                        pointer=f"/conditions/{index}/expression",
                    )
                elif matches > 1:
                    self.error(
                        "ACC_USAGE_CONDITION_REFERENCE_AMBIGUOUS",
                        "A condition reference must resolve to exactly one public route value.",
                        pointer=f"/conditions/{index}/expression",
                    )
            step = step_by_id.get(cast(str, condition.step_id))
            if step is not None and step.action_phase in {"approve", "commit"}:
                claims = {claim.id: claim for claim in contract.evidence_claims}
                if not condition.evidence_claim_ids or any(
                    claims.get(claim_id) is None
                    or claims[claim_id].authority == "observation"
                    or claims[claim_id].source_layer == "client"
                    for claim_id in condition.evidence_claim_ids
                ):
                    self.error(
                        "ACC_USAGE_CONDITION_AUTHORITY_INVALID",
                        "Client observations cannot authorize an Action phase.",
                        pointer=f"/conditions/{index}/evidence_claim_ids",
                    )

    def _analyze_actions(
        self,
        contract: DomainUsageContract,
        capabilities: Mapping[str, Any],
        tools: Mapping[str, list[Mapping[str, Any]]],
    ) -> None:
        lifecycle_by_id = {item.id: item for item in contract.action_lifecycles}
        for route_index, route in enumerate(contract.tool_routes):
            action_steps = [step for step in route.steps if step.action_phase is not None]
            if not action_steps:
                continue
            lifecycle = lifecycle_by_id.get(cast(str, route.action_lifecycle_id))
            if lifecycle is None:
                self.error(
                    "ACC_USAGE_ACTION_LIFECYCLE_MISSING",
                    "An Action route requires a complete runtime-owned lifecycle.",
                    pointer=f"/tool_routes/{route_index}/action_lifecycle_id",
                )
                continue
            capability_ids = {step.capability_id for step in action_steps}
            if len(capability_ids) != 1:
                self.error(
                    "ACC_USAGE_ACTION_CAPABILITY_MISMATCH",
                    "All phases of one Action lifecycle must bind to one Capability.",
                )
                continue
            compiled = capabilities.get(next(iter(capability_ids)))
            proof = compiled.get("action_proof") if isinstance(compiled, Mapping) else None
            if not isinstance(proof, Mapping) or set(proof) != _ACTION_PROOF_FIELDS:
                self.error(
                    "ACC_USAGE_ACTION_PROOF_MISSING",
                    "An Action route requires the compiler-owned Action safety proof.",
                )
                approval_required = True
            else:
                approval_required = proof.get("approval_required") is True
            phases = {step.action_phase for step in action_steps}
            approval_invalid = (
                lifecycle.approval == "conditional"
                and ("approve" not in phases or lifecycle.approval_condition is None)
            ) or (approval_required and lifecycle.approval == "never")
            if approval_invalid:
                self.error(
                    "ACC_USAGE_ACTION_APPROVAL_PHASE_INVALID",
                    "The Usage approval flow does not satisfy the compiled Action proof.",
                )
            outcome_branch = any(
                "outcome_unknown" in branch.outcomes
                and branch.behavior == "query_status"
                and lifecycle.status_step_id in branch.step_ids
                for branch in contract.error_handling
            )
            status_step = next(
                (step for step in action_steps if step.id == lifecycle.status_step_id), None
            )
            if (
                not outcome_branch
                or status_step is None
                or status_step.action_phase != "status"
                or status_step.retry != "status_only"
            ):
                self.error(
                    "ACC_USAGE_OUTCOME_UNKNOWN_UNHANDLED",
                    "Unknown mutation outcomes must resolve only through the status phase.",
                )
            for step in action_steps:
                phase = step.action_phase
                if phase is None:
                    continue
                expected = {
                    "approve": {"action_handle", "approval_handle"},
                    "commit": {"action_handle"},
                    "status": {"action_handle"},
                }.get(phase)
                if expected is not None and not _closed_handle_schema(
                    tools.get(step.tool_name, []), expected
                ):
                    self.error(
                        "ACC_USAGE_ACTION_TOOL_SCHEMA_INVALID",
                        "An Action phase Tool must expose only its required runtime-owned handles.",
                    )


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer:
        return ()
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _projected_output_matches(projected: object, compiled: object) -> bool:
    if projected == compiled:
        return True
    if not isinstance(projected, Mapping) or not isinstance(compiled, Mapping):
        return False
    projected_id = projected.get("$id")
    return (
        isinstance(projected_id, str)
        and projected_id.startswith("urn:acc:mcp-output:")
        and {key: value for key, value in projected.items() if key != "$id"} == dict(compiled)
    )


def _public_output_schema(
    step: UsageToolStep,
    definition: Mapping[str, Any] | None,
    tools: Mapping[str, list[Mapping[str, Any]]],
) -> Mapping[str, Any] | None:
    candidates = tools.get(step.tool_name, [])
    if len(candidates) != 1:
        return None
    output = candidates[0].get("outputSchema")
    if not isinstance(output, Mapping):
        return None
    properties = output.get("properties")
    projected = properties.get("result") if isinstance(properties, Mapping) else None
    if not isinstance(projected, Mapping):
        return None
    if definition is not None and definition.get("kind") == "read":
        return projected
    return projected


def _closed_handle_schema(
    candidates: Sequence[Mapping[str, Any]], required_handles: set[str]
) -> bool:
    if len(candidates) != 1:
        return False
    schema = candidates[0].get("inputSchema")
    if not isinstance(schema, Mapping):
        return False
    properties = schema.get("properties")
    required = schema.get("required")
    return (
        schema.get("type") == "object"
        and schema.get("additionalProperties") is False
        and isinstance(properties, Mapping)
        and set(properties) == required_handles
        and isinstance(required, Sequence)
        and not isinstance(required, (str, bytes))
        and set(required) == required_handles
        and all(
            isinstance(properties[name], Mapping) and properties[name].get("type") == "string"
            for name in required_handles
        )
    )


def _resolve_schema(root: Mapping[str, Any], schema: object) -> Mapping[str, Any] | None:
    current = schema
    seen: set[str] = set()
    while isinstance(current, Mapping) and "$ref" in current:
        reference = current.get("$ref")
        if not isinstance(reference, str) or not reference.startswith("#/") or reference in seen:
            return None
        seen.add(reference)
        resolved: object = root
        for token in _pointer_tokens(reference[1:]):
            if not isinstance(resolved, Mapping) or token not in resolved:
                return None
            resolved = resolved[token]
        current = resolved
    return current if isinstance(current, Mapping) else None


def _schema_at_pointer(schema: Mapping[str, Any], pointer: str) -> JsonObject | None:
    current: Any = schema
    for token in _pointer_tokens(pointer):
        current = _resolve_schema(schema, current)
        if current is None:
            return None
        if current.get("type") == "array":
            if not token.isdecimal() or isinstance(current.get("items"), Mapping) is False:
                return None
            current = current["items"]
        else:
            properties = current.get("properties")
            if not isinstance(properties, Mapping) or not isinstance(
                properties.get(token), Mapping
            ):
                return None
            current = properties[token]
    current = _resolve_schema(schema, current)
    return cast(JsonObject, dict(current)) if current is not None else None


def _schema_pointer_is_guaranteed(schema: Mapping[str, Any], pointer: str) -> bool:
    current: Any = schema
    for token in _pointer_tokens(pointer):
        current = _resolve_schema(schema, current)
        if current is None:
            return False
        if current.get("type") == "array":
            minimum = current.get("minItems")
            if (
                not token.isdecimal()
                or not isinstance(minimum, int)
                or isinstance(minimum, bool)
                or minimum <= int(token)
                or not isinstance(current.get("items"), Mapping)
            ):
                return False
            current = current["items"]
        else:
            properties = current.get("properties")
            required = current.get("required")
            if (
                not isinstance(properties, Mapping)
                or not isinstance(properties.get(token), Mapping)
                or not isinstance(required, Sequence)
                or isinstance(required, (str, bytes))
                or token not in required
            ):
                return False
            current = properties[token]
    return _resolve_schema(schema, current) is not None


def _escape_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _required_leaf_pointers(schema: Mapping[str, Any]) -> set[str] | None:
    leaves: set[str] = set()

    def visit(current: object, pointer: str) -> bool:
        resolved = _resolve_schema(schema, current)
        if resolved is None:
            return False
        required = resolved.get("required", [])
        properties = resolved.get("properties", {})
        if (
            not isinstance(required, Sequence)
            or isinstance(required, (str, bytes))
            or not isinstance(properties, Mapping)
            or any(not isinstance(name, str) for name in required)
        ):
            return False
        for name in required:
            child = properties.get(name)
            if not isinstance(child, Mapping):
                return False
            child_pointer = f"{pointer}/{_escape_pointer_token(name)}"
            child_resolved = _resolve_schema(schema, child)
            child_required = child_resolved.get("required") if child_resolved else None
            if (
                isinstance(child_required, Sequence)
                and not isinstance(child_required, (str, bytes))
                and child_required
            ):
                if not visit(child, child_pointer):
                    return False
            else:
                leaves.add(child_pointer)
        return True

    return leaves if visit(schema, "") else None


def _analyze_usage_contract_content(
    project: UsageProjectReport,
    release: McpReleaseAcceptanceVerification,
    *,
    domain_id: str,
) -> UsageAnalysisReport:
    """Prove one Usage domain against an exact accepted MCP release snapshot."""

    return _Analyzer(project, release, domain_id).run()


class _AnalysisRunner(Protocol):
    def __call__(
        self,
        project: UsageProjectReport,
        release: McpReleaseAcceptanceVerification,
        *,
        domain_id: str,
    ) -> UsageAnalysisReport: ...


class _AnalysisChecker(Protocol):
    def __call__(
        self,
        report: UsageAnalysisReport,
        project: UsageProjectReport | None = None,
        release: McpReleaseAcceptanceVerification | None = None,
        domain_id: str | None = None,
    ) -> bool: ...


def _make_live_analysis_runner() -> tuple[_AnalysisRunner, _AnalysisChecker]:
    live: dict[
        int,
        tuple[weakref.ReferenceType[UsageAnalysisReport], str, int, int, str, str],
    ] = {}

    def analyze_usage_contract(
        project: UsageProjectReport,
        release: McpReleaseAcceptanceVerification,
        *,
        domain_id: str,
    ) -> UsageAnalysisReport:
        result = _analyze_usage_contract_content(project, release, domain_id=domain_id)
        if not release.trusted:
            return result
        identity = id(result)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        contract = project.domain_contracts.get(domain_id)
        contract_fingerprint = (
            hashlib.sha256(canonical_json_bytes(contract.model_dump(mode="json"))).hexdigest()
            if contract is not None
            else ""
        )
        live[identity] = (
            weakref.ref(result, discard),
            _analysis_fingerprint(result),
            id(project),
            id(release),
            domain_id,
            contract_fingerprint,
        )
        return result

    def is_live_analysis(
        report: UsageAnalysisReport,
        project: UsageProjectReport | None = None,
        release: McpReleaseAcceptanceVerification | None = None,
        domain_id: str | None = None,
    ) -> bool:
        record = live.get(id(report))
        return (
            record is not None
            and record[0]() is report
            and record[1] == _analysis_fingerprint(report)
            and (project is None or record[2] == id(project))
            and (release is None or record[3] == id(release))
            and (domain_id is None or record[4] == domain_id)
            and (
                project is None
                or domain_id is None
                or (
                    (contract := project.domain_contracts.get(domain_id)) is not None
                    and record[5]
                    == hashlib.sha256(
                        canonical_json_bytes(contract.model_dump(mode="json"))
                    ).hexdigest()
                )
            )
        )

    return analyze_usage_contract, is_live_analysis


analyze_usage_contract, _is_live_analysis = _make_live_analysis_runner()
del _make_live_analysis_runner


__all__ = ["UsageAnalysisReport", "analyze_usage_contract"]
