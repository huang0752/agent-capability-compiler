"""Compile typed interaction contracts into a canonical, evidence-safe attestation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from pydantic import JsonValue

from acc_core.interactions.expressions import iter_condition_references
from acc_core.interactions.models import (
    CapabilityInteractionContract,
    InputBinding,
    InteractionDefault,
    OptionSource,
    UIInteraction,
)
from acc_core.models import StrictModel
from acc_core.validation.project import ValidationReport


class InteractionCompilationError(ValueError):
    """A typed interaction contract cannot form a safe public manifest."""

    code = "ACC_UI_INTERACTION_STATE_UNTRACED"

    def __init__(
        self,
        *,
        capability_id: str,
        consumption_index: int,
        missing_states: Sequence[str],
    ) -> None:
        self.capability_id = capability_id
        self.consumption_index = consumption_index
        self.missing_states = tuple(missing_states)
        super().__init__(
            "contract result state is not declared by an adopted interaction: "
            + ", ".join(missing_states)
        )


def _normalize_json(value: Any) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {
            str(key): _normalize_json(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    raise TypeError(f"interaction attestation is not JSON-compatible: {type(value).__name__}")


def _canonical_bytes(value: object) -> bytes:
    """Return the sole byte representation used by interaction digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _without_evidence(value: JsonValue) -> JsonValue:
    """Remove design evidence bodies while retaining executable contract facts."""

    if isinstance(value, dict):
        return {
            key: _without_evidence(item) for key, item in sorted(value.items()) if key != "evidence"
        }
    if isinstance(value, list):
        return [_without_evidence(item) for item in value]
    return value


def _compiled_values(values: Sequence[StrictModel]) -> list[JsonValue]:
    compiled: list[JsonValue] = []
    for value in values:
        dumped = value.model_dump(mode="json", by_alias=True)
        compiled.append(_without_evidence(_normalize_json(dumped)))
    return compiled


def _public_default(default: InteractionDefault) -> dict[str, JsonValue] | None:
    if not (
        default.source_kind == "literal"
        and default.authority != "observation"
        and default.precedence == "caller_over_default"
        and default.submission == "send"
        and default.override_policy == "caller_allowed"
    ):
        return None
    return {
        "id": default.id,
        "source_kind": "literal",
        "target_pointer": default.target_pointer,
        "value": default.value,
    }


def _option_source_is_public(
    source: OptionSource,
    public_targets: frozenset[str],
) -> bool:
    return (
        source.source_kind in {"static", "capability"}
        and source.target_pointer in public_targets
        and set(source.cascade_dependencies) <= public_targets
        and all(
            binding.source_kind
            in {
                "user_input",
                "route_parameter",
                "selected_record",
                "prior_response",
                "user_preference",
            }
            and binding.source_pointer in public_targets
            and "literal_value" not in binding.model_fields_set
            for binding in source.request_bindings
        )
    )


def _public_option_request_binding(binding: InputBinding) -> dict[str, JsonValue]:
    mapping: JsonValue = None
    if binding.mapping is not None:
        mapping = _normalize_json(binding.mapping.model_dump(mode="json", by_alias=True))
    return {
        "cardinality": binding.cardinality,
        "id": binding.id,
        "mapping": mapping,
        "source_kind": binding.source_kind,
        "source_pointer": binding.source_pointer,
        "target_pointer": binding.target_pointer,
    }


def _public_option_source(
    source: OptionSource,
    public_targets: frozenset[str],
) -> dict[str, JsonValue] | None:
    if not _option_source_is_public(source, public_targets):
        return None
    dumped = source.model_dump(mode="json", by_alias=True)
    dumped["request_bindings"] = [
        _public_option_request_binding(binding) for binding in source.request_bindings
    ]
    normalized = _without_evidence(_normalize_json(dumped))
    assert isinstance(normalized, dict)
    return normalized


def _inherited_interaction(
    interaction: UIInteraction,
    public_targets: frozenset[str],
) -> dict[str, JsonValue]:
    return {
        "call_order": interaction.call_order,
        "option_behaviors": [
            {
                "empty_behavior": source.empty_behavior,
                "error_behavior": source.error_behavior,
                "id": source.id,
                "target_pointer": source.target_pointer,
            }
            for source in interaction.option_sources
            if source.target_pointer in public_targets
        ],
        "trigger": {"kind": interaction.trigger.kind},
    }


def _candidate_public_targets(
    contract: CapabilityInteractionContract,
) -> frozenset[str]:
    trusted_targets = {binding.target_pointer for binding in contract.trusted_input_bindings}
    candidates = {binding.target_pointer for binding in contract.public_input_bindings}
    candidates.update(default.target_pointer for default in contract.defaults)
    candidates.update(source.target_pointer for source in contract.option_sources)
    return frozenset(candidates - trusted_targets)


def _compile_contract(
    contract: CapabilityInteractionContract,
    interactions: Mapping[str, UIInteraction],
) -> dict[str, JsonValue]:
    sidecar = contract.model_dump(mode="json", by_alias=True)
    public_targets = _candidate_public_targets(contract)
    trusted_targets = frozenset(
        binding.target_pointer for binding in contract.trusted_input_bindings
    )
    adopted = {
        interaction_id: interactions[interaction_id]
        for interaction_id in contract.interaction_ids
        if interaction_id in interactions
    }
    inherited_states = {
        state.id for interaction in adopted.values() for state in interaction.states
    }
    for consumption_index, consumption in enumerate(contract.result_consumption):
        missing_states = sorted(set(consumption.state_ids) - inherited_states)
        if missing_states:
            raise InteractionCompilationError(
                capability_id=contract.capability_id,
                consumption_index=consumption_index,
                missing_states=missing_states,
            )
    defaults = [
        compiled
        for default in contract.defaults
        if default.target_pointer in public_targets
        and default.target_pointer not in trusted_targets
        and (compiled := _public_default(default)) is not None
    ]
    conditions = [
        condition
        for condition in contract.conditions
        if condition.target_pointer in public_targets
        and set(iter_condition_references(condition.expression)) <= public_targets
    ]
    option_sources = [
        compiled
        for source in contract.option_sources
        if (compiled := _public_option_source(source, public_targets)) is not None
    ]
    action_lifecycle: JsonValue = None
    if contract.action_lifecycle is not None:
        action_lifecycle = {
            "interaction_id": contract.action_lifecycle.interaction_id,
            "phases": ["prepare", "approve", "commit", "status"],
        }
    return {
        "action_lifecycle": action_lifecycle,
        "capability_id": contract.capability_id,
        "conditions": _compiled_values(conditions),
        "defaults": cast(JsonValue, defaults),
        "inherited_interactions": {
            interaction_id: _inherited_interaction(adopted[interaction_id], public_targets)
            for interaction_id in sorted(adopted)
        },
        "interaction_ids": list(contract.interaction_ids),
        "omitted_interaction_ids": [item.interaction_id for item in contract.omissions],
        "option_sources": cast(JsonValue, option_sources),
        "overridden_interaction_ids": [item.interaction_id for item in contract.overrides],
        "public_input_bindings": _compiled_values(contract.public_input_bindings),
        "related_data": [],
        "required_scenarios": list(contract.required_scenarios),
        "result_consumption": [],
        "sidecar_sha256": _digest(sidecar),
    }


@dataclass(frozen=True, slots=True)
class CompiledInteractionAttestation:
    """Canonical interaction manifest carried independently from tool schemas."""

    schema_version: str
    digest: str
    inventory: dict[str, JsonValue]
    contracts: dict[str, dict[str, JsonValue]]
    dependencies: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the stable IR wire shape."""

        return {
            "schema_version": self.schema_version,
            "digest": self.digest,
            "inventory": self.inventory,
            "contracts": cast(JsonValue, self.contracts),
            "dependencies": [list(edge) for edge in self.dependencies],
        }


def compile_interactions(report: ValidationReport) -> CompiledInteractionAttestation:
    """Compile only the typed interaction documents already loaded by validation."""

    inventory = report.ui_interaction_inventory
    if inventory is None:
        inventory_manifest: dict[str, JsonValue] = {"status": "not_declared"}
        compiled_contracts: dict[str, dict[str, JsonValue]] = {}
        dependencies: tuple[tuple[str, str], ...] = ()
    else:
        inventory_document = inventory.model_dump(mode="json", by_alias=True)
        inventory_manifest = {
            "evidence_sha256": _digest(list(inventory.scope.evidence_sources)),
            "interaction_ids": [item.id for item in inventory.interactions],
            "scope_mode": inventory.scope.mode,
            "sidecar_sha256": _digest(inventory_document),
            "status": "declared",
            "summary": cast(
                dict[str, JsonValue],
                _normalize_json(inventory.summary.model_dump(mode="json", by_alias=True)),
            ),
            "surface_ids": [item.id for item in inventory.surfaces],
        }
        if inventory.scope.mode == "none":
            compiled_contracts = {}
            dependencies = ()
        else:
            interaction_map = {item.id: item for item in inventory.interactions}
            compiled_contracts = {
                capability_id: _compile_contract(
                    report.interaction_contracts[capability_id],
                    interaction_map,
                )
                for capability_id in sorted(report.interaction_contracts)
            }
            dependency_set: set[tuple[str, str]] = set()
            for capability_id, contract in report.interaction_contracts.items():
                public_targets = _candidate_public_targets(contract)
                dependency_set.update(
                    (source.producer_id, capability_id)
                    for source in contract.option_sources
                    if source.producer_id is not None
                    and _option_source_is_public(source, public_targets)
                )
            dependencies = tuple(sorted(dependency_set))

    digest_payload = {
        "schema_version": "2",
        "contracts": compiled_contracts,
        "dependencies": [list(edge) for edge in dependencies],
        "inventory": inventory_manifest,
    }
    return CompiledInteractionAttestation(
        schema_version="2",
        digest=_digest(digest_payload),
        inventory=inventory_manifest,
        contracts=compiled_contracts,
        dependencies=dependencies,
    )


__all__ = [
    "CompiledInteractionAttestation",
    "InteractionCompilationError",
    "compile_interactions",
]
