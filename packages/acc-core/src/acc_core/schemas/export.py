"""Export the public ACC contracts as Draft 2020-12 JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, TypeAdapter

from acc_core.contracts import SourceContract
from acc_core.coverage.live_artifact import LiveObservationArtifact
from acc_core.domains import (
    CapabilityCandidateLedger,
    DomainChangeRequest,
    DomainDecision,
    DomainMap,
    EvidenceChangeSet,
)
from acc_core.intents import IntentPlan
from acc_core.interactions import CapabilityInteractionContract, UIInteractionInventory
from acc_core.models import (
    Capability,
    Eval,
    Evidence,
    Operation,
    Policy,
    Project,
)
from acc_core.quality import CapabilityQuality
from acc_core.scope import ScopeInventory
from acc_core.usage import (
    AgentUsageProject,
    AgentUsageRelease,
    DomainUsageContract,
    DomainUsageIndex,
    McpReleaseAcceptance,
    SourceSnapshot,
    UsageScenario,
)

JSON_SCHEMA_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
MODEL_SCHEMAS: dict[str, type[BaseModel] | TypeAdapter[object]] = {
    "capability": TypeAdapter(Capability),
    "capability-quality": CapabilityQuality,
    "eval": Eval,
    "evidence": Evidence,
    "interaction-contract": CapabilityInteractionContract,
    "intent-plan": IntentPlan,
    "live-observation-artifact": LiveObservationArtifact,
    "operation": TypeAdapter(Operation),
    "policy": Policy,
    "project": Project,
    "scope-inventory": ScopeInventory,
    "source-contract": SourceContract,
    "ui-interaction-inventory": UIInteractionInventory,
    "domain-map": DomainMap,
    "capability-candidates": CapabilityCandidateLedger,
    "domain-decision": DomainDecision,
    "domain-evidence-change-set": EvidenceChangeSet,
    "domain-change-request": DomainChangeRequest,
    "usage-domain-contract": DomainUsageContract,
    "usage-domain-index": DomainUsageIndex,
    "usage-mcp-release-acceptance": McpReleaseAcceptance,
    "usage-project": AgentUsageProject,
    "usage-release": AgentUsageRelease,
    "usage-scenario": UsageScenario,
    "usage-source-snapshot": SourceSnapshot,
}


def schema_for(name: str) -> dict[str, object]:
    """Return a deterministic public schema by its stable short name."""

    try:
        model = MODEL_SCHEMAS[name]
    except KeyError as exc:
        raise ValueError(f"unknown ACC schema: {name}") from exc
    generated = (
        model.json_schema(mode="validation")
        if isinstance(model, TypeAdapter)
        else model.model_json_schema(mode="validation")
    )
    return {"$schema": JSON_SCHEMA_DRAFT_2020_12, **generated}


def export_schemas(output_directory: str | Path) -> list[Path]:
    """Write every public schema without following an output-directory symlink."""

    output = Path(output_directory)
    if output.is_symlink():
        raise ValueError("schema output directory cannot be a symbolic link")
    output.mkdir(parents=True, exist_ok=True)
    if not output.is_dir():
        raise ValueError("schema output path must be a directory")

    written: list[Path] = []
    for name in sorted(MODEL_SCHEMAS):
        path = output / f"{name}.schema.json"
        if path.is_symlink():
            raise ValueError(f"schema output cannot overwrite a symbolic link: {path.name}")
        payload = json.dumps(schema_for(name), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        path.write_text(payload, encoding="utf-8")
        written.append(path)
    return written


__all__ = ["JSON_SCHEMA_DRAFT_2020_12", "MODEL_SCHEMAS", "export_schemas", "schema_for"]
