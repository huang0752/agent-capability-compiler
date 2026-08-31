#!/usr/bin/env python3
"""Audit normalized frontend interaction documents without parsing framework source."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml
from artifact_manifest import atomic_write_json, output_path
from verify_read_only_workspace import (
    DEFAULT_MAX_FILE_BYTES,
    JsonArgumentParser,
    SafePathError,
    diagnostic,
    read_file_bytes,
    safe_existing_path,
)

COMMAND = "interaction-audit"
AUTHORITIES = {"contract", "implementation", "test", "observation"}
DIMENSIONS = {
    "conditions",
    "defaults",
    "input_bindings",
    "option_sources",
    "related_data",
    "result_consumption",
    "states",
}
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def parser() -> JsonArgumentParser:
    value = JsonArgumentParser(command=COMMAND)
    value.add_argument("--project", required=True)
    value.add_argument("--output")
    return value


def load_document(path: Path) -> dict[str, object]:
    """Load one bounded UTF-8 YAML mapping without importing project code."""

    metadata = path.stat()
    raw = read_file_bytes(path, metadata, DEFAULT_MAX_FILE_BYTES, path.name)
    try:
        value = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SafePathError(
            "ACC_UI_DOCUMENT_INVALID",
            "interaction document must be valid UTF-8 YAML or JSON",
            path=path.name,
        ) from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SafePathError(
            "ACC_UI_DOCUMENT_INVALID",
            "interaction document must be an object",
            path=path.name,
        )
    return cast(dict[str, object], value)


def mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return cast(Mapping[str, object], value)
    return None


def records(document: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    value = document.get(key)
    if not isinstance(value, list):
        return []
    return [cast(Mapping[str, object], item) for item in value if mapping(item) is not None]


def non_empty_strings(value: object, *, allow_empty: bool = False) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not value and allow_empty:
        return []
    if not value or not all(isinstance(item, str) and bool(item.strip()) for item in value):
        return None
    result = cast(list[str], value)
    return result if len(result) == len(set(result)) else None


def identifier(record: Mapping[str, object]) -> str | None:
    value = record.get("id")
    return value if isinstance(value, str) and bool(value.strip()) else None


def identifiers_are_unique_sorted(values: list[Mapping[str, object]]) -> bool:
    identifiers = [identifier(value) for value in values]
    return (
        all(value is not None for value in identifiers)
        and len(identifiers) == len(set(identifiers))
        and identifiers == sorted(identifiers, key=lambda value: value or "")
    )


def valid_pointer(value: object, *, optional: bool = False) -> bool:
    return (optional and value is None) or (isinstance(value, str) and value.startswith("/"))


def valid_evidence(value: object) -> bool:
    """Recognize the immutable Evidence envelope without importing Core models."""

    evidence = mapping(value)
    if evidence is None:
        return False
    source_id = evidence.get("source_id")
    digest = evidence.get("digest")
    has_locator = any(
        (
            isinstance(evidence.get("path"), str) and bool(evidence.get("path")),
            isinstance(evidence.get("json_pointer"), str),
            isinstance(evidence.get("openapi_operation"), str)
            and bool(evidence.get("openapi_operation")),
            isinstance(evidence.get("locator"), str) and bool(evidence.get("locator")),
            isinstance(evidence.get("summary"), str) and bool(evidence.get("summary")),
        )
    )
    return (
        isinstance(source_id, str)
        and bool(source_id.strip())
        and isinstance(digest, str)
        and SHA256_DIGEST.fullmatch(digest) is not None
        and has_locator
    )


def evidence_source_id(value: object) -> str | None:
    evidence = mapping(value)
    source_id = evidence.get("source_id") if evidence is not None else None
    return source_id if isinstance(source_id, str) and bool(source_id.strip()) else None


def valid_evidence_claim(value: object) -> bool:
    claim = mapping(value)
    return bool(
        claim is not None
        and valid_pointer(claim.get("target_pointer"))
        and valid_evidence(claim.get("evidence"))
        and valid_pointer(claim.get("evidence_pointer"), optional=True)
        and claim.get("authority") in AUTHORITIES
    )


def issue(
    diagnostics: list[dict[str, object]], code: str, message: str, *, path: str, pointer: str
) -> None:
    """Add a fixed diagnostic that never includes source values or absolute paths."""

    diagnostics.append(diagnostic(code, message, path=path, pointer=pointer))


def audit_documents(
    *,
    scope_inventory: Mapping[str, object],
    ui_inventory: Mapping[str, object],
    contracts: list[tuple[str, Mapping[str, object]]],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Check shallow structure, evidence, and cross-document identifier closure."""

    diagnostics: list[dict[str, object]] = []
    if scope_inventory.get("schema_version") != "2" or not isinstance(
        scope_inventory.get("routes"), list
    ):
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "Scope Inventory must use current format 2 with a route list",
            path="scope-inventory.yaml",
            pointer="/",
        )
    if (
        ui_inventory.get("schema_version") != "2"
        or mapping(ui_inventory.get("scope")) is None
        or not isinstance(ui_inventory.get("surfaces"), list)
        or not isinstance(ui_inventory.get("interactions"), list)
        or mapping(ui_inventory.get("summary")) is None
    ):
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "UI Interaction Inventory must use current format 2 and normalized collections",
            path="ui-interaction-inventory.yaml",
            pointer="/",
        )
    for contract_path, contract in contracts:
        if contract.get("schema_version") != "2" or not isinstance(
            contract.get("interaction_ids"), list
        ):
            issue(
                diagnostics,
                "ACC_UI_DOCUMENT_INVALID",
                "Interaction Contract must use current format 2 with interaction identifiers",
                path=contract_path,
                pointer="/",
            )
    scope_routes = records(scope_inventory, "routes")
    surfaces = records(ui_inventory, "surfaces")
    interactions = records(ui_inventory, "interactions")
    if not identifiers_are_unique_sorted(surfaces):
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "surface identifiers must be non-empty, unique, and sorted",
            path="ui-interaction-inventory.yaml",
            pointer="/surfaces",
        )
    if not identifiers_are_unique_sorted(interactions):
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "interaction identifiers must be non-empty, unique, and sorted",
            path="ui-interaction-inventory.yaml",
            pointer="/interactions",
        )
    route_ids = {value for route in scope_routes if (value := identifier(route)) is not None}
    surface_ids = {value for surface in surfaces if (value := identifier(surface)) is not None}
    interaction_ids = {
        value for interaction in interactions if (value := identifier(interaction)) is not None
    }
    ui_scope = mapping(ui_inventory.get("scope")) or {}
    surfaces_by_id = {
        identified_surface: surface
        for surface in surfaces
        if (identified_surface := identifier(surface)) is not None
    }

    surface_contexts: set[str] = set()
    for index, surface in enumerate(surfaces):
        if non_empty_strings(surface.get("evidence_sources")) is None:
            issue(
                diagnostics,
                "ACC_UI_INTERACTION_EVIDENCE_MISSING",
                "surface requires unique non-empty evidence references",
                path="ui-interaction-inventory.yaml",
                pointer=f"/surfaces/{index}/evidence_sources",
            )
        if ui_scope.get("mode") == "complete":
            usage_context = surface.get("usage_context")
            if (
                not isinstance(usage_context, str)
                or not usage_context.strip()
                or not valid_evidence(surface.get("entry_evidence"))
            ):
                issue(
                    diagnostics,
                    "ACC_UI_SURFACE_ENTRY_EVIDENCE_REQUIRED",
                    "complete surface requires usage context and immutable entry evidence",
                    path="ui-interaction-inventory.yaml",
                    pointer=f"/surfaces/{index}",
                )
            elif usage_context in surface_contexts:
                issue(
                    diagnostics,
                    "ACC_UI_SURFACE_CONTEXT_DUPLICATE",
                    "surface usage contexts must be unique instead of folded by endpoint",
                    path="ui-interaction-inventory.yaml",
                    pointer=f"/surfaces/{index}/usage_context",
                )
            else:
                surface_contexts.add(usage_context)

    unresolved = 0
    for index, interaction in enumerate(interactions):
        claims = interaction.get("evidence_claims")
        if (
            not isinstance(claims, list)
            or not claims
            or not all(valid_evidence_claim(item) for item in claims)
        ):
            issue(
                diagnostics,
                "ACC_UI_INTERACTION_EVIDENCE_MISSING",
                "interaction requires complete immutable evidence claims",
                path="ui-interaction-inventory.yaml",
                pointer=f"/interactions/{index}/evidence_claims",
            )
        surface_id = interaction.get("surface_id")
        if not isinstance(surface_id, str) or surface_id not in surface_ids:
            issue(
                diagnostics,
                "ACC_UI_SURFACE_UNKNOWN",
                "interaction surface must exist in the UI inventory",
                path="ui-interaction-inventory.yaml",
                pointer=f"/interactions/{index}/surface_id",
            )
        linked_routes = non_empty_strings(interaction.get("route_ids"), allow_empty=True)
        if linked_routes is None:
            issue(
                diagnostics,
                "ACC_UI_INTERACTION_ROUTE_UNKNOWN",
                "interaction route references must be unique identifiers",
                path="ui-interaction-inventory.yaml",
                pointer=f"/interactions/{index}/route_ids",
            )
        else:
            for offset, route_id in enumerate(linked_routes):
                if route_id not in route_ids:
                    issue(
                        diagnostics,
                        "ACC_UI_INTERACTION_ROUTE_UNKNOWN",
                        "interaction route must exist in Scope Inventory",
                        path="ui-interaction-inventory.yaml",
                        pointer=f"/interactions/{index}/route_ids/{offset}",
                    )
        unknowns = non_empty_strings(interaction.get("unknowns"), allow_empty=True)
        if unknowns is None:
            unresolved += 1
        else:
            unresolved += len(unknowns)
        if ui_scope.get("mode") == "complete":
            claim_source_ids = {
                source_id
                for claim in records(interaction, "evidence_claims")
                if (evidence := mapping(claim.get("evidence"))) is not None
                if (source_id := evidence_source_id(evidence)) is not None
            }
            linked_surface = surfaces_by_id.get(surface_id) if isinstance(surface_id, str) else None
            surface_source_ids = (
                set(non_empty_strings(linked_surface.get("evidence_sources")) or [])
                if linked_surface is not None
                else set()
            )
            dispositions = records(interaction, "dimension_dispositions")
            disposition_dimensions = {
                item.get("dimension")
                for item in dispositions
                if isinstance(item.get("dimension"), str)
                and item.get("applicability") in {"applicable", "not_applicable"}
                and isinstance(item.get("rationale"), str)
                and bool(str(item.get("rationale")).strip())
                and valid_evidence(item.get("evidence"))
            }
            if disposition_dimensions != DIMENSIONS or len(dispositions) != len(DIMENSIONS):
                issue(
                    diagnostics,
                    "ACC_UI_DIMENSION_DISPOSITION_REQUIRED",
                    "complete interaction requires seven evidenced dimension dispositions",
                    path="ui-interaction-inventory.yaml",
                    pointer=f"/interactions/{index}/dimension_dispositions",
                )
            for disposition in dispositions:
                dimension = disposition.get("dimension")
                if not isinstance(dimension, str) or dimension not in DIMENSIONS:
                    continue
                content = interaction.get(dimension)
                populated = isinstance(content, list) and bool(content)
                if (disposition.get("applicability") == "applicable") != populated:
                    issue(
                        diagnostics,
                        "ACC_UI_DIMENSION_DISPOSITION_MISMATCH",
                        "dimension content must match its evidenced applicability",
                        path="ui-interaction-inventory.yaml",
                        pointer=f"/interactions/{index}/{dimension}",
                    )
                source_id = evidence_source_id(disposition.get("evidence"))
                if source_id not in claim_source_ids or source_id not in surface_source_ids:
                    issue(
                        diagnostics,
                        "ACC_UI_DIMENSION_EVIDENCE_UNRESOLVED",
                        "dimension evidence must resolve through interaction claims and "
                        "surface evidence sources",
                        path="ui-interaction-inventory.yaml",
                        pointer=(
                            f"/interactions/{index}/dimension_dispositions/"
                            f"{dimension}/evidence/source_id"
                        ),
                    )

    for index, route in enumerate(scope_routes):
        linked_interactions = non_empty_strings(route.get("interaction_ids"), allow_empty=True)
        if linked_interactions is None:
            issue(
                diagnostics,
                "ACC_UI_INTERACTION_UNKNOWN",
                "scope interaction references must be unique identifiers",
                path="scope-inventory.yaml",
                pointer=f"/routes/{index}/interaction_ids",
            )
            continue
        for offset, interaction_id in enumerate(linked_interactions):
            if interaction_id not in interaction_ids:
                issue(
                    diagnostics,
                    "ACC_UI_INTERACTION_UNKNOWN",
                    "scope interaction must exist in the UI inventory",
                    path="scope-inventory.yaml",
                    pointer=f"/routes/{index}/interaction_ids/{offset}",
                )

    capability_ids = [contract.get("capability_id") for _, contract in contracts]
    if not all(isinstance(value, str) and bool(value.strip()) for value in capability_ids) or len(
        capability_ids
    ) != len(set(capability_ids)):
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "capability contract identifiers must be non-empty and unique",
            path="interaction-contracts",
            pointer="/capability_id",
        )

    for contract_path, contract in contracts:
        linked_interactions = non_empty_strings(contract.get("interaction_ids"), allow_empty=True)
        if linked_interactions is None:
            issue(
                diagnostics,
                "ACC_UI_INTERACTION_UNKNOWN",
                "contract interaction references must be unique identifiers",
                path=contract_path,
                pointer="/interaction_ids",
            )
            continue
        for offset, interaction_id in enumerate(linked_interactions):
            if interaction_id not in interaction_ids:
                issue(
                    diagnostics,
                    "ACC_UI_INTERACTION_UNKNOWN",
                    "contract interaction must exist in the UI inventory",
                    path=contract_path,
                    pointer=f"/interaction_ids/{offset}",
                )

    adopted = {
        interaction_id
        for _, contract in contracts
        for interaction_id in (
            non_empty_strings(contract.get("interaction_ids"), allow_empty=True) or []
        )
    }
    omitted: set[str] = set()
    for contract_path, contract in contracts:
        for omission_index, omission in enumerate(records(contract, "omissions")):
            omitted_interaction_id = omission.get("interaction_id")
            if (
                not isinstance(omitted_interaction_id, str)
                or omitted_interaction_id not in interaction_ids
                or not isinstance(omission.get("justification"), str)
                or not str(omission.get("justification")).strip()
                or omission.get("authority") not in {"contract", "implementation", "test"}
                or not valid_evidence(omission.get("evidence"))
            ):
                issue(
                    diagnostics,
                    "ACC_UI_INTERACTION_OMISSION_INVALID",
                    "omitted interaction requires immutable evidence and explicit authority",
                    path=contract_path,
                    pointer=f"/omissions/{omission_index}",
                )
            elif omitted_interaction_id in adopted:
                issue(
                    diagnostics,
                    "ACC_UI_INTERACTION_OMISSION_INVALID",
                    "interaction cannot be both adopted and omitted",
                    path=contract_path,
                    pointer=f"/omissions/{omission_index}/interaction_id",
                )
            else:
                omitted.add(omitted_interaction_id)

    scope = mapping(ui_inventory.get("scope")) or {}
    mode = scope.get("mode") if isinstance(scope.get("mode"), str) else None
    summary = mapping(ui_inventory.get("summary")) or {}
    declared_unresolved = summary.get("unresolved")
    if mode not in {"none", "discovered", "complete"}:
        issue(
            diagnostics,
            "ACC_UI_DOCUMENT_INVALID",
            "interaction scope mode is invalid",
            path="ui-interaction-inventory.yaml",
            pointer="/scope/mode",
        )
    if mode == "none":
        evidence_sources = non_empty_strings(scope.get("evidence_sources"))
        rationale = scope.get("rationale")
        if (
            evidence_sources is None
            or not isinstance(rationale, str)
            or not rationale.strip()
            or surfaces
            or interactions
        ):
            issue(
                diagnostics,
                "ACC_UI_DOCUMENT_INVALID",
                "none scope requires evidence, rationale, and empty denominators",
                path="ui-interaction-inventory.yaml",
                pointer="/scope",
            )
    if mode == "complete" and (not surfaces or not interactions):
        issue(
            diagnostics,
            "ACC_UI_SURFACE_COVERAGE_INCOMPLETE",
            "complete interaction scope requires a non-empty denominator",
            path="ui-interaction-inventory.yaml",
            pointer="/scope/mode",
        )
    if mode == "complete" and (
        unresolved != 0 or not isinstance(declared_unresolved, int) or declared_unresolved != 0
    ):
        issue(
            diagnostics,
            "ACC_UI_SURFACE_COVERAGE_INCOMPLETE",
            "complete interaction scope cannot contain unresolved items",
            path="ui-interaction-inventory.yaml",
            pointer="/summary/unresolved",
        )
    if mode == "complete" and interaction_ids - adopted - omitted:
        issue(
            diagnostics,
            "ACC_UI_SURFACE_COVERAGE_INCOMPLETE",
            "complete interactions must be adopted or explicitly omitted with evidence",
            path="ui-interaction-inventory.yaml",
            pointer="/interactions",
        )
    scope_selection = mapping(scope_inventory.get("scope")) or {}
    if scope_selection.get("mode") == "system_complete" and interactions and mode != "complete":
        issue(
            diagnostics,
            "ACC_UI_SYSTEM_SCOPE_INCOMPLETE",
            "system-complete route scope with frontend interactions requires complete UI scope",
            path="ui-interaction-inventory.yaml",
            pointer="/scope/mode",
        )
    if (
        summary.get("surfaces") != len(surfaces)
        or summary.get("interactions") != len(interactions)
        or declared_unresolved != unresolved
    ):
        issue(
            diagnostics,
            "ACC_UI_SURFACE_COVERAGE_INCOMPLETE",
            "interaction summary must exactly match the normalized denominator",
            path="ui-interaction-inventory.yaml",
            pointer="/summary",
        )

    result: dict[str, object] = {
        "contracts": len(contracts),
        "interactions": len(interactions),
        "scope_mode": mode,
        "surfaces": len(surfaces),
        "unresolved": unresolved,
    }
    diagnostics.sort(
        key=lambda item: (
            str(item.get("path", "")),
            str(item.get("pointer", "")),
            str(item.get("code", "")),
        )
    )
    return result, diagnostics


def report_payload(
    *, result: dict[str, object] | None, diagnostics: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "command": COMMAND,
        "diagnostics": diagnostics,
        "ok": not diagnostics,
        "result": result if not diagnostics else None,
    }


def emit_payload(payload: Mapping[str, object]) -> None:
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        project = safe_existing_path(arguments.project, kind="directory")
        scope_path = safe_existing_path(str(project / "scope-inventory.yaml"), kind="file")
        ui_path = safe_existing_path(str(project / "ui-interaction-inventory.yaml"), kind="file")
        contracts_directory = safe_existing_path(
            str(project / "interaction-contracts"), kind="directory"
        )
        contracts: list[tuple[str, Mapping[str, object]]] = []
        for candidate in sorted(contracts_directory.glob("*.yaml")):
            path = safe_existing_path(str(candidate), kind="file")
            contracts.append((f"interaction-contracts/{path.name}", load_document(path)))
        result, diagnostics = audit_documents(
            scope_inventory=load_document(scope_path),
            ui_inventory=load_document(ui_path),
            contracts=contracts,
        )
        payload = report_payload(result=result, diagnostics=diagnostics)
        if arguments.output is not None:
            target, _ = output_path(project, arguments.output)
            atomic_write_json(target, payload)
        emit_payload(payload)
        return 0 if not diagnostics else 3
    except SafePathError as exc:
        payload = report_payload(
            result=None,
            diagnostics=[diagnostic(exc.code, str(exc), path=Path(exc.path or "").name or None)],
        )
        emit_payload(payload)
        return 2 if exc.code == "ACC_SKILL_PATH_INVALID" else 3


if __name__ == "__main__":
    raise SystemExit(main())
