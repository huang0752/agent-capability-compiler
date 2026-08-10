"""Evidence and direction-aware fidelity diagnostics for Operation schemas."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Literal

from acc_core.contracts.models import SchemaProvenance, SourceContract
from acc_core.contracts.schema_relation import (
    RelationReport,
    SchemaRelation,
    compare_operation_input,
    compare_operation_output,
)
from acc_core.diagnostics import Diagnostic
from acc_core.models import JsonObject, Operation

_UPPER_BOUND_KEYWORDS = frozenset({"exclusiveMaximum", "maxItems", "maxLength", "maximum"})


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _join(pointer: str, token: str) -> str:
    return f"{pointer}/{_escape(token)}"


def _schema_bounds(value: object, pointer: str = "") -> Iterator[tuple[str, object]]:
    if isinstance(value, dict):
        for key, item in sorted(value.items()):
            child_pointer = _join(pointer, str(key))
            if key in _UPPER_BOUND_KEYWORDS:
                yield child_pointer, item
            yield from _schema_bounds(item, child_pointer)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _schema_bounds(item, _join(pointer, str(index)))


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer:
        return ()
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _resolve_pointer(document: object, pointer: str) -> object:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdecimal():
            index = int(token)
            if index < len(current):
                current = current[index]
                continue
        raise LookupError(pointer)
    return current


def _covering_claims(
    provenance: list[SchemaProvenance], contract_pointer: str
) -> tuple[SchemaProvenance, ...]:
    return tuple(
        claim
        for claim in provenance
        if contract_pointer == claim.target_pointer
        or contract_pointer.startswith(f"{claim.target_pointer}/")
    )


def _relation_diagnostics(
    report: RelationReport,
    *,
    code: str,
    message: str,
    schema_pointer: str,
    operation_path: str,
) -> list[Diagnostic]:
    if report.relation is SchemaRelation.PROVEN:
        return []
    if report.relation is SchemaRelation.CONFLICT:
        severity: Literal["error", "warning"] = "error"
        selected_code = code
    else:
        severity = "warning"
        selected_code = "ACC_SCHEMA_EVIDENCE_COMPARISON_UNKNOWN"
    return [
        Diagnostic(
            code=selected_code,
            severity=severity,
            message=message if report.relation is SchemaRelation.CONFLICT else finding.message,
            path=operation_path,
            pointer=f"{schema_pointer}{finding.pointer}",
        )
        for finding in report.findings
    ]


def _provenance_diagnostics(
    declared_schema: JsonObject,
    source_schema: JsonObject,
    *,
    contract_root: str,
    operation_root: str,
    provenance: list[SchemaProvenance],
    operation_path: str,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for relative_pointer, declared_value in _schema_bounds(declared_schema):
        contract_pointer = f"/{contract_root}{relative_pointer}"
        operation_pointer = f"/{operation_root}{relative_pointer}"
        try:
            source_value = _resolve_pointer(source_schema, relative_pointer)
        except LookupError:
            source_value = object()
        claims = _covering_claims(provenance, contract_pointer)
        if source_value != declared_value or not claims:
            diagnostics.append(
                Diagnostic(
                    code="ACC_SCHEMA_CONSTRAINT_PROVENANCE_MISSING",
                    severity="warning",
                    message="A restrictive schema bound is not supported by source provenance.",
                    path=operation_path,
                    pointer=operation_pointer,
                )
            )
        elif all(claim.authority == "observation" for claim in claims):
            diagnostics.append(
                Diagnostic(
                    code="ACC_SCHEMA_OBSERVATION_USED_AS_BOUND",
                    severity="error",
                    message="Runtime observation cannot prove a schema upper bound.",
                    path=operation_path,
                    pointer=operation_pointer,
                )
            )
    return diagnostics


def analyze_operation_schema_fidelity(
    operation: Operation,
    contract: SourceContract,
    *,
    operation_path: str | None = None,
) -> tuple[Diagnostic, ...]:
    """Compare one Operation with its evidence-backed source contract."""

    path = operation_path or f"operations/{operation.id}.yaml"
    diagnostics = _relation_diagnostics(
        compare_operation_input(operation.input_schema, contract.request_schema),
        code="ACC_SCHEMA_INPUT_OUTSIDE_EVIDENCE",
        message="Operation input permits requests outside the evidenced source contract.",
        schema_pointer="/input_schema",
        operation_path=path,
    )
    diagnostics.extend(
        _relation_diagnostics(
            compare_operation_output(contract.response_schema, operation.output_schema),
            code="ACC_SCHEMA_OUTPUT_NARROWER_THAN_EVIDENCE",
            message="Operation output rejects responses permitted by the source contract.",
            schema_pointer="/output_schema",
            operation_path=path,
        )
    )
    diagnostics.extend(
        _provenance_diagnostics(
            operation.input_schema,
            contract.request_schema,
            contract_root="request_schema",
            operation_root="input_schema",
            provenance=contract.provenance,
            operation_path=path,
        )
    )
    diagnostics.extend(
        _provenance_diagnostics(
            operation.output_schema,
            contract.response_schema,
            contract_root="response_schema",
            operation_root="output_schema",
            provenance=contract.provenance,
            operation_path=path,
        )
    )
    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (item.path or "", item.pointer or "", item.code, item.message),
        )
    )


__all__ = ["analyze_operation_schema_fidelity"]
