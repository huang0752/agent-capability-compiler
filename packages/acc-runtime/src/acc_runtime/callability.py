"""Platform-neutral deployment and Principal scope callability analysis."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum

from acc_core.models import (
    PasswordBearerAuthConfig,
    ProjectV2,
)
from acc_core.scope import (
    CapabilityScopeRequirements,
)
from acc_runtime.context import PrincipalContext, map_effective_scopes

type ScopeSet = frozenset[str]


class CallabilityAnalysisError(ValueError):
    """Compiled scope metadata cannot be analyzed safely."""

    def __init__(self, reason: str) -> None:
        super().__init__("scope callability analysis failed")
        self.reason = reason


class CallabilityStatus(StrEnum):
    """Whether one scope source can satisfy a capability's successful paths."""

    CALLABLE = "callable"
    CONDITIONAL = "conditional"
    DENIED = "denied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScopeDimensionCallability:
    """Callability under one deployment, user, or effective scope collection."""

    status: CallabilityStatus
    available_scopes: ScopeSet | None
    missing_always: ScopeSet
    missing_conditional: ScopeSet
    unmet_alternatives: tuple[ScopeSet, ...]


@dataclass(frozen=True, slots=True)
class CapabilityCallability:
    """Scope-only callability facts without identity or authentication state."""

    capability_id: str
    always_required: ScopeSet
    conditionally_required: ScopeSet
    all_referenced: ScopeSet
    completion_alternatives: tuple[ScopeSet, ...]
    deployment: ScopeDimensionCallability
    user: ScopeDimensionCallability
    effective: ScopeDimensionCallability


@dataclass(frozen=True, slots=True)
class ScopeCallabilityReport:
    """Deterministically ordered callability for one compiled runtime candidate."""

    ir_version: str
    deployment_scope_ceiling: ScopeSet
    capabilities: tuple[CapabilityCallability, ...]


def analyze_scope_callability(
    ir: Mapping[str, object],
    *,
    deployment_scope_ceiling: Collection[str],
    principal_context: PrincipalContext | None = None,
    requirements_by_capability: Mapping[str, CapabilityScopeRequirements] | None = None,
) -> ScopeCallabilityReport:
    """Compare typed scope requirements with deployment, user, and effective scopes."""

    ceiling = _normalize_scopes(deployment_scope_ceiling, reason="deployment_scope_invalid")
    ir_version = ir.get("ir_version")
    if ir_version != "2":
        raise CallabilityAnalysisError("ir_version_invalid")
    requirements = (
        _validated_typed_requirements(requirements_by_capability)
        if requirements_by_capability is not None
        else _requirements_from_ir(ir)
    )

    user_scopes: ScopeSet | None = None
    effective_scopes: ScopeSet | None = None
    if principal_context is not None:
        project = _project_from_ir(ir)
        if principal_context.target_system_id != project.project.id:
            raise CallabilityAnalysisError("principal_target_mismatch")
        if principal_context.deployment_scope_ceiling != ceiling:
            raise CallabilityAnalysisError("deployment_scope_mismatch")
        effective_scopes = principal_context.effective_scopes
        if principal_context.source_scopes is not None:
            universe = frozenset(
                scope
                for requirement in requirements.values()
                for scope in requirement.all_referenced
            )
            auth = project.provider.auth
            scope_mapping = auth.scope_mapping if isinstance(auth, PasswordBearerAuthConfig) else {}
            user_scopes = map_effective_scopes(
                principal_context.source_scopes,
                universe,
                scope_mapping,
            )

    capabilities = tuple(
        _capability_callability(
            requirements[capability_id],
            deployment_scopes=ceiling,
            user_scopes=user_scopes,
            effective_scopes=effective_scopes,
        )
        for capability_id in sorted(requirements)
    )
    return ScopeCallabilityReport(
        ir_version=ir_version,
        deployment_scope_ceiling=ceiling,
        capabilities=capabilities,
    )


def _capability_callability(
    requirements: CapabilityScopeRequirements,
    *,
    deployment_scopes: ScopeSet,
    user_scopes: ScopeSet | None,
    effective_scopes: ScopeSet | None,
) -> CapabilityCallability:
    return CapabilityCallability(
        capability_id=requirements.capability_id,
        always_required=requirements.always_required,
        conditionally_required=requirements.conditionally_required,
        all_referenced=requirements.all_referenced,
        completion_alternatives=requirements.completion_alternatives,
        deployment=_dimension(requirements, deployment_scopes),
        user=_dimension(requirements, user_scopes),
        effective=_dimension(requirements, effective_scopes),
    )


def _dimension(
    requirements: CapabilityScopeRequirements,
    available_scopes: ScopeSet | None,
) -> ScopeDimensionCallability:
    if available_scopes is None:
        return ScopeDimensionCallability(
            status=CallabilityStatus.UNKNOWN,
            available_scopes=None,
            missing_always=frozenset(),
            missing_conditional=frozenset(),
            unmet_alternatives=(),
        )
    feasible_union = requirements.always_required | requirements.conditionally_required
    if feasible_union <= available_scopes:
        status = CallabilityStatus.CALLABLE
    elif any(
        alternative <= available_scopes for alternative in requirements.completion_alternatives
    ):
        status = CallabilityStatus.CONDITIONAL
    else:
        status = CallabilityStatus.DENIED
    return ScopeDimensionCallability(
        status=status,
        available_scopes=available_scopes,
        missing_always=requirements.always_required - available_scopes,
        missing_conditional=requirements.conditionally_required - available_scopes,
        unmet_alternatives=tuple(
            alternative - available_scopes
            for alternative in requirements.completion_alternatives
            if not alternative <= available_scopes
        ),
    )


def _requirements_from_ir(
    ir: Mapping[str, object],
) -> dict[str, CapabilityScopeRequirements]:
    raw_capabilities = ir.get("capabilities")
    if not isinstance(raw_capabilities, Mapping):
        raise CallabilityAnalysisError("capabilities_invalid")
    requirements: dict[str, CapabilityScopeRequirements] = {}
    for capability_id, raw_compiled in raw_capabilities.items():
        if not isinstance(capability_id, str) or not isinstance(raw_compiled, Mapping):
            raise CallabilityAnalysisError("capabilities_invalid")
        requirements[capability_id] = _requirements_from_mapping(
            capability_id,
            raw_compiled.get("scope_requirements"),
        )
    return requirements


def _requirements_from_mapping(
    capability_id: str,
    raw: object,
) -> CapabilityScopeRequirements:
    if not isinstance(raw, Mapping):
        raise CallabilityAnalysisError("scope_requirements_invalid")
    try:
        policy = _string_array(raw.get("policy_always_required"))
        always = _string_array(raw.get("always_required"))
        conditional = _string_array(raw.get("conditionally_required"))
        referenced = _string_array(raw.get("all_referenced"))
        raw_alternatives = raw.get("completion_alternatives")
        if not isinstance(raw_alternatives, list) or not raw_alternatives:
            raise ValueError
        alternatives = tuple(_string_array(item) for item in raw_alternatives)
        requirement = CapabilityScopeRequirements(
            capability_id=capability_id,
            policy_always_required=policy,
            always_required=always,
            conditionally_required=conditional,
            all_referenced=referenced,
            completion_alternatives=alternatives,
        )
        _validate_requirement(requirement)
        return requirement
    except (TypeError, ValueError):
        raise CallabilityAnalysisError("scope_requirements_invalid") from None


def _validated_typed_requirements(
    values: Mapping[str, CapabilityScopeRequirements],
) -> dict[str, CapabilityScopeRequirements]:
    result: dict[str, CapabilityScopeRequirements] = {}
    for capability_id, requirement in values.items():
        if (
            not isinstance(capability_id, str)
            or not isinstance(requirement, CapabilityScopeRequirements)
            or requirement.capability_id != capability_id
        ):
            raise CallabilityAnalysisError("typed_scope_requirements_invalid")
        _validate_requirement(requirement)
        result[capability_id] = requirement
    return result


def _validate_requirement(requirement: CapabilityScopeRequirements) -> None:
    if (
        not requirement.completion_alternatives
        or not requirement.policy_always_required <= requirement.always_required
        or requirement.always_required & requirement.conditionally_required
        or not (requirement.always_required | requirement.conditionally_required)
        <= requirement.all_referenced
        or any(
            not requirement.always_required <= alternative
            for alternative in requirement.completion_alternatives
        )
    ):
        raise CallabilityAnalysisError("scope_requirements_invalid")


def _string_array(value: object) -> ScopeSet:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError
    return frozenset(value)


def _normalize_scopes(value: Collection[str], *, reason: str) -> ScopeSet:
    if isinstance(value, str) or any(not isinstance(item, str) or not item for item in value):
        raise CallabilityAnalysisError(reason)
    return frozenset(value)


def _project_from_ir(ir: Mapping[str, object]) -> ProjectV2:
    try:
        return ProjectV2.model_validate(ir.get("project"))
    except (TypeError, ValueError):
        raise CallabilityAnalysisError("project_invalid") from None


__all__ = [
    "CallabilityAnalysisError",
    "CallabilityStatus",
    "CapabilityCallability",
    "ScopeCallabilityReport",
    "ScopeDimensionCallability",
    "analyze_scope_callability",
]
