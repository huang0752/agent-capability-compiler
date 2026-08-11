"""Faithful, platform-neutral projections of released Agent Usage contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from acc_core.diagnostics import Diagnostic
from acc_core.usage.models import AgentUsageRelease, DomainUsageContract, UsageToolRoute
from acc_core.usage.packaging import VerifiedUsagePackage

_SUPPORTED_ADAPTER_FEATURES = frozenset({"markdown-guide"})
_TRUSTED_REFERENCE_ADAPTERS = frozenset({"generic-markdown", "reference-host"})
_VERIFICATION_FIELDS = (
    "source_usage_traced",
    "usage_contract_verified",
    "headless_agent_verified",
    "host_adapter_verified",
    "real_mcp_verified",
    "user_accepted",
)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _without_evidence(value: Any) -> Any:
    """Remove proof-linkage fields while retaining executable route semantics."""

    if isinstance(value, dict):
        return {
            key: _without_evidence(item)
            for key, item in value.items()
            if key not in {"evidence_claim_ids", "evidence_refs"}
        }
    if isinstance(value, list):
        return [_without_evidence(item) for item in value]
    return value


def _route_projection(contract: DomainUsageContract, route: UsageToolRoute) -> dict[str, Any]:
    step_ids = {step.id for step in route.steps}
    step_pairs = {(step.capability_id, step.id) for step in route.steps}
    binding_ids = {binding_id for step in route.steps for binding_id in step.binding_ids}

    def model_values(items: list[Any]) -> list[dict[str, Any]]:
        return [_without_evidence(item.model_dump(mode="json")) for item in items]

    bindings = [item for item in contract.input_bindings if item.id in binding_ids]
    defaults = [
        item for item in contract.defaults if (item.capability_id, item.step_id) in step_pairs
    ]
    conditions = [item for item in contract.conditions if item.route_id == route.id]
    option_sources = [item for item in contract.option_sources if item.consumer_step_id in step_ids]
    related_data = [
        item
        for item in contract.related_data
        if item.producer_step_id in step_ids and item.consumer_step_id in step_ids
    ]
    result_consumption = [
        item
        for item in contract.result_consumption
        if (item.capability_id, item.step_id) in step_pairs
    ]
    error_handling = [item for item in contract.error_handling if item.id in route.error_branch_ids]
    action_lifecycle = next(
        (item for item in contract.action_lifecycles if item.id == route.action_lifecycle_id),
        None,
    )
    return {
        "action_lifecycle": (
            None
            if action_lifecycle is None
            else _without_evidence(action_lifecycle.model_dump(mode="json"))
        ),
        "bindings": model_values(bindings),
        "business_goal_id": route.business_goal_id,
        "conditions": model_values(conditions),
        "defaults": model_values(defaults),
        "error_handling": model_values(error_handling),
        "id": route.id,
        "option_sources": model_values(option_sources),
        "preconditions": list(route.preconditions),
        "related_data": model_values(related_data),
        "result_consumption": model_values(result_consumption),
        "result_pointer": route.result_pointer,
        "result_step_id": route.result_step_id,
        "steps": model_values(route.steps),
    }


@dataclass(frozen=True)
class UsageAdapterInput:
    """The only platform-neutral facts a host renderer needs to receive."""

    release: dict[str, Any]
    business_goals: tuple[dict[str, Any], ...]
    tool_routes: tuple[dict[str, Any], ...]
    safety: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return {
            "business_goals": [dict(item) for item in self.business_goals],
            "release": dict(self.release),
            "safety": dict(self.safety),
            "tool_routes": [dict(item) for item in self.tool_routes],
        }

    @property
    def digest(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class AdapterArtifacts:
    """A renderer result plus a machine-checkable claim about its projection."""

    adapter_id: str
    guide_bytes: bytes
    package_digest: str
    usage_release_id: str
    contract_digest: str
    decision_digest: str
    tool_schema_digest: str
    projection_digest: str
    business_goal_ids: tuple[str, ...]
    route_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    tool_names: tuple[str, ...]
    prohibited_behaviors: tuple[str, ...]
    verification: tuple[tuple[str, bool], ...]
    known_limitations: tuple[str, ...]
    permissions: tuple[str, ...] = ()
    action_shortcuts: tuple[str, ...] = ()
    required_features: tuple[str, ...] = ("markdown-guide",)

    def manifest_dict(self) -> dict[str, object]:
        return {
            "action_shortcuts": list(self.action_shortcuts),
            "adapter_id": self.adapter_id,
            "business_goal_ids": list(self.business_goal_ids),
            "capability_ids": list(self.capability_ids),
            "contract_digest": self.contract_digest,
            "decision_digest": self.decision_digest,
            "guide_digest": _sha256(self.guide_bytes),
            "known_limitations": list(self.known_limitations),
            "package_digest": self.package_digest,
            "permissions": list(self.permissions),
            "prohibited_behaviors": list(self.prohibited_behaviors),
            "projection_digest": self.projection_digest,
            "required_features": list(self.required_features),
            "route_ids": list(self.route_ids),
            "tool_names": list(self.tool_names),
            "tool_schema_digest": self.tool_schema_digest,
            "usage_release_id": self.usage_release_id,
            "verification": dict(self.verification),
        }


class UsageAdapter(Protocol):
    """A host-specific renderer that cannot change the core Usage truth."""

    adapter_id: str

    def render(
        self,
        release: AgentUsageRelease,
        package: VerifiedUsagePackage,
    ) -> AdapterArtifacts: ...


def _resolve_contract(
    release: AgentUsageRelease, package: VerifiedUsagePackage
) -> tuple[AgentUsageRelease, DomainUsageContract]:
    if not package.trusted:
        raise ValueError("renderer requires a live trusted Usage package")
    packaged_release = package.releases.get(release.domain_id)
    contract = package.contracts.get(release.domain_id)
    if packaged_release is None or contract is None:
        raise ValueError("release domain is not present in the verified Usage package")
    if release.model_dump(mode="json") != packaged_release.model_dump(mode="json"):
        raise ValueError("release is not the exact active packaged Usage release")
    if packaged_release.tool_schema_digest != package.manifest.tool_schema_digest:
        raise ValueError("release digests do not match the verified Usage package")
    return packaged_release, contract


def build_usage_adapter_input(
    release: AgentUsageRelease,
    package: VerifiedUsagePackage,
) -> UsageAdapterInput:
    """Project one exact release without proof locators or unreleased contract members."""

    release, contract = _resolve_contract(release, package)
    goal_by_id = {goal.id: goal for goal in contract.business_goals}
    route_by_id = {route.id: route for route in contract.tool_routes}
    try:
        goals = tuple(
            {"description": goal_by_id[goal_id].description, "id": goal_id}
            for goal_id in release.business_goal_ids
        )
        routes = tuple(
            _route_projection(contract, route_by_id[route_id]) for route_id in release.route_ids
        )
    except KeyError as exc:
        raise ValueError("release references a missing contract goal or route") from exc
    if any(route["business_goal_id"] not in release.business_goal_ids for route in routes):
        raise ValueError("released route references an unreleased business goal")

    projection = UsageAdapterInput(
        release={
            "business_goal_ids": list(release.business_goal_ids),
            "contract_digest": release.contract_digest,
            "decision_digest": release.decision_digest,
            "domain_id": release.domain_id,
            "known_limitations": list(release.known_limitations),
            "package_digest": package.sha256,
            "release_status": release.release_status,
            "route_ids": list(release.route_ids),
            "tool_schema_digest": release.tool_schema_digest,
            "usage_release_id": release.usage_release_id,
            "verification": release.verification.model_dump(mode="json"),
        },
        business_goals=goals,
        tool_routes=routes,
        safety={
            "prohibited_behaviors": list(contract.prohibited_behaviors),
            "source_authorization": "The source API remains authoritative for every request.",
        },
    )
    encoded = _canonical_json(projection.to_dict()).decode()
    forbidden_locators = {
        source_id for records in package.evidence.values() for source_id, _digest in records
    }
    if "embedded-artifact:" in encoded or any(locator in encoded for locator in forbidden_locators):
        raise ValueError("adapter input contains an Evidence locator")
    return projection


def _markdown(input_document: UsageAdapterInput) -> bytes:
    release = input_document.release
    verification = release["verification"]
    assert isinstance(verification, dict)
    lines = [
        "# Agent Usage Guide",
        "",
        "This guide is a platform-neutral projection of one verified Agent Usage release.",
        "The source API remains authoritative for authentication and authorization "
        "on every request.",
        "",
        "## Release",
        "",
        f"- Usage release: {release['usage_release_id']}",
        f"- Domain: {release['domain_id']}",
        f"- Release status: {release['release_status']}",
        f"- Package digest: {release['package_digest']}",
        f"- Contract digest: {release['contract_digest']}",
        f"- Decision digest: {release['decision_digest']}",
        f"- Tool schema digest: {release['tool_schema_digest']}",
        "",
        "## Verification limits",
        "",
    ]
    for field in _VERIFICATION_FIELDS:
        lines.append(f"- {field}: {str(verification[field]).lower()}")
    lines.extend(["", "## Known limitations", ""])
    limitations = release["known_limitations"]
    assert isinstance(limitations, list)
    lines.extend(f"- {item}" for item in limitations)
    if not limitations:
        lines.append("- None declared.")

    goals = {str(item["id"]): item for item in input_document.business_goals}
    lines.extend(["", "## Released routes", ""])
    for route in input_document.tool_routes:
        goal = goals[str(route["business_goal_id"])]
        lines.extend(
            [
                f"### {route['id']}",
                "",
                f"Goal: {goal['description']}",
                f"Result: step `{route['result_step_id']}` at `{route['result_pointer']}`.",
                "",
                "Steps:",
                "",
            ]
        )
        steps = route["steps"]
        assert isinstance(steps, list)
        for step in steps:
            assert isinstance(step, dict)
            phase = "" if step["action_phase"] is None else f", phase `{step['action_phase']}`"
            lines.append(
                f"- `{step['id']}` calls `{step['tool_name']}` "
                f"(capability `{step['capability_id']}`, retry `{step['retry']}`{phase})."
            )
    lines.extend(["", "## Safety", ""])
    for item in input_document.safety["prohibited_behaviors"]:
        lines.append(f"- {item}")
    lines.append("- The source API remains authoritative for every request.")
    lines.extend(
        [
            "",
            "## Structured route projection",
            "",
            "```json",
            _canonical_json(list(input_document.tool_routes)).decode().rstrip("\n"),
            "```",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


class GenericMarkdownRenderer:
    """Reference renderer for a generic Markdown agent guide."""

    def __init__(self, *, adapter_id: str = "generic-markdown") -> None:
        self.adapter_id = adapter_id

    def render(
        self,
        release: AgentUsageRelease,
        package: VerifiedUsagePackage,
    ) -> AdapterArtifacts:
        projection = build_usage_adapter_input(release, package)
        routes = projection.tool_routes
        tool_names = tuple(
            sorted({str(step["tool_name"]) for route in routes for step in route["steps"]})
        )
        capability_ids = tuple(
            sorted({str(step["capability_id"]) for route in routes for step in route["steps"]})
        )
        return AdapterArtifacts(
            adapter_id=self.adapter_id,
            guide_bytes=_markdown(projection),
            package_digest=package.sha256,
            usage_release_id=release.usage_release_id,
            contract_digest=release.contract_digest,
            decision_digest=release.decision_digest,
            tool_schema_digest=release.tool_schema_digest,
            projection_digest=projection.digest,
            business_goal_ids=tuple(release.business_goal_ids),
            route_ids=tuple(release.route_ids),
            capability_ids=capability_ids,
            tool_names=tool_names,
            prohibited_behaviors=tuple(projection.safety["prohibited_behaviors"]),
            verification=tuple(
                (field, bool(release.verification.model_dump(mode="json")[field]))
                for field in _VERIFICATION_FIELDS
            ),
            known_limitations=tuple(release.known_limitations),
        )


def render_generic_agent_guide(
    release: AgentUsageRelease,
    package: VerifiedUsagePackage,
) -> bytes:
    """Render the reference platform-neutral guide bytes."""

    return GenericMarkdownRenderer().render(release, package).guide_bytes


def _diagnostic(code: str, message: str) -> Diagnostic:
    return Diagnostic(code=code, severity="error", message=message, path=None, pointer=None)


def _secret_or_locator_present(artifacts: AdapterArtifacts, package: VerifiedUsagePackage) -> bool:
    try:
        text = artifacts.guide_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return True
    if re.search(r"(?i)(?:authorization\s*:|bearer\s+|set-cookie\s*:|cookie\s*:)", text):
        return True
    if re.search(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", text):
        return True
    if "embedded-artifact:" in text or "evidence locator" in text.lower():
        return True
    return any(
        source_id in text for records in package.evidence.values() for source_id, _ in records
    )


class AdapterArtifactValidator:
    """Fail closed when a host output claims authority absent from the release."""

    def __init__(self, release: AgentUsageRelease, package: VerifiedUsagePackage) -> None:
        self.release = release
        self.package = package

    def validate(self, artifacts: AdapterArtifacts) -> tuple[Diagnostic, ...]:
        expected = GenericMarkdownRenderer(adapter_id=artifacts.adapter_id).render(
            self.release, self.package
        )
        diagnostics: list[Diagnostic] = []
        trusted_reference = artifacts.adapter_id in _TRUSTED_REFERENCE_ADAPTERS
        if not trusted_reference:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_UNTRUSTED",
                    "adapter has no registered trusted output validator",
                )
            )
        elif artifacts.guide_bytes != expected.guide_bytes:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_GUIDE_MISMATCH",
                    "adapter guide does not match its trusted reference output",
                )
            )
        if (
            artifacts.package_digest != expected.package_digest
            or artifacts.usage_release_id != expected.usage_release_id
            or artifacts.contract_digest != expected.contract_digest
            or artifacts.decision_digest != expected.decision_digest
            or artifacts.tool_schema_digest != expected.tool_schema_digest
            or artifacts.projection_digest != expected.projection_digest
        ):
            diagnostics.append(
                _diagnostic("ACC_USAGE_ADAPTER_DIGEST_MISMATCH", "adapter digests do not match")
            )
        if not set(artifacts.business_goal_ids) <= set(expected.business_goal_ids):
            diagnostics.append(
                _diagnostic("ACC_USAGE_ADAPTER_GOAL_ADDED", "adapter adds an unreleased goal")
            )
        if not set(artifacts.route_ids) <= set(expected.route_ids):
            diagnostics.append(
                _diagnostic("ACC_USAGE_ADAPTER_ROUTE_ADDED", "adapter adds an unreleased route")
            )
        if not set(artifacts.capability_ids) <= set(expected.capability_ids):
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_CAPABILITY_ADDED", "adapter adds an undeclared capability"
                )
            )
        if not set(artifacts.tool_names) <= set(expected.tool_names):
            diagnostics.append(
                _diagnostic("ACC_USAGE_ADAPTER_TOOL_ADDED", "adapter adds an undeclared tool")
            )
        if artifacts.action_shortcuts:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_ACTION_SHORTCUT",
                    "adapter cannot bypass the declared Action lifecycle",
                )
            )
        if artifacts.permissions:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_PERMISSION_ADDED",
                    "adapter cannot grant or infer source permissions",
                )
            )
        if not set(artifacts.required_features) <= _SUPPORTED_ADAPTER_FEATURES:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_FEATURE_UNSUPPORTED",
                    "adapter requires an unsupported host feature",
                )
            )
        if artifacts.verification != expected.verification:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_VERIFICATION_CHANGED",
                    "adapter changes an independent verification axis",
                )
            )
        if artifacts.known_limitations != expected.known_limitations:
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_LIMITATION_CHANGED",
                    "adapter changes release limitations",
                )
            )
        if not set(artifacts.prohibited_behaviors) >= set(expected.prohibited_behaviors):
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_SAFETY_REMOVED",
                    "adapter removes a prohibited behavior",
                )
            )
        if _secret_or_locator_present(artifacts, self.package):
            diagnostics.append(
                _diagnostic(
                    "ACC_USAGE_ADAPTER_SECRET",
                    "adapter output contains a credential or Evidence locator",
                )
            )
        return tuple(diagnostics)


def validate_adapter_artifacts(
    release: AgentUsageRelease,
    package: VerifiedUsagePackage,
    artifacts: AdapterArtifacts,
) -> tuple[Diagnostic, ...]:
    """Validate one host projection without upgrading any verification axis."""

    return AdapterArtifactValidator(release, package).validate(artifacts)


__all__ = [
    "AdapterArtifactValidator",
    "AdapterArtifacts",
    "GenericMarkdownRenderer",
    "UsageAdapter",
    "UsageAdapterInput",
    "build_usage_adapter_input",
    "render_generic_agent_guide",
    "validate_adapter_artifacts",
]
