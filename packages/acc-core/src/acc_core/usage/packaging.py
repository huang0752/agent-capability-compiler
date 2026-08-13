"""Build and verify the independent deterministic Agent Usage package format.

The package carries only released, digest-bound Usage contracts.  Its lock file
establishes archive integrity; its HMAC receipt binds a live verified release to
an explicit deployment trust root without replacing source-system authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import weakref
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import ClassVar, Protocol

from pydantic import BaseModel, ValidationError

from acc_core.usage.models import (
    AgentUsageRelease,
    DomainUsageContract,
    UsageDomainDecision,
    UsageScenario,
)
from acc_core.usage.project import validate_usage_project
from acc_core.usage.verification import VerifiedUsageReleaseBundle

USAGE_PACKAGE_FORMAT = "acc.agent-usage-package"
USAGE_PACKAGE_FORMAT_VERSION = 2
USAGE_PACKAGE_SUFFIX = ".accusage"
USAGE_PACKAGE_MAX_MEMBER_BYTES = 1024 * 1024
USAGE_PACKAGE_MAX_TOTAL_BYTES = 16 * 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

_REQUIRED_ENTRIES = {"manifest.json", "usage.lock"}
_RECEIPT_PATH = "release-receipt.json"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_LOCK_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_DOMAIN_MEMBER_PATTERN = re.compile(
    r"domains/[0-9]{4}/(?:contract|decision|evidence|release)\.json"
)
_SCENARIO_MEMBER_PATTERN = re.compile(r"domains/[0-9]{4}/scenarios/[0-9]{4}\.json")
_SIGNING_ALGORITHM = "hmac-sha256"
_MIN_SIGNING_KEY_BYTES = 32


def _is_path_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


class _EvidenceClaimBound(Protocol):
    evidence_claim_ids: list[str]


class UsagePackageError(Exception):
    """Base class for stable Agent Usage package failures."""

    code: ClassVar[str] = "ACC_USAGE_PACKAGE_ERROR"

    def __init__(self, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.path = path


class UsagePackagePathError(UsagePackageError, ValueError):
    code = "ACC_USAGE_PACKAGE_PATH_INVALID"


class UsagePackageSymlinkError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_SYMLINK_REJECTED"


class UsagePackageDuplicateEntryError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_ENTRY_DUPLICATE"


class UsagePackageUnknownEntryError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_ENTRY_UNKNOWN"


class UsagePackageChecksumMismatchError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_CHECKSUM_MISMATCH"


class UsagePackageFileTooLargeError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_FILE_TOO_LARGE"


class UsagePackageFormatError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_FORMAT_INVALID"


class UsagePackageTrustError(UsagePackageError):
    code = "ACC_USAGE_PACKAGE_TRUST_INVALID"


class UsagePackageSigner:
    """In-process deterministic signer backed by a deployment-owned secret."""

    __slots__ = ("__key", "_key_id")

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < _MIN_SIGNING_KEY_BYTES:
            raise ValueError("Usage package signing key must contain at least 32 bytes")
        copied = bytes(memoryview(key))
        self.__key = copied
        self._key_id = "sha256:" + hashlib.sha256(copied).hexdigest()

    @property
    def key_id(self) -> str:
        """Return the public selector; it does not authenticate a key by itself."""

        return self._key_id

    def _sign(self, contents: bytes) -> str:
        return hmac.new(self.__key, contents, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return f"UsagePackageSigner(key_id={self.key_id!r})"


class UsagePackageTrustStore:
    """Copied deployment trust roots indexed by their public key digest."""

    __slots__ = ("__keys",)

    def __init__(self, keys: Mapping[str, bytes] | Sequence[tuple[str, bytes]]) -> None:
        copied: dict[str, bytes] = {}
        items = keys.items() if isinstance(keys, Mapping) else keys
        for key_id, key in items:
            if not isinstance(key_id, str) or not isinstance(key, bytes):
                raise ValueError("Usage package trust roots must be key-id/bytes pairs")
            if len(key) < _MIN_SIGNING_KEY_BYTES:
                raise ValueError("Usage package trust keys must contain at least 32 bytes")
            key_copy = bytes(memoryview(key))
            expected_id = "sha256:" + hashlib.sha256(key_copy).hexdigest()
            if key_id != expected_id or key_id in copied:
                raise ValueError("Usage package trust key id is invalid or duplicated")
            copied[key_id] = key_copy
        self.__keys = MappingProxyType(copied)

    def _verify(self, key_id: str, contents: bytes, signature: str) -> bool:
        key = self.__keys.get(key_id)
        if key is None:
            return False
        expected = hmac.new(key, contents, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def __repr__(self) -> str:
        return f"UsagePackageTrustStore(key_ids={tuple(sorted(self.__keys))!r})"


@dataclass(frozen=True, slots=True)
class UsagePackageFileRecord:
    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class UsagePackageScenarioMember:
    scenario_id: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "scenario_id": self.scenario_id}


@dataclass(frozen=True, slots=True)
class UsagePackageDomainMember:
    domain_id: str
    usage_release_id: str
    contract: str
    decision: str
    release: str
    scenarios: tuple[UsagePackageScenarioMember, ...]
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "contract": self.contract,
            "decision": self.decision,
            "domain_id": self.domain_id,
            "evidence": self.evidence,
            "release": self.release,
            "scenarios": [item.to_dict() for item in self.scenarios],
            "usage_release_id": self.usage_release_id,
        }


@dataclass(frozen=True, slots=True)
class UsagePackageManifest:
    format: str
    format_version: int
    project_id: str
    project_version: str
    mcp_release_id: str
    pack_digest: str
    ir_digest: str
    tool_schema_digest: str
    test_report_digest: str
    source_snapshot_digest: str
    domains: tuple[UsagePackageDomainMember, ...]

    @property
    def released_domain_ids(self) -> tuple[str, ...]:
        return tuple(item.domain_id for item in self.domains)

    def to_dict(self) -> dict[str, object]:
        return {
            "domains": [item.to_dict() for item in self.domains],
            "format": self.format,
            "format_version": self.format_version,
            "mcp_release": {
                "ir_digest": self.ir_digest,
                "pack_digest": self.pack_digest,
                "release_id": self.mcp_release_id,
                "source_snapshot_digest": self.source_snapshot_digest,
                "test_report_digest": self.test_report_digest,
                "tool_schema_digest": self.tool_schema_digest,
            },
            "project": {"id": self.project_id, "version": self.project_version},
        }


@dataclass(frozen=True, slots=True)
class UsageReleaseReceiptDomain:
    domain_id: str
    usage_release_id: str
    bundle_digest: str
    release_digest: str
    report_digests: Mapping[str, str]
    contract_digest: str
    scenario_digests: Mapping[str, str]
    mcp_pack_digest: str
    decision_digest: str
    selected_closure_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_digests", MappingProxyType(dict(self.report_digests)))
        object.__setattr__(self, "scenario_digests", MappingProxyType(dict(self.scenario_digests)))

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_digest": self.bundle_digest,
            "contract_digest": self.contract_digest,
            "decision_digest": self.decision_digest,
            "domain_id": self.domain_id,
            "mcp_pack_digest": self.mcp_pack_digest,
            "release_digest": self.release_digest,
            "report_digests": dict(self.report_digests),
            "scenario_digests": dict(self.scenario_digests),
            "selected_closure_digest": self.selected_closure_digest,
            "usage_release_id": self.usage_release_id,
        }


@dataclass(frozen=True, slots=True)
class UsageReleaseReceipt:
    schema_version: str
    algorithm: str
    key_id: str
    manifest_logical_digest: str
    domains: tuple[UsageReleaseReceiptDomain, ...]
    signature: str

    def signed_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "domains": [item.to_dict() for item in self.domains],
            "key_id": self.key_id,
            "manifest_logical_digest": self.manifest_logical_digest,
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.signed_dict(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class UsagePackageBuildResult:
    path: Path
    sha256: str
    manifest: UsagePackageManifest


class _VerifiedModelMapping[ModelT: BaseModel](Mapping[str, ModelT]):
    """Immutable mapping that materializes a fresh model for every access."""

    __slots__ = ("_model_type", "_payloads")

    def __init__(self, payloads: Mapping[str, bytes], model_type: type[ModelT]) -> None:
        self._payloads = payloads
        self._model_type = model_type

    def __getitem__(self, key: str) -> ModelT:
        return self._model_type.model_validate_json(self._payloads[key])

    def __iter__(self) -> Iterator[str]:
        return iter(self._payloads)

    def __len__(self) -> int:
        return len(self._payloads)


def _verified_model_mapping[ModelT: BaseModel](
    values: Mapping[str, ModelT], model_type: type[ModelT]
) -> Mapping[str, ModelT]:
    payloads = {
        key: _canonical_json(value.model_dump(mode="json"), description="verified model")
        for key, value in values.items()
    }
    return _VerifiedModelMapping(MappingProxyType(payloads), model_type)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class VerifiedUsagePackage:
    """Verified immutable bytes with defensive typed accessors.

    Pydantic's frozen models do not recursively freeze their list fields.  The
    package therefore retains canonical bytes as authority and reconstructs
    fresh typed snapshots for callers instead of exposing verified model state.
    """

    path: Path
    sha256: str
    manifest: UsagePackageManifest
    files: tuple[UsagePackageFileRecord, ...]
    contracts: Mapping[str, DomainUsageContract]
    decisions: Mapping[str, UsageDomainDecision]
    releases: Mapping[str, AgentUsageRelease]
    scenarios: Mapping[str, UsageScenario]
    evidence: Mapping[str, tuple[tuple[str, str], ...]]
    release_receipt: UsageReleaseReceipt | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contracts",
            _verified_model_mapping(self.contracts, DomainUsageContract),
        )
        object.__setattr__(
            self,
            "decisions",
            _verified_model_mapping(self.decisions, UsageDomainDecision),
        )
        object.__setattr__(
            self,
            "releases",
            _verified_model_mapping(self.releases, AgentUsageRelease),
        )
        object.__setattr__(
            self,
            "scenarios",
            _verified_model_mapping(self.scenarios, UsageScenario),
        )
        object.__setattr__(
            self,
            "evidence",
            MappingProxyType(
                {domain_id: tuple(records) for domain_id, records in self.evidence.items()}
            ),
        )

    @property
    def trusted(self) -> bool:
        """Return whether this exact, unchanged object came from live verification."""

        return _is_live_verified_package(self)


def _verified_package_fingerprint(value: VerifiedUsagePackage) -> str:
    document = {
        "contracts": {key: item.model_dump(mode="json") for key, item in value.contracts.items()},
        "decisions": {key: item.model_dump(mode="json") for key, item in value.decisions.items()},
        "evidence": {key: list(records) for key, records in value.evidence.items()},
        "files": [item.to_dict() for item in value.files],
        "manifest": value.manifest.to_dict(),
        "path": str(value.path),
        "release_receipt": (
            None if value.release_receipt is None else value.release_receipt.to_dict()
        ),
        "releases": {key: item.model_dump(mode="json") for key, item in value.releases.items()},
        "scenarios": {key: item.model_dump(mode="json") for key, item in value.scenarios.items()},
        "sha256": value.sha256,
    }
    return _canonical_digest(document)


class _VerifiedPackageChecker(Protocol):
    def __call__(self, value: VerifiedUsagePackage) -> bool: ...


class _VerifiedPackageVerifier(Protocol):
    def __call__(
        self,
        package_path: str | os.PathLike[str],
        *,
        trust_store: UsagePackageTrustStore | None = None,
        max_member_bytes: int = USAGE_PACKAGE_MAX_MEMBER_BYTES,
        max_total_bytes: int = USAGE_PACKAGE_MAX_TOTAL_BYTES,
    ) -> VerifiedUsagePackage: ...


UsagePackageVerification = VerifiedUsagePackage


def _validate_limits(max_member_bytes: int, max_total_bytes: int) -> None:
    for name, value in (
        ("max_member_bytes", max_member_bytes),
        ("max_total_bytes", max_total_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")


def _canonical_json(value: object, *, description: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise UsagePackageFormatError(f"{description} must contain canonical JSON values") from exc
    return f"{encoded}\n".encode()


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _canonical_digest(value: object) -> str:
    contents = _canonical_json(value, description="digest input")
    return "sha256:" + _sha256(contents[:-1])


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(path: str, contents: bytes) -> UsagePackageFileRecord:
    return UsagePackageFileRecord(path=path, sha256=_sha256(contents), size=len(contents))


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def _validate_member_path(path: str) -> None:
    posix = PurePosixPath(path)
    windows = PureWindowsPath(path)
    if (
        not path
        or "\\" in path
        or "\x00" in path
        or path.endswith("/")
        or posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise UsagePackagePathError("unsafe Agent Usage package member path", path=path)


def _is_allowed_member(path: str) -> bool:
    return (
        path in _REQUIRED_ENTRIES
        or path == _RECEIPT_PATH
        or _DOMAIN_MEMBER_PATTERN.fullmatch(path) is not None
        or _SCENARIO_MEMBER_PATTERN.fullmatch(path) is not None
    )


def _ensure_payload_limits(
    payloads: Mapping[str, bytes], *, max_member_bytes: int, max_total_bytes: int
) -> None:
    total = 0
    for path, contents in payloads.items():
        if len(contents) > max_member_bytes:
            raise UsagePackageFileTooLargeError(
                f"Agent Usage package member exceeds {max_member_bytes} bytes", path=path
            )
        total += len(contents)
    if total > max_total_bytes:
        raise UsagePackageFileTooLargeError(
            f"Agent Usage package total exceeds {max_total_bytes} bytes"
        )


def _selected_contract_projection(
    contract: DomainUsageContract,
    decision: UsageDomainDecision,
    release: AgentUsageRelease,
) -> DomainUsageContract:
    """Close one contract over exactly the user-selected goals and routes."""

    selected_goal_ids = set(decision.business_goal_ids)
    selected_route_ids = set(decision.included_route_ids)
    routes = [route for route in contract.tool_routes if route.id in selected_route_ids]
    goals = [goal for goal in contract.business_goals if goal.id in selected_goal_ids]
    step_ids = {step.id for route in routes for step in route.steps}
    binding_ids = {
        binding_id for route in routes for step in route.steps for binding_id in step.binding_ids
    }
    error_ids = {error_id for route in routes for error_id in route.error_branch_ids}
    lifecycle_ids = {
        route.action_lifecycle_id for route in routes if route.action_lifecycle_id is not None
    }

    bindings = [item for item in contract.input_bindings if item.id in binding_ids]
    defaults = [item for item in contract.defaults if item.step_id in step_ids]
    conditions = [
        item
        for item in contract.conditions
        if item.route_id in selected_route_ids
        and (item.step_id is None or item.step_id in step_ids)
    ]
    option_sources = [
        item
        for item in contract.option_sources
        if item.consumer_step_id in step_ids
        and (item.producer_step_id is None or item.producer_step_id in step_ids)
    ]
    related_data = [
        item
        for item in contract.related_data
        if item.consumer_step_id in step_ids and item.producer_step_id in step_ids
    ]
    result_consumption = [item for item in contract.result_consumption if item.step_id in step_ids]
    error_handling = [item for item in contract.error_handling if item.id in error_ids]
    action_lifecycles = [item for item in contract.action_lifecycles if item.id in lifecycle_ids]
    required_scenario_ids = [
        scenario_id
        for scenario_id in contract.required_scenario_ids
        if scenario_id in set(release.scenario_ids)
    ]

    retained_targets = {
        "business_goal": {item.id for item in goals},
        "tool_route": {item.id for item in routes},
        "input_binding": {item.id for item in bindings},
        "default": {item.id for item in defaults},
        "condition": {item.id for item in conditions},
        "option_source": {item.id for item in option_sources},
        "related_data": {item.id for item in related_data},
        "result_consumption": {item.id for item in result_consumption},
        "error_branch": {item.id for item in error_handling},
        "action_lifecycle": {item.id for item in action_lifecycles},
    }
    retained_semantics: tuple[_EvidenceClaimBound, ...] = (
        *goals,
        *defaults,
        *conditions,
        *option_sources,
        *related_data,
        *result_consumption,
        *error_handling,
    )
    referenced_claim_ids = {
        claim_id for semantic in retained_semantics for claim_id in semantic.evidence_claim_ids
    }
    evidence_claims = [
        claim
        for claim in contract.evidence_claims
        if claim.id in referenced_claim_ids
        or claim.target.target_id in retained_targets.get(claim.target.target_kind, set())
    ]

    projected = contract.model_dump(mode="json")
    projected.update(
        {
            "action_lifecycles": [item.model_dump(mode="json") for item in action_lifecycles],
            "business_goals": [item.model_dump(mode="json") for item in goals],
            "conditions": [item.model_dump(mode="json") for item in conditions],
            "defaults": [item.model_dump(mode="json") for item in defaults],
            "error_handling": [item.model_dump(mode="json") for item in error_handling],
            "evidence_claims": [item.model_dump(mode="json") for item in evidence_claims],
            "input_bindings": [item.model_dump(mode="json") for item in bindings],
            "option_sources": [item.model_dump(mode="json") for item in option_sources],
            "related_data": [item.model_dump(mode="json") for item in related_data],
            "required_scenario_ids": required_scenario_ids,
            "result_consumption": [item.model_dump(mode="json") for item in result_consumption],
            "tool_routes": [item.model_dump(mode="json") for item in routes],
        }
    )
    try:
        selected_contract = DomainUsageContract.model_validate(projected)
    except ValidationError as exc:
        raise UsagePackageFormatError(
            "selected Usage route closure cannot be packaged safely",
            path=f"domain-usage-contracts/{contract.domain_id}",
        ) from exc
    if {item.id for item in selected_contract.business_goals} != selected_goal_ids or {
        item.id for item in selected_contract.tool_routes
    } != selected_route_ids:
        raise UsagePackageFormatError("selected Usage route closure is incomplete")
    return selected_contract


def _manifest_from_report(
    project_root: Path,
    *,
    verified_releases: Sequence[VerifiedUsageReleaseBundle],
    signer: UsagePackageSigner | None,
    max_member_bytes: int,
    max_total_bytes: int,
) -> tuple[UsagePackageManifest, dict[str, bytes]]:
    report = validate_usage_project(project_root)
    if not report.ok:
        raise UsagePackageFormatError(
            "Agent Usage project validation failed", path=str(project_root)
        )
    if report.project is None or report.acceptance is None or report.domain_index is None:
        raise UsagePackageFormatError("Agent Usage project validation produced no package baseline")

    payloads: dict[str, bytes] = {}
    domain_members: list[UsagePackageDomainMember] = []
    receipt_domains: list[UsageReleaseReceiptDomain] = []
    decisions_by_domain: dict[str, list[UsageDomainDecision]] = {}
    for decision in report.decisions.values():
        decisions_by_domain.setdefault(decision.domain_id, []).append(decision)

    bundles: dict[str, VerifiedUsageReleaseBundle] = {}
    for bundle in verified_releases:
        domain_id = bundle.release.domain_id
        if domain_id in bundles:
            raise UsagePackageTrustError("verified release bundles must be unique by domain")
        if not bundle.trusted:
            raise UsagePackageTrustError("published domains require a live verified release bundle")
        bundles[domain_id] = bundle
    published_domain_ids = {item.domain_id for item in report.domain_index.published_releases}
    if set(bundles) != published_domain_ids:
        raise UsagePackageTrustError("published domains require one exact verified release bundle")
    if published_domain_ids and signer is None:
        raise UsagePackageTrustError("published domains require an explicit package signer")

    for domain_number, published in enumerate(report.domain_index.published_releases):
        domain_id = published.domain_id
        source_contract = report.domain_contracts[domain_id]
        release = report.releases[published.usage_release_id]
        decision = max(decisions_by_domain[domain_id], key=lambda item: item.revision)
        bundle = bundles[domain_id]
        source_contract_digest = _canonical_digest(source_contract.model_dump(mode="json"))
        scenario_digests = {
            scenario_id: _canonical_digest(report.scenarios[scenario_id].model_dump(mode="json"))
            for scenario_id in release.scenario_ids
        }
        if (
            bundle.release != release
            or bundle.release_digest != _canonical_digest(release.model_dump(mode="json"))
            or bundle.contract_digest != source_contract_digest
            or bundle.contract_digest != release.contract_digest
            or dict(bundle.scenario_digests) != scenario_digests
            or bundle.pack_digest != release.pack_digest
            or bundle.decision_digest != decision.decision_digest
            or bundle.decision_digest != release.decision_digest
        ):
            raise UsagePackageTrustError(
                "verified release bundle does not exactly match the project release"
            )
        contract = _selected_contract_projection(source_contract, decision, release)
        prefix = f"domains/{domain_number:04d}"
        contract_path = f"{prefix}/contract.json"
        decision_path = f"{prefix}/decision.json"
        release_path = f"{prefix}/release.json"
        evidence_path = f"{prefix}/evidence.json"
        payloads[contract_path] = _canonical_json(
            contract.model_dump(mode="json"), description="Usage contract"
        )
        payloads[decision_path] = _canonical_json(
            decision.model_dump(mode="json"), description="Usage decision"
        )
        payloads[release_path] = _canonical_json(
            release.model_dump(mode="json"), description="Usage release"
        )

        scenario_members: list[UsagePackageScenarioMember] = []
        for scenario_number, scenario_id in enumerate(release.scenario_ids):
            scenario = report.scenarios[scenario_id]
            scenario_path = f"{prefix}/scenarios/{scenario_number:04d}.json"
            payloads[scenario_path] = _canonical_json(
                scenario.model_dump(mode="json"), description="Usage scenario"
            )
            scenario_members.append(
                UsagePackageScenarioMember(scenario_id=scenario_id, path=scenario_path)
            )

        evidence_refs = {
            (reference.source_id, reference.digest)
            for claim in contract.evidence_claims
            for reference in claim.evidence_refs
        }
        evidence_metadata = [
            {"digest": digest, "source_id": source_id}
            for source_id, digest in sorted(evidence_refs)
        ]
        payloads[evidence_path] = _canonical_json(
            evidence_metadata, description="Usage evidence metadata"
        )
        domain_members.append(
            UsagePackageDomainMember(
                domain_id=domain_id,
                usage_release_id=release.usage_release_id,
                contract=contract_path,
                decision=decision_path,
                release=release_path,
                scenarios=tuple(scenario_members),
                evidence=evidence_path,
            )
        )
        receipt_domains.append(
            UsageReleaseReceiptDomain(
                domain_id=domain_id,
                usage_release_id=release.usage_release_id,
                bundle_digest=bundle.bundle_digest,
                release_digest=bundle.release_digest,
                report_digests=dict(sorted(bundle.report_digests.items())),
                contract_digest=bundle.contract_digest,
                scenario_digests=dict(sorted(bundle.scenario_digests.items())),
                mcp_pack_digest=bundle.pack_digest,
                decision_digest=bundle.decision_digest,
                selected_closure_digest=_canonical_digest(contract.model_dump(mode="json")),
            )
        )

    identity = report.project.project
    baseline = report.domain_index
    manifest = UsagePackageManifest(
        format=USAGE_PACKAGE_FORMAT,
        format_version=USAGE_PACKAGE_FORMAT_VERSION,
        project_id=identity.id,
        project_version=identity.version,
        mcp_release_id=baseline.mcp_release_id,
        pack_digest=baseline.pack_digest,
        ir_digest=baseline.ir_digest,
        tool_schema_digest=baseline.tool_schema_digest,
        test_report_digest=baseline.test_report_digest,
        source_snapshot_digest=baseline.source_snapshot_digest,
        domains=tuple(domain_members),
    )
    payloads["manifest.json"] = _canonical_json(manifest.to_dict(), description="manifest")
    if manifest.domains:
        assert signer is not None
        unsigned_receipt = UsageReleaseReceipt(
            schema_version="2",
            algorithm=_SIGNING_ALGORITHM,
            key_id=signer.key_id,
            manifest_logical_digest=_canonical_digest(manifest.to_dict()),
            domains=tuple(receipt_domains),
            signature="pending",
        )
        signature = signer._sign(
            _canonical_json(unsigned_receipt.signed_dict(), description="Usage release receipt")[
                :-1
            ]
        )
        receipt = UsageReleaseReceipt(
            schema_version=unsigned_receipt.schema_version,
            algorithm=unsigned_receipt.algorithm,
            key_id=unsigned_receipt.key_id,
            manifest_logical_digest=unsigned_receipt.manifest_logical_digest,
            domains=unsigned_receipt.domains,
            signature=signature,
        )
        payloads[_RECEIPT_PATH] = _canonical_json(
            receipt.to_dict(), description="Usage release receipt"
        )
    _ensure_payload_limits(
        payloads, max_member_bytes=max_member_bytes, max_total_bytes=max_total_bytes
    )
    records = tuple(_record(path, payloads[path]) for path in sorted(payloads))
    payloads["usage.lock"] = _canonical_json(
        {
            "algorithm": "sha256",
            "files": [record.to_dict() for record in records],
            "format_version": USAGE_PACKAGE_FORMAT_VERSION,
        },
        description="Usage package lock",
    )
    _ensure_payload_limits(
        payloads, max_member_bytes=max_member_bytes, max_total_bytes=max_total_bytes
    )
    return manifest, payloads


def _validate_package_path(path: Path) -> None:
    if path.suffix.lower() != USAGE_PACKAGE_SUFFIX:
        raise UsagePackagePathError(
            f"Agent Usage package must use the {USAGE_PACKAGE_SUFFIX} suffix", path=str(path)
        )


def _reject_symlinked_parent(path: Path) -> None:
    parent = path.parent
    normalized_parent = Path(os.path.abspath(parent))
    try:
        resolved_parent = parent.resolve(strict=False)
    except OSError as exc:
        raise UsagePackageSymlinkError(
            "cannot resolve Agent Usage package output parent", path=str(parent)
        ) from exc
    if resolved_parent != normalized_parent:
        raise UsagePackageSymlinkError(
            "Agent Usage package output parent cannot contain symbolic links", path=str(parent)
        )


def build_usage_package(
    project_root: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    verified_releases: Sequence[VerifiedUsageReleaseBundle] = (),
    signer: UsagePackageSigner | None = None,
    max_member_bytes: int = USAGE_PACKAGE_MAX_MEMBER_BYTES,
    max_total_bytes: int = USAGE_PACKAGE_MAX_TOTAL_BYTES,
) -> UsagePackageBuildResult:
    """Build a byte-reproducible, receipt-signed package of live releases."""

    _validate_limits(max_member_bytes, max_total_bytes)
    root = Path(project_root)
    destination = Path(output_path)
    _validate_package_path(destination)
    if _is_path_link(root):
        raise UsagePackageSymlinkError("Agent Usage project root cannot be a symbolic link")
    if _is_path_link(destination):
        raise UsagePackageSymlinkError(
            "Agent Usage package output cannot be a symbolic link", path=str(destination)
        )
    if ".." in destination.parts:
        raise UsagePackagePathError("Agent Usage package output path must be normalized")
    _reject_symlinked_parent(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlinked_parent(destination)

    manifest, payloads = _manifest_from_report(
        root,
        verified_releases=tuple(verified_releases),
        signer=signer,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(payloads):
                archive.writestr(_zip_info(path), payloads[path])
        if _is_path_link(destination):
            raise UsagePackageSymlinkError(
                "Agent Usage package output became a symbolic link", path=str(destination)
            )
        os.replace(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return UsagePackageBuildResult(
        path=destination,
        sha256=_file_sha256(destination),
        manifest=manifest,
    )


def _parse_json(contents: bytes, *, path: str) -> object:
    try:
        return json.loads(
            contents.decode("utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise UsagePackageFormatError("package member must be valid UTF-8 JSON", path=path) from exc


def _required_object(value: object, keys: set[str], *, path: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise UsagePackageFormatError("package member must be a JSON object", path=path)
    if set(value) != keys:
        raise UsagePackageFormatError("package member has unknown or missing fields", path=path)
    return value


def _required_text(value: object, *, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise UsagePackageFormatError("package field must be a non-empty string", path=path)
    return value


def _required_digest(value: object, *, path: str) -> str:
    text = _required_text(value, path=path)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise UsagePackageFormatError("package field must be a sha256 digest", path=path)
    return text


def _parse_manifest(contents: bytes) -> UsagePackageManifest:
    value = _required_object(
        _parse_json(contents, path="manifest.json"),
        {"domains", "format", "format_version", "mcp_release", "project"},
        path="manifest.json",
    )
    if (
        value["format"] != USAGE_PACKAGE_FORMAT
        or value["format_version"] != USAGE_PACKAGE_FORMAT_VERSION
        or isinstance(value["format_version"], bool)
    ):
        raise UsagePackageFormatError(
            "unsupported Agent Usage package format", path="manifest.json"
        )
    project = _required_object(value["project"], {"id", "version"}, path="manifest.json")
    baseline = _required_object(
        value["mcp_release"],
        {
            "ir_digest",
            "pack_digest",
            "release_id",
            "source_snapshot_digest",
            "test_report_digest",
            "tool_schema_digest",
        },
        path="manifest.json",
    )
    raw_domains = value["domains"]
    if not isinstance(raw_domains, list):
        raise UsagePackageFormatError("manifest domains must be an array", path="manifest.json")
    domains: list[UsagePackageDomainMember] = []
    for index, raw_domain in enumerate(raw_domains):
        domain = _required_object(
            raw_domain,
            {
                "contract",
                "decision",
                "domain_id",
                "evidence",
                "release",
                "scenarios",
                "usage_release_id",
            },
            path="manifest.json",
        )
        expected_prefix = f"domains/{index:04d}"
        raw_scenarios = domain["scenarios"]
        if not isinstance(raw_scenarios, list):
            raise UsagePackageFormatError(
                "manifest scenarios must be an array", path="manifest.json"
            )
        scenarios: list[UsagePackageScenarioMember] = []
        for scenario_index, raw_scenario in enumerate(raw_scenarios):
            scenario = _required_object(raw_scenario, {"path", "scenario_id"}, path="manifest.json")
            scenario_path = _required_text(scenario["path"], path="manifest.json")
            if scenario_path != f"{expected_prefix}/scenarios/{scenario_index:04d}.json":
                raise UsagePackageFormatError(
                    "manifest scenario paths must use canonical ordering", path="manifest.json"
                )
            scenarios.append(
                UsagePackageScenarioMember(
                    scenario_id=_required_text(scenario["scenario_id"], path="manifest.json"),
                    path=scenario_path,
                )
            )
        paths = {
            name: _required_text(domain[name], path="manifest.json")
            for name in ("contract", "decision", "evidence", "release")
        }
        for name, member_path in paths.items():
            if member_path != f"{expected_prefix}/{name}.json":
                raise UsagePackageFormatError(
                    "manifest domain paths must use canonical ordering", path="manifest.json"
                )
        domains.append(
            UsagePackageDomainMember(
                domain_id=_required_text(domain["domain_id"], path="manifest.json"),
                usage_release_id=_required_text(domain["usage_release_id"], path="manifest.json"),
                contract=paths["contract"],
                decision=paths["decision"],
                evidence=paths["evidence"],
                release=paths["release"],
                scenarios=tuple(scenarios),
            )
        )
    domain_ids = [item.domain_id for item in domains]
    if domain_ids != sorted(set(domain_ids)):
        raise UsagePackageFormatError("manifest domains must be sorted and unique")
    return UsagePackageManifest(
        format=USAGE_PACKAGE_FORMAT,
        format_version=USAGE_PACKAGE_FORMAT_VERSION,
        project_id=_required_text(project["id"], path="manifest.json"),
        project_version=_required_text(project["version"], path="manifest.json"),
        mcp_release_id=_required_text(baseline["release_id"], path="manifest.json"),
        pack_digest=_required_digest(baseline["pack_digest"], path="manifest.json"),
        ir_digest=_required_digest(baseline["ir_digest"], path="manifest.json"),
        tool_schema_digest=_required_digest(baseline["tool_schema_digest"], path="manifest.json"),
        test_report_digest=_required_digest(baseline["test_report_digest"], path="manifest.json"),
        source_snapshot_digest=_required_digest(
            baseline["source_snapshot_digest"], path="manifest.json"
        ),
        domains=tuple(domains),
    )


def _parse_lock(contents: bytes) -> tuple[UsagePackageFileRecord, ...]:
    value = _required_object(
        _parse_json(contents, path="usage.lock"),
        {"algorithm", "files", "format_version"},
        path="usage.lock",
    )
    if (
        value["algorithm"] != "sha256"
        or value["format_version"] != USAGE_PACKAGE_FORMAT_VERSION
        or isinstance(value["format_version"], bool)
    ):
        raise UsagePackageFormatError("unsupported Usage lock format", path="usage.lock")
    raw_files = value["files"]
    if not isinstance(raw_files, list):
        raise UsagePackageFormatError("Usage lock files must be an array", path="usage.lock")
    records: list[UsagePackageFileRecord] = []
    seen: set[str] = set()
    for raw_record in raw_files:
        record = _required_object(raw_record, {"path", "sha256", "size"}, path="usage.lock")
        path = _required_text(record["path"], path="usage.lock")
        _validate_member_path(path)
        if path == "usage.lock" or not _is_allowed_member(path):
            raise UsagePackageUnknownEntryError("Usage lock lists an unknown member", path=path)
        if path in seen:
            raise UsagePackageDuplicateEntryError("Usage lock repeats a member", path=path)
        digest = record["sha256"]
        size = record["size"]
        if not isinstance(digest, str) or _LOCK_SHA256_PATTERN.fullmatch(digest) is None:
            raise UsagePackageFormatError("Usage lock digest must be lowercase SHA-256", path=path)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise UsagePackageFormatError("Usage lock size must be non-negative", path=path)
        seen.add(path)
        records.append(UsagePackageFileRecord(path=path, sha256=digest, size=size))
    if [item.path for item in records] != sorted(item.path for item in records):
        raise UsagePackageFormatError("Usage lock records must use stable ordering")
    return tuple(records)


def _parse_digest_map(value: object, *, path: str) -> Mapping[str, str]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise UsagePackageFormatError("receipt digest map must be an object", path=path)
    if list(value) != sorted(value):
        raise UsagePackageFormatError("receipt digest map must use stable ordering", path=path)
    return MappingProxyType(
        {key: _required_digest(digest, path=path) for key, digest in value.items()}
    )


def _parse_receipt(contents: bytes) -> UsageReleaseReceipt:
    value = _required_object(
        _parse_json(contents, path=_RECEIPT_PATH),
        {
            "algorithm",
            "domains",
            "key_id",
            "manifest_logical_digest",
            "schema_version",
            "signature",
        },
        path=_RECEIPT_PATH,
    )
    if value["schema_version"] != "2" or value["algorithm"] != _SIGNING_ALGORITHM:
        raise UsagePackageFormatError("unsupported Usage release receipt", path=_RECEIPT_PATH)
    key_id = _required_digest(value["key_id"], path=_RECEIPT_PATH)
    signature = _required_text(value["signature"], path=_RECEIPT_PATH)
    if _LOCK_SHA256_PATTERN.fullmatch(signature) is None:
        raise UsagePackageFormatError("receipt signature must be lowercase HMAC-SHA256")
    raw_domains = value["domains"]
    if not isinstance(raw_domains, list) or not raw_domains:
        raise UsagePackageFormatError("signed receipt must contain released domains")
    domains: list[UsageReleaseReceiptDomain] = []
    for raw_domain in raw_domains:
        domain = _required_object(
            raw_domain,
            {
                "bundle_digest",
                "contract_digest",
                "decision_digest",
                "domain_id",
                "mcp_pack_digest",
                "release_digest",
                "report_digests",
                "scenario_digests",
                "selected_closure_digest",
                "usage_release_id",
            },
            path=_RECEIPT_PATH,
        )
        domains.append(
            UsageReleaseReceiptDomain(
                domain_id=_required_text(domain["domain_id"], path=_RECEIPT_PATH),
                usage_release_id=_required_text(domain["usage_release_id"], path=_RECEIPT_PATH),
                bundle_digest=_required_digest(domain["bundle_digest"], path=_RECEIPT_PATH),
                release_digest=_required_digest(domain["release_digest"], path=_RECEIPT_PATH),
                report_digests=_parse_digest_map(domain["report_digests"], path=_RECEIPT_PATH),
                contract_digest=_required_digest(domain["contract_digest"], path=_RECEIPT_PATH),
                scenario_digests=_parse_digest_map(domain["scenario_digests"], path=_RECEIPT_PATH),
                mcp_pack_digest=_required_digest(domain["mcp_pack_digest"], path=_RECEIPT_PATH),
                decision_digest=_required_digest(domain["decision_digest"], path=_RECEIPT_PATH),
                selected_closure_digest=_required_digest(
                    domain["selected_closure_digest"], path=_RECEIPT_PATH
                ),
            )
        )
    if [item.domain_id for item in domains] != sorted({item.domain_id for item in domains}):
        raise UsagePackageFormatError("receipt domains must be sorted and unique")
    return UsageReleaseReceipt(
        schema_version="2",
        algorithm=_SIGNING_ALGORITHM,
        key_id=key_id,
        manifest_logical_digest=_required_digest(
            value["manifest_logical_digest"], path=_RECEIPT_PATH
        ),
        domains=tuple(domains),
        signature=signature,
    )


def _read_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, *, max_member_bytes: int
) -> bytes:
    if info.flag_bits & 1:
        raise UsagePackageFormatError("encrypted package members are forbidden", path=info.filename)
    if info.file_size > max_member_bytes:
        raise UsagePackageFileTooLargeError(
            f"Agent Usage package member exceeds {max_member_bytes} bytes", path=info.filename
        )
    try:
        with archive.open(info) as source:
            contents = source.read(max_member_bytes + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise UsagePackageFormatError("cannot read Agent Usage package member") from exc
    if len(contents) > max_member_bytes:
        raise UsagePackageFileTooLargeError(
            f"Agent Usage package member exceeds {max_member_bytes} bytes", path=info.filename
        )
    return contents


def _validate_semantics(
    manifest: UsagePackageManifest, members: Mapping[str, bytes]
) -> tuple[
    dict[str, DomainUsageContract],
    dict[str, UsageDomainDecision],
    dict[str, AgentUsageRelease],
    dict[str, UsageScenario],
    dict[str, tuple[tuple[str, str], ...]],
]:
    contracts: dict[str, DomainUsageContract] = {}
    decisions: dict[str, UsageDomainDecision] = {}
    releases: dict[str, AgentUsageRelease] = {}
    scenarios: dict[str, UsageScenario] = {}
    evidence: dict[str, tuple[tuple[str, str], ...]] = {}
    expected_members = {"manifest.json", "usage.lock"}
    if manifest.domains:
        expected_members.add(_RECEIPT_PATH)
    try:
        for domain in manifest.domains:
            expected_members.update(
                {domain.contract, domain.decision, domain.evidence, domain.release}
            )
            expected_members.update(item.path for item in domain.scenarios)
            contract = DomainUsageContract.model_validate(
                _parse_json(members[domain.contract], path=domain.contract)
            )
            decision = UsageDomainDecision.model_validate(
                _parse_json(members[domain.decision], path=domain.decision)
            )
            release = AgentUsageRelease.model_validate(
                _parse_json(members[domain.release], path=domain.release)
            )
            for member_path, document, description in (
                (domain.contract, contract, "Usage contract"),
                (domain.decision, decision, "Usage decision"),
                (domain.release, release, "Usage release"),
            ):
                if members[member_path] != _canonical_json(
                    document.model_dump(mode="json"), description=description
                ):
                    raise UsagePackageFormatError(
                        "package Usage document must use canonical JSON", path=member_path
                    )
            if (
                contract.domain_id != domain.domain_id
                or decision.domain_id != domain.domain_id
                or release.domain_id != domain.domain_id
                or release.usage_release_id != domain.usage_release_id
                or release.release_status != "released"
            ):
                raise UsagePackageFormatError("manifest domain does not match released documents")
            baseline = (
                manifest.pack_digest,
                manifest.ir_digest,
                manifest.tool_schema_digest,
                manifest.test_report_digest,
                manifest.source_snapshot_digest,
            )
            if (
                (
                    contract.pack_digest,
                    contract.ir_digest,
                    contract.tool_schema_digest,
                    contract.test_report_digest,
                    contract.source_snapshot_digest,
                )
                != baseline
                or (
                    release.pack_digest,
                    release.ir_digest,
                    release.tool_schema_digest,
                    release.test_report_digest,
                    release.source_snapshot_digest,
                )
                != baseline
                or release.mcp_release_id != manifest.mcp_release_id
            ):
                raise UsagePackageFormatError("released documents do not match package baseline")
            if (
                decision.contract_digest != release.contract_digest
                or release.decision_digest != decision.decision_digest
            ):
                raise UsagePackageFormatError(
                    "released documents have stale source contract bindings"
                )
            if (
                set(release.business_goal_ids) != set(decision.business_goal_ids)
                or set(release.route_ids) != set(decision.included_route_ids)
                or {item.id for item in contract.business_goals} != set(decision.business_goal_ids)
                or {item.id for item in contract.tool_routes} != set(decision.included_route_ids)
                or {step.capability_id for route in contract.tool_routes for step in route.steps}
                != set(release.capability_ids)
            ):
                raise UsagePackageFormatError(
                    "released documents are not the exact selected route closure"
                )
            domain_scenario_ids: list[str] = []
            route_ids = set(release.route_ids)
            for scenario_member in domain.scenarios:
                scenario = UsageScenario.model_validate(
                    _parse_json(members[scenario_member.path], path=scenario_member.path)
                )
                if members[scenario_member.path] != _canonical_json(
                    scenario.model_dump(mode="json"), description="Usage scenario"
                ):
                    raise UsagePackageFormatError(
                        "package Usage scenario must use canonical JSON",
                        path=scenario_member.path,
                    )
                if (
                    scenario.scenario_id != scenario_member.scenario_id
                    or scenario.domain_id != domain.domain_id
                    or scenario.route_id not in route_ids
                    or scenario.scenario_id in scenarios
                ):
                    raise UsagePackageFormatError("package scenario does not match its release")
                scenarios[scenario.scenario_id] = scenario
                domain_scenario_ids.append(scenario.scenario_id)
            if domain_scenario_ids != release.scenario_ids:
                raise UsagePackageFormatError("package scenarios are not the exact release set")

            raw_evidence = _parse_json(members[domain.evidence], path=domain.evidence)
            if not isinstance(raw_evidence, list):
                raise UsagePackageFormatError("evidence metadata must be an array")
            evidence_records: list[tuple[str, str]] = []
            for raw_record in raw_evidence:
                record = _required_object(raw_record, {"digest", "source_id"}, path=domain.evidence)
                source_id = _required_text(record["source_id"], path=domain.evidence)
                digest = _required_digest(record["digest"], path=domain.evidence)
                evidence_records.append((source_id, digest))
            if evidence_records != sorted(set(evidence_records)):
                raise UsagePackageFormatError("evidence metadata must be sorted and unique")
            required_evidence = sorted(
                {
                    (reference.source_id, reference.digest)
                    for claim in contract.evidence_claims
                    for reference in claim.evidence_refs
                }
            )
            if evidence_records != required_evidence:
                raise UsagePackageFormatError("evidence metadata is not the exact contract set")
            if members[domain.evidence] != _canonical_json(
                [
                    {"digest": digest, "source_id": source_id}
                    for source_id, digest in evidence_records
                ],
                description="Usage evidence metadata",
            ):
                raise UsagePackageFormatError(
                    "evidence metadata must use canonical JSON", path=domain.evidence
                )
            contracts[domain.domain_id] = contract
            decisions[domain.domain_id] = decision
            releases[domain.domain_id] = release
            evidence[domain.domain_id] = tuple(evidence_records)
    except KeyError as exc:
        raise UsagePackageFormatError("manifest references a missing package member") from exc
    except ValidationError as exc:
        raise UsagePackageFormatError("package Usage document violates its schema") from exc
    if set(members) != expected_members:
        raise UsagePackageUnknownEntryError("package members do not match the manifest")
    return contracts, decisions, releases, scenarios, evidence


def _required_report_digest_keys(release: AgentUsageRelease) -> set[str]:
    verification = release.verification
    keys = {
        axis
        for axis in (
            "source_usage_traced",
            "usage_contract_verified",
            "headless_agent_verified",
            "real_mcp_verified",
            "user_accepted",
        )
        if getattr(verification, axis)
    }
    if verification.host_adapter_verified:
        keys.update(f"host_adapter_verified:{item}" for item in release.host_adapters)
    return keys


def _verify_release_receipt(
    *,
    manifest: UsagePackageManifest,
    members: Mapping[str, bytes],
    contracts: Mapping[str, DomainUsageContract],
    releases: Mapping[str, AgentUsageRelease],
    scenarios: Mapping[str, UsageScenario],
    trust_store: UsagePackageTrustStore | None,
) -> UsageReleaseReceipt | None:
    if not manifest.domains:
        if _RECEIPT_PATH in members:
            raise UsagePackageTrustError("unreleased Usage package cannot carry a receipt")
        return None
    if trust_store is None:
        raise UsagePackageTrustError(
            "released Usage package verification requires an explicit trust store"
        )
    receipt = _parse_receipt(members[_RECEIPT_PATH])
    if members[_RECEIPT_PATH] != _canonical_json(
        receipt.to_dict(), description="Usage release receipt"
    ):
        raise UsagePackageFormatError(
            "Usage release receipt must use canonical JSON", path=_RECEIPT_PATH
        )
    if receipt.manifest_logical_digest != _canonical_digest(manifest.to_dict()):
        raise UsagePackageTrustError("receipt does not bind the exact package manifest")
    receipt_by_domain = {item.domain_id: item for item in receipt.domains}
    if tuple(receipt_by_domain) != manifest.released_domain_ids:
        raise UsagePackageTrustError("receipt domains do not match the package manifest")
    for domain in manifest.domains:
        item = receipt_by_domain[domain.domain_id]
        release = releases[domain.domain_id]
        contract = contracts[domain.domain_id]
        scenario_digests = {
            member.scenario_id: _canonical_digest(
                scenarios[member.scenario_id].model_dump(mode="json")
            )
            for member in domain.scenarios
        }
        release_digest = _canonical_digest(release.model_dump(mode="json"))
        if (
            item.usage_release_id != domain.usage_release_id
            or item.release_digest != release_digest
            or item.contract_digest != release.contract_digest
            or dict(item.scenario_digests) != scenario_digests
            or item.mcp_pack_digest != manifest.pack_digest
            or item.mcp_pack_digest != release.pack_digest
            or item.decision_digest != release.decision_digest
            or item.selected_closure_digest != _canonical_digest(contract.model_dump(mode="json"))
            or set(item.report_digests) != _required_report_digest_keys(release)
        ):
            raise UsagePackageTrustError("receipt does not bind the exact verified release closure")
        bundle_content = {
            "schema_version": "2",
            "release": release.model_dump(mode="json"),
            "report_digests": dict(item.report_digests),
            "contract_digest": item.contract_digest,
            "scenario_digests": dict(item.scenario_digests),
            "pack_digest": item.mcp_pack_digest,
            "decision_digest": item.decision_digest,
            "release_digest": item.release_digest,
        }
        if item.bundle_digest != _canonical_digest(bundle_content):
            raise UsagePackageTrustError("receipt verified release bundle digest is stale")
    signed_contents = _canonical_json(receipt.signed_dict(), description="Usage release receipt")[
        :-1
    ]
    if not trust_store._verify(receipt.key_id, signed_contents, receipt.signature):
        raise UsagePackageTrustError("Usage release receipt signature is not trusted")
    return receipt


def _verify_usage_package_impl(
    package_path: str | os.PathLike[str],
    *,
    trust_store: UsagePackageTrustStore | None = None,
    max_member_bytes: int = USAGE_PACKAGE_MAX_MEMBER_BYTES,
    max_total_bytes: int = USAGE_PACKAGE_MAX_TOTAL_BYTES,
) -> VerifiedUsagePackage:
    """Verify archive closure and authenticate released domains via a trust root."""

    _validate_limits(max_member_bytes, max_total_bytes)
    path = Path(package_path)
    _validate_package_path(path)
    if _is_path_link(path):
        raise UsagePackageSymlinkError("Agent Usage package cannot be a symbolic link")
    if not path.is_file():
        raise UsagePackageFormatError("Agent Usage package is not a regular file")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            for info in infos:
                _validate_member_path(info.orig_filename)
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                duplicate = next(name for name in names if names.count(name) > 1)
                raise UsagePackageDuplicateEntryError(
                    "Agent Usage package repeats a member", path=duplicate
                )
            for info in infos:
                member_mode = info.external_attr >> 16
                member_type = stat.S_IFMT(member_mode)
                if member_type == stat.S_IFLNK:
                    raise UsagePackageSymlinkError(
                        "symbolic links are forbidden in Agent Usage packages",
                        path=info.filename,
                    )
                if (
                    info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != FIXED_ZIP_TIME
                    or info.create_system != 3
                    or member_mode != stat.S_IFREG | 0o644
                ):
                    raise UsagePackageFormatError(
                        "Agent Usage package member metadata is not canonical",
                        path=info.filename,
                    )
                if info.is_dir() or member_type not in {0, stat.S_IFREG}:
                    raise UsagePackageUnknownEntryError(
                        "non-regular Agent Usage package members are forbidden",
                        path=info.filename,
                    )
                if not _is_allowed_member(info.filename):
                    raise UsagePackageUnknownEntryError(
                        "unknown Agent Usage package member", path=info.filename
                    )
            if names != sorted(names):
                raise UsagePackageFormatError(
                    "Agent Usage package members must use stable ordering"
                )
            total = 0
            members: dict[str, bytes] = {}
            for info in infos:
                contents = _read_member(archive, info, max_member_bytes=max_member_bytes)
                total += len(contents)
                if total > max_total_bytes:
                    raise UsagePackageFileTooLargeError(
                        f"Agent Usage package total exceeds {max_total_bytes} bytes"
                    )
                members[info.filename] = contents
    except UsagePackageError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise UsagePackageFormatError("Agent Usage package is not a readable ZIP archive") from exc

    missing = sorted(_REQUIRED_ENTRIES - set(members))
    if missing:
        raise UsagePackageFormatError(
            f"Agent Usage package is missing required members: {', '.join(missing)}"
        )
    manifest = _parse_manifest(members["manifest.json"])
    if members["manifest.json"] != _canonical_json(manifest.to_dict(), description="manifest"):
        raise UsagePackageFormatError(
            "Agent Usage package manifest must use canonical JSON", path="manifest.json"
        )
    records = _parse_lock(members["usage.lock"])
    if members["usage.lock"] != _canonical_json(
        {
            "algorithm": "sha256",
            "files": [record.to_dict() for record in records],
            "format_version": USAGE_PACKAGE_FORMAT_VERSION,
        },
        description="Usage package lock",
    ):
        raise UsagePackageFormatError(
            "Agent Usage package lock must use canonical JSON", path="usage.lock"
        )
    expected_paths = set(members) - {"usage.lock"}
    if {record.path for record in records} != expected_paths:
        raise UsagePackageChecksumMismatchError(
            "Usage lock does not cover exactly every payload member"
        )
    for record in records:
        contents = members[record.path]
        if record.size != len(contents) or record.sha256 != _sha256(contents):
            raise UsagePackageChecksumMismatchError(
                "Agent Usage package member does not match Usage lock", path=record.path
            )
    contracts, decisions, releases, scenarios, evidence = _validate_semantics(manifest, members)
    receipt = _verify_release_receipt(
        manifest=manifest,
        members=members,
        contracts=contracts,
        releases=releases,
        scenarios=scenarios,
        trust_store=trust_store,
    )
    package = VerifiedUsagePackage(
        path=path,
        sha256=_file_sha256(path),
        manifest=manifest,
        files=records,
        contracts=contracts,
        decisions=decisions,
        releases=releases,
        scenarios=scenarios,
        evidence=evidence,
        release_receipt=receipt,
    )
    return package


def _make_verified_package_api() -> tuple[_VerifiedPackageVerifier, _VerifiedPackageChecker]:
    live: dict[int, tuple[weakref.ReferenceType[VerifiedUsagePackage], str]] = {}

    def register(value: VerifiedUsagePackage) -> None:
        identity = id(value)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        live[identity] = (weakref.ref(value, discard), _verified_package_fingerprint(value))

    def is_live(value: VerifiedUsagePackage) -> bool:
        record = live.get(id(value))
        if record is None or record[0]() is not value:
            return False
        try:
            return (
                not _is_path_link(value.path)
                and value.path.is_file()
                and _file_sha256(value.path) == value.sha256
                and record[1] == _verified_package_fingerprint(value)
            )
        except (OSError, TypeError, ValueError, ValidationError):
            return False

    def verify(
        package_path: str | os.PathLike[str],
        *,
        trust_store: UsagePackageTrustStore | None = None,
        max_member_bytes: int = USAGE_PACKAGE_MAX_MEMBER_BYTES,
        max_total_bytes: int = USAGE_PACKAGE_MAX_TOTAL_BYTES,
    ) -> VerifiedUsagePackage:
        package = _verify_usage_package_impl(
            package_path,
            trust_store=trust_store,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
        if package.release_receipt is not None:
            register(package)
        return package

    return verify, is_live


verify_usage_package, _is_live_verified_package = _make_verified_package_api()
del _make_verified_package_api


__all__ = [
    "USAGE_PACKAGE_FORMAT",
    "USAGE_PACKAGE_FORMAT_VERSION",
    "USAGE_PACKAGE_MAX_MEMBER_BYTES",
    "USAGE_PACKAGE_MAX_TOTAL_BYTES",
    "USAGE_PACKAGE_SUFFIX",
    "UsagePackageBuildResult",
    "UsagePackageChecksumMismatchError",
    "UsagePackageDomainMember",
    "UsagePackageDuplicateEntryError",
    "UsagePackageError",
    "UsagePackageFileRecord",
    "UsagePackageFileTooLargeError",
    "UsagePackageFormatError",
    "UsagePackageManifest",
    "UsagePackagePathError",
    "UsagePackageScenarioMember",
    "UsagePackageSigner",
    "UsagePackageSymlinkError",
    "UsagePackageTrustError",
    "UsagePackageTrustStore",
    "UsagePackageUnknownEntryError",
    "UsagePackageVerification",
    "UsageReleaseReceipt",
    "UsageReleaseReceiptDomain",
    "VerifiedUsagePackage",
    "build_usage_package",
    "verify_usage_package",
]
