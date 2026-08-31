"""Immutable attestation checks for an accepted MCP release baseline."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import weakref
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

import yaml
from pydantic import ValidationError

from acc_core.domains import DomainMap
from acc_core.io import is_path_link
from acc_core.packaging import CapabilityPackError, verify_pack
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage.models import McpReleaseAcceptance

_MAX_PACK_BYTES = 256 * 1024 * 1024
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_SHA256 = frozenset("0123456789abcdef")
_TOOL_FIELDS = frozenset({"name", "inputSchema", "outputSchema"})
_RUNTIME_INFO_FIELDS = frozenset(
    {
        "pack_sha256",
        "project_id",
        "project_version",
        "interaction_sha256",
        "tool_schema_sha256",
        "transport",
    }
)


class _AcceptanceError(Exception):
    code: ClassVar[str]


class _ArtifactInvalid(_AcceptanceError):
    code = "ACC_USAGE_ARTIFACT_INVALID"


class _ToolSnapshotInvalid(_AcceptanceError):
    code = "ACC_USAGE_TOOL_SNAPSHOT_INVALID"


class _DigestMismatch(_AcceptanceError):
    code = "ACC_USAGE_DIGEST_MISMATCH"


class _ReleaseMismatch(_AcceptanceError):
    code = "ACC_USAGE_RELEASE_MISMATCH"


@dataclass(frozen=True, slots=True, weakref_slot=True)
class McpReleaseAcceptanceVerification:
    """Secret-free result of verifying one immutable MCP release snapshot."""

    ok: bool
    code: str
    message: str
    runtime_attested: bool = False
    accepted_domain_ids: tuple[str, ...] = ()
    compiled_ir: Mapping[str, Any] | None = None
    tool_snapshot: Mapping[str, Any] | None = None

    @property
    def trusted(self) -> bool:
        return _is_live_acceptance(self)


def _acceptance_fingerprint(value: McpReleaseAcceptanceVerification) -> str:
    payload = {
        "accepted_domain_ids": value.accepted_domain_ids,
        "code": value.code,
        "compiled_ir": value.compiled_ir,
        "message": value.message,
        "ok": value.ok,
        "runtime_attested": value.runtime_attested,
        "tool_snapshot": value.tool_snapshot,
    }
    return hashlib.sha256(canonical_json_bytes(_fingerprint_value(payload))).hexdigest()


def _fingerprint_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _fingerprint_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_fingerprint_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class _FileFingerprint:
    path: Path
    device: int
    inode: int
    size: int
    modified_ns: int


def _is_bare_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and not (set(value) - _SHA256)


def _prefixed_sha256(contents: bytes) -> str:
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _read_regular_snapshot(
    path_value: str | os.PathLike[str], *, max_bytes: int
) -> tuple[bytes, _FileFingerprint]:
    path = Path(path_value)
    if is_path_link(path):
        raise _ArtifactInvalid
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _ArtifactInvalid from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise _ArtifactInvalid
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(contents) > max_bytes
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise _ArtifactInvalid
    except OSError:
        raise _ArtifactInvalid from None
    finally:
        os.close(descriptor)
    try:
        current = path.stat(follow_symlinks=False)
    except OSError:
        raise _ArtifactInvalid from None
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != after.st_dev
        or current.st_ino != after.st_ino
        or current.st_size != after.st_size
        or current.st_mtime_ns != after.st_mtime_ns
    ):
        raise _ArtifactInvalid
    return contents, _FileFingerprint(
        path=path,
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        modified_ns=after.st_mtime_ns,
    )


def _require_unchanged(fingerprint: _FileFingerprint) -> None:
    try:
        current = fingerprint.path.stat(follow_symlinks=False)
    except OSError:
        raise _ArtifactInvalid from None
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != fingerprint.device
        or current.st_ino != fingerprint.inode
        or current.st_size != fingerprint.size
        or current.st_mtime_ns != fingerprint.modified_ns
    ):
        raise _ArtifactInvalid


def _json_object(contents: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            contents.decode("utf-8"),
            parse_constant=lambda _constant: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _ArtifactInvalid from None
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _ArtifactInvalid
    return value


def _pack_payloads(
    pack_bytes: bytes,
) -> tuple[dict[str, Any], DomainMap, str, str, str, str]:
    with tempfile.TemporaryDirectory(prefix="acc-usage-acceptance-") as directory:
        snapshot = Path(directory) / "release.accpkg"
        snapshot.write_bytes(pack_bytes)
        try:
            verification = verify_pack(snapshot)
        except CapabilityPackError:
            raise _ArtifactInvalid from None
    if verification.sha256 != hashlib.sha256(pack_bytes).hexdigest():
        raise _ArtifactInvalid
    records = {record.path: record for record in verification.files}
    if "compiled/ir.json" not in records or "domain-map.yaml" not in records:
        raise _ArtifactInvalid
    try:
        with zipfile.ZipFile(io.BytesIO(pack_bytes)) as archive:
            ir_bytes = archive.read("compiled/ir.json")
            domain_bytes = archive.read("domain-map.yaml")
    except (KeyError, RuntimeError, zipfile.BadZipFile):
        raise _ArtifactInvalid from None
    ir_record = records["compiled/ir.json"]
    domain_record = records["domain-map.yaml"]
    if (
        len(ir_bytes) != ir_record.size
        or hashlib.sha256(ir_bytes).hexdigest() != ir_record.sha256
        or len(domain_bytes) != domain_record.size
        or hashlib.sha256(domain_bytes).hexdigest() != domain_record.sha256
    ):
        raise _ArtifactInvalid
    ir = _json_object(ir_bytes)
    try:
        domain_value = yaml.safe_load(domain_bytes.decode("utf-8"))
        domain_map = DomainMap.model_validate(domain_value)
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError):
        raise _ArtifactInvalid from None
    return (
        ir,
        domain_map,
        _prefixed_sha256(ir_bytes),
        verification.sha256,
        verification.manifest.project_id,
        verification.manifest.project_version,
    )


def _tool_payload(tool_snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    if set(tool_snapshot) != {"tools"}:
        raise _ToolSnapshotInvalid
    values = tool_snapshot.get("tools")
    if not isinstance(values, list):
        raise _ToolSnapshotInvalid
    schemas: list[dict[str, object]] = []
    names: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping) or set(value) != _TOOL_FIELDS:
            raise _ToolSnapshotInvalid
        name = value.get("name")
        input_schema = value.get("inputSchema")
        output_schema = value.get("outputSchema")
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or name in names
            or not isinstance(input_schema, Mapping)
            or not isinstance(output_schema, Mapping)
        ):
            raise _ToolSnapshotInvalid
        try:
            schema: dict[str, object] = {
                "name": name,
                "input_schema": dict(input_schema),
                "output_schema": dict(output_schema),
            }
            canonical_json_bytes(schema)
        except (TypeError, ValueError):
            raise _ToolSnapshotInvalid from None
        names.add(name)
        schemas.append(schema)
    schemas.sort(key=lambda item: str(item["name"]))
    return schemas


def listed_tool_snapshot_sha256(tool_snapshot: Mapping[str, object]) -> str:
    """Digest a strict frozen ``tools/list`` projection like ACC Runtime."""

    return hashlib.sha256(canonical_json_bytes(_tool_payload(tool_snapshot))).hexdigest()


def _runtime_info(runtime_info: Mapping[str, object]) -> dict[str, object]:
    if set(runtime_info) != _RUNTIME_INFO_FIELDS:
        raise _ArtifactInvalid
    value = dict(runtime_info)
    if (
        not _is_bare_sha256(value.get("pack_sha256"))
        or not _is_bare_sha256(value.get("interaction_sha256"))
        or not _is_bare_sha256(value.get("tool_schema_sha256"))
        or not isinstance(value.get("project_id"), str)
        or not value["project_id"]
        or value["project_id"] != str(value["project_id"]).strip()
        or not isinstance(value.get("project_version"), str)
        or not value["project_version"]
        or value["project_version"] != str(value["project_version"]).strip()
        or value.get("transport") != "streamable_http"
    ):
        raise _ArtifactInvalid
    return value


def _compiled_identity(ir: Mapping[str, Any]) -> tuple[str, str, str]:
    if ir.get("ir_version") != "2":
        raise _ArtifactInvalid
    project_document = ir.get("project")
    if not isinstance(project_document, Mapping):
        raise _ArtifactInvalid
    identity = project_document.get("project")
    if not isinstance(identity, Mapping) or set(identity) != {"id", "version"}:
        raise _ArtifactInvalid
    project_id = identity.get("id")
    project_version = identity.get("version")
    interaction_digest = ir.get("interaction_sha256")
    if (
        not isinstance(project_id, str)
        or not project_id
        or not isinstance(project_version, str)
        or not project_version
        or not _is_bare_sha256(interaction_digest)
    ):
        raise _ArtifactInvalid
    return project_id, project_version, str(interaction_digest)


def _verify(
    *,
    acceptance: McpReleaseAcceptance,
    pack_path: str | os.PathLike[str],
    tool_snapshot: Mapping[str, object],
    runtime_info: Mapping[str, object] | None,
    test_report_path: str | os.PathLike[str],
) -> McpReleaseAcceptanceVerification:
    pack_bytes, pack_fingerprint = _read_regular_snapshot(pack_path, max_bytes=_MAX_PACK_BYTES)
    report_bytes, report_fingerprint = _read_regular_snapshot(
        test_report_path, max_bytes=_MAX_REPORT_BYTES
    )
    (
        ir,
        domain_map,
        ir_digest,
        pack_sha256,
        manifest_project_id,
        manifest_project_version,
    ) = _pack_payloads(pack_bytes)
    tool_digest = listed_tool_snapshot_sha256(tool_snapshot)
    project_id, project_version, interaction_digest = _compiled_identity(ir)

    if (
        acceptance.pack_digest != "sha256:" + pack_sha256
        or acceptance.ir_digest != ir_digest
        or acceptance.tool_schema_digest != "sha256:" + tool_digest
        or acceptance.test_report_digest != _prefixed_sha256(report_bytes)
    ):
        raise _DigestMismatch
    if runtime_info is not None:
        runtime = _runtime_info(runtime_info)
        if (
            runtime["pack_sha256"] != pack_sha256
            or runtime["tool_schema_sha256"] != tool_digest
            or runtime["project_id"] != project_id
            or runtime["project_version"] != project_version
            or runtime["interaction_sha256"] != interaction_digest
        ):
            raise _DigestMismatch
    if manifest_project_id != project_id or manifest_project_version != project_version:
        raise _ReleaseMismatch
    available_domains = {domain.id for domain in domain_map.domains}
    if (
        not acceptance.accepted_domain_ids
        or not set(acceptance.accepted_domain_ids) <= available_domains
    ):
        raise _ReleaseMismatch
    _require_unchanged(pack_fingerprint)
    _require_unchanged(report_fingerprint)

    frozen_ir = _deep_freeze(ir)
    frozen_tools = _deep_freeze(json.loads(json.dumps(tool_snapshot)))
    return McpReleaseAcceptanceVerification(
        ok=True,
        code="ACC_USAGE_ACCEPTANCE_VERIFIED",
        message="The accepted MCP release baseline is verified.",
        runtime_attested=runtime_info is not None,
        accepted_domain_ids=tuple(acceptance.accepted_domain_ids),
        compiled_ir=frozen_ir,
        tool_snapshot=frozen_tools,
    )


def _verify_mcp_release_acceptance_content(
    *,
    acceptance: McpReleaseAcceptance,
    pack_path: str | os.PathLike[str],
    tool_snapshot: Mapping[str, object],
    test_report_path: str | os.PathLike[str],
    runtime_info: Mapping[str, object] | None = None,
) -> McpReleaseAcceptanceVerification:
    """Verify every accepted release artifact without exposing artifact values."""

    try:
        return _verify(
            acceptance=acceptance,
            pack_path=pack_path,
            tool_snapshot=tool_snapshot,
            runtime_info=runtime_info,
            test_report_path=test_report_path,
        )
    except _AcceptanceError as exc:
        messages = {
            "ACC_USAGE_ARTIFACT_INVALID": "A release artifact is missing, unsafe, or invalid.",
            "ACC_USAGE_TOOL_SNAPSHOT_INVALID": "The frozen Tool snapshot is invalid.",
            "ACC_USAGE_DIGEST_MISMATCH": "Release attestation does not match accepted digests.",
            "ACC_USAGE_RELEASE_MISMATCH": "Release project or domain identity does not match.",
        }
        return McpReleaseAcceptanceVerification(
            ok=False,
            code=exc.code,
            message=messages[exc.code],
        )


class _AcceptanceVerifier(Protocol):
    def __call__(
        self,
        *,
        acceptance: McpReleaseAcceptance,
        pack_path: str | os.PathLike[str],
        tool_snapshot: Mapping[str, object],
        test_report_path: str | os.PathLike[str],
        runtime_info: Mapping[str, object] | None = None,
    ) -> McpReleaseAcceptanceVerification: ...


class _AcceptanceChecker(Protocol):
    def __call__(
        self,
        result: McpReleaseAcceptanceVerification,
        acceptance: McpReleaseAcceptance | None = None,
    ) -> bool: ...


def _make_live_acceptance_verifier() -> tuple[_AcceptanceVerifier, _AcceptanceChecker]:
    live: dict[
        int,
        tuple[
            weakref.ReferenceType[McpReleaseAcceptanceVerification],
            str,
            str,
        ],
    ] = {}

    def verify_mcp_release_acceptance(
        *,
        acceptance: McpReleaseAcceptance,
        pack_path: str | os.PathLike[str],
        tool_snapshot: Mapping[str, object],
        test_report_path: str | os.PathLike[str],
        runtime_info: Mapping[str, object] | None = None,
    ) -> McpReleaseAcceptanceVerification:
        result = _verify_mcp_release_acceptance_content(
            acceptance=acceptance,
            pack_path=pack_path,
            tool_snapshot=tool_snapshot,
            test_report_path=test_report_path,
            runtime_info=runtime_info,
        )
        identity = id(result)

        def discard(_reference: object) -> None:
            live.pop(identity, None)

        live[identity] = (
            weakref.ref(result, discard),
            _acceptance_fingerprint(result),
            hashlib.sha256(canonical_json_bytes(acceptance.model_dump(mode="json"))).hexdigest(),
        )
        return result

    def is_live_acceptance(
        result: McpReleaseAcceptanceVerification,
        acceptance: McpReleaseAcceptance | None = None,
    ) -> bool:
        record = live.get(id(result))
        return (
            record is not None
            and record[0]() is result
            and record[1] == _acceptance_fingerprint(result)
            and (
                acceptance is None
                or record[2]
                == hashlib.sha256(
                    canonical_json_bytes(acceptance.model_dump(mode="json"))
                ).hexdigest()
            )
        )

    return verify_mcp_release_acceptance, is_live_acceptance


verify_mcp_release_acceptance, _is_live_acceptance = _make_live_acceptance_verifier()
del _make_live_acceptance_verifier


__all__ = [
    "McpReleaseAcceptanceVerification",
    "listed_tool_snapshot_sha256",
    "verify_mcp_release_acceptance",
]
