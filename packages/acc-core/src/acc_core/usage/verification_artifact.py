"""Signed, expiring bridge for live Agent Usage verification provenance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from acc_core.io import is_path_link
from acc_core.quality.output_size import canonical_json_bytes
from acc_core.usage.models import McpReleaseAcceptance
from acc_core.usage.project import UsageProjectReport
from acc_core.usage.verification import (
    VerifiedUsageReleaseBundle,
    _register_authenticated_bundle,
)

_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_TRUST_BYTES = 64 * 1024
_MAX_VALIDITY_SECONDS = 86_400


class UsageVerificationArtifactError(ValueError):
    """Fail-closed signed verification artifact error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _project_projection(report: UsageProjectReport) -> dict[str, object]:
    return {
        "project": None if report.project is None else report.project.model_dump(mode="json"),
        "acceptance": (
            None if report.acceptance is None else report.acceptance.model_dump(mode="json")
        ),
        "source_snapshot": (
            None
            if report.source_snapshot is None
            else report.source_snapshot.model_dump(mode="json")
        ),
        "domain_index": (
            None if report.domain_index is None else report.domain_index.model_dump(mode="json")
        ),
        "contracts": {
            key: value.model_dump(mode="json")
            for key, value in sorted(report.domain_contracts.items())
        },
        "scenarios": {
            key: value.model_dump(mode="json") for key, value in sorted(report.scenarios.items())
        },
        "decisions": {
            f"{key[0]}:{key[1]}": value.model_dump(mode="json")
            for key, value in sorted(report.decisions.items())
        },
        "releases": {
            key: value.model_dump(mode="json") for key, value in sorted(report.releases.items())
        },
    }


def _read_regular(path: Path, maximum: int) -> bytes:
    if _contains_link(path):
        raise UsageVerificationArtifactError("ACC_USAGE_VERIFICATION_UNTRUSTED", "linked input")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise OSError
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(value) > maximum or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise OSError
        finally:
            os.close(descriptor)
        current = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError
        return value
    except OSError:
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_UNTRUSTED", "verification input is not a stable regular file"
        ) from None


def _contains_link(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if is_path_link(current):
            return True
        if not current.exists():
            return False
    return False


def _atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _contains_link(path.parent) or is_path_link(path):
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_OUTPUT_UNSAFE", "verification output path is linked"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        if _contains_link(path.parent) or is_path_link(path):
            raise UsageVerificationArtifactError(
                "ACC_USAGE_VERIFICATION_OUTPUT_UNSAFE", "verification output path became linked"
            )
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_usage_verification_artifact(
    path: Path,
    *,
    report: UsageProjectReport,
    acceptance: McpReleaseAcceptance,
    bundle: VerifiedUsageReleaseBundle,
    signing_key: bytes,
    observed_at: int | None = None,
    expires_in_seconds: int = 900,
) -> str:
    """Write an artifact from a live trusted runner result."""

    if not report.ok or not bundle.trusted or not 0 < expires_in_seconds <= _MAX_VALIDITY_SECONDS:
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_UNTRUSTED", "only a live trusted bundle can be signed"
        )
    now = int(time.time()) if observed_at is None else observed_at
    key = bytes(signing_key)
    if len(key) < 32:
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_KEY_INVALID", "verification key must be at least 32 bytes"
        )
    key_id = "sha256:" + hashlib.sha256(key).hexdigest()
    payload: dict[str, object] = {
        "schema_version": "2",
        "artifact_kind": "trusted_usage_verification",
        "key_id": key_id,
        "observed_at": now,
        "expires_at": now + expires_in_seconds,
        "nonce": secrets.token_hex(32),
        "project_digest": _digest(_project_projection(report)),
        "acceptance_digest": _digest(acceptance.model_dump(mode="json")),
        "bundle": bundle.model_dump(mode="json"),
    }
    signature = hmac.new(key, canonical_json_bytes(payload), hashlib.sha256).hexdigest()
    document = {**payload, "signature": signature}
    _atomic_write(path, canonical_json_bytes(document) + b"\n")
    return key_id


def _trust_keys(path: Path) -> dict[str, bytes]:
    try:
        raw_document = _read_regular(path, _MAX_TRUST_BYTES)
        document = json.loads(raw_document)
        if raw_document != canonical_json_bytes(document) + b"\n":
            raise ValueError
        raw_keys = document["keys"]
        if document.get("schema_version") != "2" or not isinstance(raw_keys, Mapping):
            raise ValueError
        keys = {
            str(key): base64.b64decode(str(value), validate=True) for key, value in raw_keys.items()
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_TRUST_INVALID", "verification trust store is invalid"
        ) from None
    if not keys or any(
        "sha256:" + hashlib.sha256(value).hexdigest() != key for key, value in keys.items()
    ):
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_TRUST_INVALID", "verification trust store identities mismatch"
        )
    return keys


def load_usage_verification_artifact(
    path: Path,
    *,
    trust_store: Path,
    report: UsageProjectReport,
    acceptance: McpReleaseAcceptance,
    domain_id: str,
    now: int | None = None,
) -> VerifiedUsageReleaseBundle:
    """Authenticate, expire, rebind, and register one trusted runner artifact."""

    try:
        raw_document = _read_regular(path, _MAX_ARTIFACT_BYTES)
        document: dict[str, Any] = json.loads(raw_document)
        if raw_document != canonical_json_bytes(document) + b"\n":
            raise ValueError
        signature = document.pop("signature")
        key_id = document["key_id"]
        keys = _trust_keys(trust_store)
        key = keys[key_id]
        expected = hmac.new(key, canonical_json_bytes(document), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError
        current = int(time.time()) if now is None else now
        if (
            document.get("schema_version") != "2"
            or document.get("artifact_kind") != "trusted_usage_verification"
            or not isinstance(document.get("nonce"), str)
            or len(document["nonce"]) != 64
            or not isinstance(document.get("observed_at"), int)
            or not isinstance(document.get("expires_at"), int)
            or document["observed_at"] > current + 60
            or document["expires_at"] < current
            or document["expires_at"] <= document["observed_at"]
            or document["expires_at"] - document["observed_at"] > _MAX_VALIDITY_SECONDS
            or document["project_digest"] != _digest(_project_projection(report))
            or document["acceptance_digest"] != _digest(acceptance.model_dump(mode="json"))
        ):
            raise ValueError
        bundle = VerifiedUsageReleaseBundle.model_validate(document["bundle"])
        release = bundle.release
        if (
            release.domain_id != domain_id
            or release.pack_digest != acceptance.pack_digest
            or release.ir_digest != acceptance.ir_digest
            or release.tool_schema_digest != acceptance.tool_schema_digest
            or release.test_report_digest != acceptance.test_report_digest
            or domain_id not in acceptance.accepted_domain_ids
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise UsageVerificationArtifactError(
            "ACC_USAGE_VERIFICATION_UNTRUSTED",
            "verification artifact is invalid, expired, stale, mismatched, or untrusted",
        ) from None
    return _register_authenticated_bundle(bundle)


__all__ = [
    "UsageVerificationArtifactError",
    "load_usage_verification_artifact",
    "write_usage_verification_artifact",
]
