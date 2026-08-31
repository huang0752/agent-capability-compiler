"""Safety gates and orchestration for ``acc test live``."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import anyio
import yaml
from pydantic import ValidationError

from acc_core.coverage import (
    LiveObservationArtifact,
    LiveObservationSample,
    create_live_observation_artifact,
)
from acc_core.diagnostics import Diagnostic, ResultEnvelope
from acc_core.quality.output_size import canonical_json_bytes
from acc_runtime.errors import RuntimeError as AccRuntimeError
from acc_runtime.loader import LoadedPack, load_pack
from acc_testkit.live import LiveGatewayProfile, LiveGatewayReport, LiveGatewayRunner

_EXIT_SUCCESS = 0
_EXIT_TEST = 5
_MAX_PROFILE_BYTES = 1_048_576
_OBSERVATION_VALIDITY = timedelta(hours=24)


def run_live_command(
    arguments: argparse.Namespace,
    *,
    environment: Mapping[str, str],
) -> tuple[int, ResultEnvelope]:
    """Validate an explicit source connection and run a live Gateway profile."""

    if not bool(arguments.allow_source_connect):
        return _fail(
            "ACC_LIVE_SOURCE_CONNECT_NOT_ALLOWED",
            "Live testing requires explicit source-connection authorization.",
        )
    try:
        gateway_url, authority, loopback = _validated_gateway_url(str(arguments.gateway_url))
    except ValueError:
        return _fail(
            "ACC_LIVE_GATEWAY_URL_INVALID",
            "The live Gateway URL is invalid.",
        )
    try:
        allowed = _validated_allowlist(
            cast(Sequence[str], arguments.allowed_gateway_host),
        )
    except ValueError:
        return _fail(
            "ACC_LIVE_GATEWAY_ALLOWLIST_INVALID",
            "The live Gateway allowlist is invalid.",
        )
    if not loopback and authority not in allowed:
        return _fail(
            "ACC_LIVE_GATEWAY_NOT_ALLOWED",
            "A non-loopback Gateway requires an exact authority allowlist entry.",
        )
    if not loopback and not gateway_url.startswith("https://"):
        return _fail(
            "ACC_LIVE_GATEWAY_NOT_ALLOWED",
            "A non-loopback Gateway must use HTTPS.",
        )

    try:
        loaded_pack = load_pack(Path(str(arguments.pack)))
        verification = loaded_pack.verification
    except (AccRuntimeError, OSError, ValueError):
        return _fail("ACC_LIVE_PACK_INVALID", "The live-test Pack is invalid.")
    try:
        profile = _load_profile(Path(str(arguments.profile)), gateway_url=gateway_url)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, ValueError):
        return _fail("ACC_LIVE_PROFILE_INVALID", "The live-test Profile is invalid.")
    expected = profile.attestation
    if (
        expected.pack_sha256 != verification.sha256
        or expected.project_id != verification.manifest.project_id
        or expected.project_version != verification.manifest.project_version
    ):
        return _fail(
            "ACC_LIVE_PACK_ATTESTATION_MISMATCH",
            "The live-test Profile does not identify the supplied Pack.",
        )
    if any(
        not environment.get(secret.env)
        for account in profile.accounts
        for secret in (account.identity, account.password)
    ):
        return _fail(
            "ACC_LIVE_SECRET_MISSING",
            "One or more Profile credential environment references are unavailable.",
        )
    try:
        report = anyio.run(_execute_live_profile, profile, environment)
    except Exception:
        return _fail("ACC_LIVE_RUN_FAILED", "The live Gateway test could not complete.")

    if report.verified:
        result = report.model_dump(mode="json")
        observations_output = getattr(arguments, "observations_output", None)
        if observations_output is not None:
            try:
                artifact = _build_observation_artifact(
                    loaded_pack,
                    profile,
                    report,
                    observed_at=datetime.now(UTC),
                )
                output_path = Path(str(observations_output)).expanduser().resolve(strict=False)
                _write_observation_artifact(output_path, artifact.model_dump(mode="json"))
            except (OSError, TypeError, ValueError):
                return _fail(
                    "ACC_LIVE_OBSERVATIONS_OUTPUT_FAILED",
                    "The verified live observations could not be written safely.",
                )
            result["live_observations"] = {
                "path": str(output_path),
                "sha256": artifact.artifact_sha256,
                "expires_at": artifact.expires_at.isoformat().replace("+00:00", "Z"),
            }
        return _EXIT_SUCCESS, ResultEnvelope(
            ok=True,
            command="test live",
            result=result,
            diagnostics=[],
        )
    return _EXIT_TEST, ResultEnvelope(
        ok=False,
        command="test live",
        result=None,
        diagnostics=[
            Diagnostic(
                code="ACC_LIVE_VERIFICATION_INCOMPLETE",
                severity="error",
                message="The live Gateway report did not reach verified status.",
                path=None,
                pointer=None,
            )
        ],
    )


def _build_observation_artifact(
    loaded_pack: LoadedPack,
    profile: LiveGatewayProfile,
    report: LiveGatewayReport,
    *,
    observed_at: datetime,
) -> LiveObservationArtifact:
    capabilities = loaded_pack.ir.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ValueError("compiled IR has no capability map")
    steps = {step.id: step for step in report.steps}
    samples: list[LiveObservationSample] = []
    for case in profile.cases:
        if case.capability_id is None or case.expect_error:
            continue
        if case.capability_id not in capabilities:
            raise ValueError("live case references an unknown Pack capability")
        if case.tool not in {case.capability_id, f"{case.capability_id}.prepare"}:
            raise ValueError("live case tool does not match its capability binding")
        step = steps.get(f"case.{case.id}")
        response_bytes = None if step is None else step.evidence.get("response_bytes")
        if step is None or step.status.value != "passed" or not isinstance(response_bytes, int):
            continue
        samples.append(
            LiveObservationSample(
                capability_id=case.capability_id,
                case_id=case.id,
                response_bytes=response_bytes,
            )
        )
    if not samples:
        raise ValueError("no successful capability-bound live cases")
    ir_record = next(
        (item for item in loaded_pack.verification.files if item.path == "compiled/ir.json"),
        None,
    )
    if ir_record is None:
        raise ValueError("Pack has no compiled IR record")
    profile_sha256 = hashlib.sha256(
        canonical_json_bytes(profile.model_dump(mode="json"))
    ).hexdigest()
    report_sha256 = hashlib.sha256(canonical_json_bytes(report.model_dump(mode="json"))).hexdigest()
    return create_live_observation_artifact(
        project_id=loaded_pack.manifest.project_id,
        project_version=loaded_pack.manifest.project_version,
        pack_sha256=loaded_pack.verification.sha256,
        compiled_ir_sha256=ir_record.sha256,
        profile_sha256=profile_sha256,
        report_sha256=report_sha256,
        observed_at=observed_at,
        expires_at=observed_at + _OBSERVATION_VALIDITY,
        samples=tuple(sorted(samples, key=lambda item: (item.capability_id, item.case_id))),
    )


def _write_observation_artifact(path: Path, value: object) -> None:
    if path.is_symlink():
        raise ValueError("observation output cannot be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    contents = canonical_json_bytes(value) + b"\n"
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


async def _execute_live_profile(
    profile: LiveGatewayProfile,
    environment: Mapping[str, str],
) -> LiveGatewayReport:
    return await LiveGatewayRunner(profile, environment=environment).run()


def _load_profile(path: Path, *, gateway_url: str) -> LiveGatewayProfile:
    if path.is_symlink() or not path.is_file():
        raise ValueError("live Profile must be a regular non-symlink file")
    if path.stat(follow_symlinks=False).st_size > _MAX_PROFILE_BYTES:
        raise ValueError("live Profile is too large")
    contents = path.read_bytes()
    if len(contents) > _MAX_PROFILE_BYTES:
        raise ValueError("live Profile is too large")
    raw = yaml.safe_load(contents.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("live Profile must be an object")
    document: dict[str, Any] = dict(raw)
    document["gateway_url"] = gateway_url
    accounts = document.get("accounts")
    cases = document.get("cases")
    isolation = document.get("isolation")
    if isinstance(accounts, list):
        document["accounts"] = tuple(accounts)
    if isinstance(cases, list):
        document["cases"] = tuple(cases)
    if isinstance(isolation, dict):
        normalized_isolation = dict(isolation)
        isolation_accounts = normalized_isolation.get("accounts")
        if isinstance(isolation_accounts, list):
            normalized_isolation["accounts"] = tuple(isolation_accounts)
        document["isolation"] = normalized_isolation
    return LiveGatewayProfile.model_validate(document)


def _validated_gateway_url(value: str) -> tuple[str, str, bool]:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid Gateway URL")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid Gateway port") from None
    hostname = parsed.hostname.casefold()
    if hostname == "localhost":
        loopback = True
        rendered_host = hostname
    else:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            loopback = False
            if (
                not hostname.isascii()
                or "*" in hostname
                or any(character.isspace() for character in hostname)
            ):
                raise ValueError("invalid Gateway hostname") from None
            rendered_host = hostname
        else:
            loopback = address.is_loopback
            rendered_host = (
                f"[{address.compressed}]" if address.version == 6 else address.compressed
            )
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    return f"{parsed.scheme}://{authority}", authority, loopback


def _validated_allowlist(values: Sequence[str]) -> frozenset[str]:
    allowed: set[str] = set()
    for value in values:
        if (
            not value
            or value != value.strip()
            or "*" in value
            or any(marker in value for marker in ("/", "?", "#", "@", "\\"))
        ):
            raise ValueError("invalid Gateway allowlist entry")
        parsed = urlsplit(f"//{value}")
        if parsed.hostname is None or parsed.username is not None or parsed.password is not None:
            raise ValueError("invalid Gateway allowlist entry")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("invalid Gateway allowlist port") from None
        hostname = parsed.hostname.casefold()
        rendered = f"[{hostname}]" if ":" in hostname else hostname
        allowed.add(rendered if port is None else f"{rendered}:{port}")
    return frozenset(allowed)


def _fail(code: str, message: str) -> tuple[int, ResultEnvelope]:
    return _EXIT_TEST, ResultEnvelope(
        ok=False,
        command="test live",
        result=None,
        diagnostics=[
            Diagnostic(
                code=code,
                severity="error",
                message=message,
                path=None,
                pointer=None,
            )
        ],
    )


__all__ = ["run_live_command"]
