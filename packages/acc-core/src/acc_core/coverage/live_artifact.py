"""Integrity-bound machine artifacts for source-connected live observations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationError, field_validator, model_validator

from acc_core.coverage.models import LiveObservation
from acc_core.models import StrictModel
from acc_core.quality.output_size import canonical_json_bytes

_MAX_ARTIFACT_BYTES = 1_048_576


class LiveObservationArtifactError(ValueError):
    """A live-observation artifact is unsafe, invalid, stale, or mismatched."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LiveObservationSample(StrictModel):
    """One successful source-connected capability invocation."""

    capability_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    response_bytes: Annotated[int, Field(ge=0)]


class LiveObservationArtifact(StrictModel):
    """Canonical output emitted by ``acc test live``, never by coverage summaries."""

    schema_version: Literal["1"] = "1"
    kind: Literal["acc.live_observations"] = "acc.live_observations"
    project_id: str = Field(min_length=1)
    project_version: str = Field(min_length=1)
    pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiled_ir_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime
    expires_at: datetime
    samples: tuple[LiveObservationSample, ...] = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at", "expires_at")
    @classmethod
    def validate_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("live observation timestamps must include UTC offsets")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        keys = [(item.capability_id, item.case_id) for item in self.samples]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("live observation samples must be uniquely sorted")
        if self.expires_at <= self.observed_at:
            raise ValueError("live observation expiry must follow observation time")
        if self.artifact_sha256 != artifact_digest(self):
            raise ValueError("live observation artifact digest mismatch")
        return self


def _digest_payload(value: LiveObservationArtifact | dict[str, object]) -> dict[str, object]:
    if isinstance(value, LiveObservationArtifact):
        return value.model_dump(mode="json", exclude={"artifact_sha256"})
    return {key: item for key, item in value.items() if key != "artifact_sha256"}


def artifact_digest(value: LiveObservationArtifact | dict[str, object]) -> str:
    """Digest canonical artifact content, excluding the digest field itself."""

    return hashlib.sha256(canonical_json_bytes(_digest_payload(value))).hexdigest()


def create_live_observation_artifact(
    *,
    project_id: str,
    project_version: str,
    pack_sha256: str,
    compiled_ir_sha256: str,
    profile_sha256: str,
    report_sha256: str,
    observed_at: datetime,
    expires_at: datetime,
    samples: tuple[LiveObservationSample, ...],
) -> LiveObservationArtifact:
    """Create a strict artifact and its self-consistency digest."""

    provisional = LiveObservationArtifact.model_construct(
        project_id=project_id,
        project_version=project_version,
        pack_sha256=pack_sha256,
        compiled_ir_sha256=compiled_ir_sha256,
        profile_sha256=profile_sha256,
        report_sha256=report_sha256,
        observed_at=observed_at,
        expires_at=expires_at,
        samples=samples,
        artifact_sha256="0" * 64,
    )
    digest = artifact_digest(provisional.model_dump(mode="json"))
    return LiveObservationArtifact(
        project_id=project_id,
        project_version=project_version,
        pack_sha256=pack_sha256,
        compiled_ir_sha256=compiled_ir_sha256,
        profile_sha256=profile_sha256,
        report_sha256=report_sha256,
        observed_at=observed_at,
        expires_at=expires_at,
        samples=samples,
        artifact_sha256=digest,
    )


def artifact_observations(artifact: LiveObservationArtifact) -> tuple[LiveObservation, ...]:
    """Aggregate raw samples deterministically for the Coverage live axis."""

    grouped: dict[str, list[int]] = {}
    for sample in artifact.samples:
        grouped.setdefault(sample.capability_id, []).append(sample.response_bytes)
    observations: list[LiveObservation] = []
    for capability_id, sizes in sorted(grouped.items()):
        ordered = sorted(sizes)
        observations.append(
            LiveObservation(
                capability_id=capability_id,
                verification_level="source_connected_verified",
                sample_count=len(ordered),
                response_bytes_p50=_nearest_rank(ordered, 0.50),
                response_bytes_p95=_nearest_rank(ordered, 0.95),
                response_bytes_max=ordered[-1],
            )
        )
    return tuple(observations)


def _nearest_rank(values: list[int], percentile: float) -> int:
    index = max(0, int(len(values) * percentile + 0.999999999) - 1)
    return values[index]


def load_live_observation_artifact(
    path: Path,
    *,
    project_id: str,
    project_version: str,
    pack_sha256: str,
    compiled_ir_sha256: str,
    capability_ids: Collection[str],
    now: datetime | None = None,
) -> LiveObservationArtifact:
    """Load canonical bytes and enforce integrity, freshness, and Project binding."""

    if path.is_symlink() or not path.is_file():
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_INVALID",
            "Live observations must be a regular non-symlink file.",
        )
    try:
        if path.stat(follow_symlinks=False).st_size > _MAX_ARTIFACT_BYTES:
            raise ValueError("artifact too large")
        contents = path.read_bytes()
        if len(contents) > _MAX_ARTIFACT_BYTES:
            raise ValueError("artifact too large")
        raw = json.loads(contents.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_INVALID",
            "The live-observation artifact is invalid.",
        ) from exc
    if not isinstance(raw, dict):
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_INVALID",
            "The live-observation artifact is invalid.",
        )
    supplied_digest = raw.get("artifact_sha256")
    if not isinstance(supplied_digest, str) or supplied_digest != artifact_digest(raw):
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_TAMPERED",
            "The live-observation artifact digest does not match its content.",
        )
    try:
        artifact = LiveObservationArtifact.model_validate_json(contents)
    except ValidationError as exc:
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_INVALID",
            "The live-observation artifact is invalid.",
        ) from exc
    canonical = canonical_json_bytes(artifact.model_dump(mode="json")) + b"\n"
    if contents != canonical:
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_INVALID",
            "The live-observation artifact must use canonical JSON encoding.",
        )
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    if artifact.observed_at > checked_at or artifact.expires_at <= checked_at:
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_STALE",
            "The live-observation artifact is outside its validity window.",
        )
    if (
        artifact.project_id != project_id
        or artifact.project_version != project_version
        or artifact.pack_sha256 != pack_sha256
        or artifact.compiled_ir_sha256 != compiled_ir_sha256
    ):
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_MISMATCH",
            "The live-observation artifact does not match the current Project IR.",
        )
    observed_capability_ids = {sample.capability_id for sample in artifact.samples}
    if not observed_capability_ids <= set(capability_ids):
        raise LiveObservationArtifactError(
            "ACC_COVERAGE_LIVE_OBSERVATIONS_MISMATCH",
            "The live-observation artifact references capabilities outside the current Project.",
        )
    return artifact


__all__ = [
    "LiveObservationArtifact",
    "LiveObservationArtifactError",
    "LiveObservationSample",
    "artifact_digest",
    "artifact_observations",
    "create_live_observation_artifact",
    "load_live_observation_artifact",
]
