from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from acc_core.coverage import (
    LiveObservationArtifact,
    LiveObservationArtifactError,
    LiveObservationSample,
    artifact_observations,
    create_live_observation_artifact,
    load_live_observation_artifact,
)
from acc_core.quality.output_size import canonical_json_bytes


def _artifact(now: datetime) -> LiveObservationArtifact:
    return create_live_observation_artifact(
        project_id="project-a",
        project_version="1.0.0",
        pack_sha256="a" * 64,
        compiled_ir_sha256="b" * 64,
        profile_sha256="c" * 64,
        report_sha256="d" * 64,
        observed_at=now,
        expires_at=now + timedelta(hours=24),
        samples=(
            LiveObservationSample(
                capability_id="records.current",
                case_id="read-1",
                response_bytes=10,
            ),
            LiveObservationSample(
                capability_id="records.current",
                case_id="read-2",
                response_bytes=30,
            ),
            LiveObservationSample(
                capability_id="records.current",
                case_id="read-3",
                response_bytes=20,
            ),
        ),
    )


def _write(path: Path, artifact: object) -> None:
    path.write_bytes(canonical_json_bytes(artifact) + b"\n")


def test_live_observation_artifact_aggregates_capability_samples(tmp_path: Path) -> None:
    now = datetime(2026, 8, 12, tzinfo=UTC)
    artifact = _artifact(now)
    path = tmp_path / "observations.json"
    _write(path, artifact.model_dump(mode="json"))

    loaded = load_live_observation_artifact(
        path,
        project_id="project-a",
        project_version="1.0.0",
        pack_sha256="a" * 64,
        compiled_ir_sha256="b" * 64,
        capability_ids={"records.current"},
        now=now + timedelta(minutes=1),
    )

    observations = artifact_observations(loaded)
    assert len(observations) == 1
    assert observations[0].sample_count == 3
    assert observations[0].response_bytes_p50 == 20
    assert observations[0].response_bytes_p95 == 30
    assert observations[0].response_bytes_max == 30


def test_live_observation_artifact_rejects_tampering(tmp_path: Path) -> None:
    now = datetime(2026, 8, 12, tzinfo=UTC)
    payload = _artifact(now).model_dump(mode="json")
    payload["samples"][0]["response_bytes"] = 999
    path = tmp_path / "observations.json"
    _write(path, payload)

    with pytest.raises(LiveObservationArtifactError) as raised:
        load_live_observation_artifact(
            path,
            project_id="project-a",
            project_version="1.0.0",
            pack_sha256="a" * 64,
            compiled_ir_sha256="b" * 64,
            capability_ids={"records.current"},
            now=now + timedelta(minutes=1),
        )

    assert raised.value.code == "ACC_COVERAGE_LIVE_OBSERVATIONS_TAMPERED"


@pytest.mark.parametrize(
    ("now_offset", "ir_digest", "expected_code"),
    [
        (timedelta(days=2), "b" * 64, "ACC_COVERAGE_LIVE_OBSERVATIONS_STALE"),
        (timedelta(minutes=1), "e" * 64, "ACC_COVERAGE_LIVE_OBSERVATIONS_MISMATCH"),
    ],
)
def test_live_observation_artifact_rejects_stale_or_mismatched_evidence(
    tmp_path: Path,
    now_offset: timedelta,
    ir_digest: str,
    expected_code: str,
) -> None:
    now = datetime(2026, 8, 12, tzinfo=UTC)
    path = tmp_path / "observations.json"
    _write(path, _artifact(now).model_dump(mode="json"))

    with pytest.raises(LiveObservationArtifactError) as raised:
        load_live_observation_artifact(
            path,
            project_id="project-a",
            project_version="1.0.0",
            pack_sha256="a" * 64,
            compiled_ir_sha256=ir_digest,
            capability_ids={"records.current"},
            now=now + now_offset,
        )

    assert raised.value.code == expected_code
