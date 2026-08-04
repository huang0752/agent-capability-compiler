from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "evidence_capture.py"


def _run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def _base(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    project = tmp_path / "acc-project"
    source.mkdir()
    project.mkdir()
    file = source / "app" / "routes.py"
    file.parent.mkdir()
    file.write_text("private-value-never-copy\nsecond line\n", encoding="utf-8")
    return source, project, file


def test_evidence_capture_atomically_writes_only_locator_metadata(tmp_path: Path) -> None:
    source, project, file = _base(tmp_path)

    completed, payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        "app/routes.py",
        "--source-id",
        "example-system",
        "--output",
        "api/routes.json",
        "--line-start",
        "1",
        "--line-end",
        "2",
    )

    assert completed.returncode == 0
    assert payload["ok"] is True
    output = project / "evidence" / "api" / "routes.json"
    evidence = json.loads(output.read_text(encoding="utf-8"))
    raw = file.read_bytes()
    assert evidence == {
        "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "kind": "source_file",
        "line_end": 2,
        "line_start": 1,
        "path": "app/routes.py",
        "size_bytes": len(raw),
        "source_id": "example-system",
    }
    assert "private-value-never-copy" not in output.read_text(encoding="utf-8")
    assert "private-value-never-copy" not in completed.stdout
    assert not list(output.parent.glob(".acc-evidence-*"))


def test_evidence_capture_rejects_traversal_secret_and_source_symlink(tmp_path: Path) -> None:
    source, project, _ = _base(tmp_path)
    secret = source / ".env"
    secret.write_text("never-open-production-secret", encoding="utf-8")
    secret.chmod(0)
    (source / "linked.py").symlink_to(source / "app" / "routes.py")

    traversing, traversal_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        "../outside",
        "--source-id",
        "example",
        "--output",
        "capture.json",
    )
    sensitive, sensitive_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        ".env",
        "--source-id",
        "example",
        "--output",
        "capture.json",
    )
    linked, linked_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        "linked.py",
        "--source-id",
        "example",
        "--output",
        "capture.json",
    )

    assert traversing.returncode == 2
    assert traversal_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert sensitive.returncode == 3
    assert sensitive_payload["diagnostics"][0]["code"] == "ACC_SKILL_SECRET_REJECTED"
    assert "never-open-production-secret" not in sensitive.stdout
    assert linked.returncode == 3
    assert linked_payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"


def test_evidence_capture_never_writes_outside_real_project_evidence_dir(
    tmp_path: Path,
) -> None:
    source, project, _ = _base(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (project / "evidence").symlink_to(outside, target_is_directory=True)

    linked_dir, linked_payload = _run(
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        "app/routes.py",
        "--source-id",
        "example",
        "--output",
        "capture.json",
    )

    assert linked_dir.returncode == 3
    assert linked_payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"
    assert list(outside.iterdir()) == []


def test_evidence_capture_rejects_output_parent_segments_and_oversize(tmp_path: Path) -> None:
    source, project, _ = _base(tmp_path)
    common = [
        "--source-workspace",
        str(source),
        "--project-dir",
        str(project),
        "--source",
        "app/routes.py",
        "--source-id",
        "example",
    ]

    traversal, traversal_payload = _run(*common, "--output", "../escape.json")
    oversized, oversized_payload = _run(
        *common, "--output", "capture.json", "--max-file-bytes", "4"
    )

    assert traversal.returncode == 2
    assert traversal_payload["diagnostics"][0]["code"] == "ACC_SKILL_PATH_INVALID"
    assert not (project / "escape.json").exists()
    assert oversized.returncode == 3
    assert oversized_payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"
