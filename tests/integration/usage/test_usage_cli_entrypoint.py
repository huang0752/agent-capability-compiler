from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parents[2] / "fixtures" / "usage" / "finance"


def test_usage_status_runs_through_installed_cli_entrypoint(tmp_path: Path) -> None:
    project = tmp_path / "usage-project"
    shutil.copytree(FIXTURE, project)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acc_core.cli.main",
            "usage",
            "status",
            str(project),
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload["command"] == "usage status"
    assert payload["result"]["next_domain"] is None
    assert payload["result"]["domains"] == [
        {"dependency_ready": True, "domain_id": "finance", "state": "released"}
    ]


def test_usage_build_fails_closed_without_live_evidence_and_signer(tmp_path: Path) -> None:
    project = tmp_path / "usage-project"
    shutil.copytree(FIXTURE, project)
    package = project / "artifacts" / "finance.accusage"
    guide = project / "exports" / "finance.md"

    built = subprocess.run(
        [
            sys.executable,
            "-m",
            "acc_core.cli.main",
            "usage",
            "build",
            "--domain",
            "finance",
            "--project",
            str(project),
            "--output",
            str(package),
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert built.returncode == 3
    assert built.stderr == ""
    payload = json.loads(built.stdout)
    assert payload["result"] is None
    assert payload["diagnostics"][0]["code"] == "ACC_USAGE_BUILD_EVIDENCE_NOT_PROVISIONED"
    assert not package.exists()
    assert not guide.exists()
