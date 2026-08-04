from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "skills" / "acc-engineer" / "scripts" / "summarize_diagnostics.py"


def _run(
    *arguments: str, stdin: str | None = None
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        input=stdin,
        capture_output=True,
        check=False,
    )
    return completed, json.loads(completed.stdout)


def test_summarize_counts_nested_diagnostics_without_echoing_messages(tmp_path: Path) -> None:
    secret = "credential-never-output"
    document = {
        "ok": False,
        "diagnostics": [
            {"code": "ACC_A", "severity": "error", "message": secret, "path": ".env"},
            {"code": "ACC_B", "severity": "warning", "message": "safe"},
        ],
        "result": {
            "cases": [{"diagnostics": [{"code": "ACC_A", "severity": "error", "message": "again"}]}]
        },
    }
    input_file = tmp_path / "diagnostics.json"
    input_file.write_text(json.dumps(document), encoding="utf-8")

    completed, payload = _run("--input", str(input_file))

    assert completed.returncode == 0
    assert payload["result"] == {
        "by_code": {"ACC_A": 2, "ACC_B": 1},
        "by_severity": {"error": 2, "warning": 1},
        "codes": ["ACC_A", "ACC_B"],
        "total": 3,
    }
    assert secret not in completed.stdout
    assert ".env" not in completed.stdout


def test_summarize_accepts_bounded_stdin() -> None:
    completed, payload = _run(
        "--input",
        "-",
        stdin=json.dumps([{"code": "ACC_ONLY", "severity": "error", "message": "not echoed"}]),
    )

    assert completed.returncode == 0
    assert payload["result"]["by_code"] == {"ACC_ONLY": 1}
    assert "not echoed" not in completed.stdout


def test_summarize_rejects_oversized_and_symlink_inputs(tmp_path: Path) -> None:
    input_file = tmp_path / "input.json"
    input_file.write_text('{"diagnostics":[]}', encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(input_file)

    oversized, oversized_payload = _run("--input", str(input_file), "--max-file-bytes", "4")
    symlinked, symlinked_payload = _run("--input", str(linked))

    assert oversized.returncode == 3
    assert oversized_payload["diagnostics"][0]["code"] == "ACC_SKILL_FILE_TOO_LARGE"
    assert symlinked.returncode == 3
    assert symlinked_payload["diagnostics"][0]["code"] == "ACC_SKILL_SYMLINK_REJECTED"
