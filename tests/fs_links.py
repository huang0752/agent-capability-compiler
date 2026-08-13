"""Filesystem-link helpers for cross-platform security tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def create_link(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create a symlink, or an equivalent directory junction on Windows.

    File and broken symlinks have no unprivileged Windows substitute with the
    same path-redirection semantics, so only those individual test cases skip
    when SeCreateSymbolicLinkPrivilege is unavailable.
    """

    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
        return
    except OSError as exc:
        if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
            raise
    if target_is_directory and target.is_dir():
        completed = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0 and link.is_junction():
            return
    pytest.skip(
        "Windows symlink privilege is unavailable and this file/broken-link "
        "case has no semantics-preserving unprivileged substitute"
    )
