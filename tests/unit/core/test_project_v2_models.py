from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from acc_core.models import Project, ProjectDocument, ProjectV2


def _project(version: str = "2") -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": version,
        "project": {"id": "orders", "version": "2.0.0"},
        "source_workspace": {"path": "/srv/orders", "mode": "read_only"},
        "runtime": {"transport": ["stdio"]},
        "provider": {
            "kind": "http",
            "base_url_ref": "ORDERS_BASE_URL",
            "auth": {"kind": "bearer_secret", "token_ref": "ORDERS_TOKEN"},
        },
    }
    if version == "2":
        document["quality"] = {"profile": "standard"}
    return document


def test_project_document_dispatches_versions_without_widening_v1() -> None:
    v1 = TypeAdapter(ProjectDocument).validate_python(_project("1"))
    v2 = TypeAdapter(ProjectDocument).validate_python(_project("2"))

    assert isinstance(v1, Project)
    assert isinstance(v2, ProjectV2)
    assert v2.quality.profile == "standard"


def test_project_v2_requires_an_explicit_quality_profile() -> None:
    document = _project()
    document.pop("quality")

    with pytest.raises(ValidationError, match="quality"):
        ProjectV2.model_validate(document)


def test_project_v1_cannot_silently_accept_v2_quality_semantics() -> None:
    document = _project("1")
    document["quality"] = {"profile": "release"}

    with pytest.raises(ValidationError, match="quality"):
        Project.model_validate(document)
