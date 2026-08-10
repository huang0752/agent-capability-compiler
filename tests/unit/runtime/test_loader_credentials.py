from __future__ import annotations

import hashlib
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

import pytest

from acc_core.packaging import PackFormatError, build_pack
from acc_runtime.credentials import (
    SecretNotFoundError,
    SecretRef,
    SecretReferenceError,
    SecretValue,
    resolve_secret,
)
from acc_runtime.errors import RuntimeError as ACCRuntimeError
from acc_runtime.loader import (
    RuntimeIRFormatError,
    RuntimeIRMissingError,
    RuntimeIRTooLargeError,
    RuntimeLookupError,
    RuntimePackVerificationError,
    load_pack,
)

_SAMPLE_IR: dict[str, Any] = {
    "ir_version": "2",
    "project": {"id": "example-crm", "version": "0.1.0"},
    "operations": {
        "crm.get_customer": {
            "id": "crm.get_customer",
            "http": {"method": "GET", "path": "/customers/{customer_id}"},
        }
    },
    "capabilities": {
        "get_customer": {
            "definition": {"id": "get_customer", "title": "Get customer"},
            "operation_dependencies": ["crm.get_customer"],
        }
    },
}


def _build_pack(tmp_path: Path, *, compiled_ir: object = _SAMPLE_IR) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "project.yaml").write_text(
        json.dumps(
            {
                "schema_version": "2",
                "project": {"id": "example-crm", "version": "2.0.0"},
                "source_workspace": {"path": "../crm", "mode": "read_only"},
                "runtime": {"transport": ["stdio"]},
                "provider": {"kind": "http", "base_url_ref": "CRM_BASE_URL"},
                "quality": {"profile": "standard"},
            }
        ),
        encoding="utf-8",
    )
    pack_path = tmp_path / "example.accpkg"
    if compiled_ir is None:
        build_pack(project, pack_path)
    else:
        assert isinstance(compiled_ir, dict)
        build_pack(project, pack_path, compiled_ir=compiled_ir)
    return pack_path


def _replace_compiled_ir(pack_path: Path, contents: bytes) -> None:
    rewritten_path = pack_path.with_name("rewritten.accpkg")
    with zipfile.ZipFile(pack_path) as source:
        entries = {info.filename: source.read(info) for info in source.infolist()}
    entries["compiled/ir.json"] = contents
    lock = json.loads(entries["pack.lock"])
    for record in lock["files"]:
        if record["path"] == "compiled/ir.json":
            record["size"] = len(contents)
            record["sha256"] = hashlib.sha256(contents).hexdigest()
    entries["pack.lock"] = (
        json.dumps(lock, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with zipfile.ZipFile(rewritten_path, "w", compression=zipfile.ZIP_STORED) as target:
        for name, value in sorted(entries.items()):
            target.writestr(name, value)
    rewritten_path.replace(pack_path)


def test_runtime_error_exposes_a_stable_json_safe_structure() -> None:
    error = ACCRuntimeError(
        "runtime execution failed",
        details={"operation": "crm.get_customer", "retryable": False},
    )

    assert error.code == "ACC_RUNTIME_ERROR"
    assert error.status == 500
    assert error.to_dict() == {
        "code": "ACC_RUNTIME_ERROR",
        "status": 500,
        "details": {"operation": "crm.get_customer", "retryable": False},
    }
    assert str(error) == "runtime execution failed"


def test_runtime_error_rejects_non_json_and_non_finite_details() -> None:
    with pytest.raises(TypeError, match="JSON-compatible"):
        ACCRuntimeError("bad details", details={"value": object()})

    with pytest.raises(ValueError, match="finite JSON values"):
        ACCRuntimeError("bad details", details={"value": float("nan")})


@pytest.mark.parametrize(
    "name",
    ["", "crm_TOKEN", "CRM-TOKEN", "1CRM_TOKEN", "CRM TOKEN"],
)
def test_secret_ref_accepts_only_uppercase_environment_names(name: str) -> None:
    with pytest.raises(SecretReferenceError) as caught:
        SecretRef(name)

    assert caught.value.code == "ACC_RUNTIME_SECRET_REF_INVALID"
    assert caught.value.status == 400
    assert caught.value.to_dict()["details"] == {"name": name}


def test_secret_ref_resolves_from_an_explicit_mapping_without_exposing_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_secret = "top-secret-bearer-token"

    secret = resolve_secret(SecretRef("CRM_USER_TOKEN"), {"CRM_USER_TOKEN": raw_secret})

    assert isinstance(secret, SecretValue)
    assert secret.get_secret_value() == raw_secret
    assert raw_secret not in str(secret)
    assert raw_secret not in repr(secret)
    with caplog.at_level(logging.INFO):
        logging.getLogger("acc-runtime-test").info("credential=%s", secret)
    assert raw_secret not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_secret_ref_uses_process_environment_only_when_mapping_is_not_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRM_USER_TOKEN", "environment-secret")

    assert SecretRef("CRM_USER_TOKEN").resolve().get_secret_value() == "environment-secret"
    with pytest.raises(SecretNotFoundError):
        SecretRef("CRM_USER_TOKEN").resolve({})


def test_missing_secret_has_a_stable_error_without_secret_material() -> None:
    with pytest.raises(SecretNotFoundError) as caught:
        resolve_secret("CRM_USER_TOKEN", {})

    error = caught.value
    assert error.code == "ACC_RUNTIME_SECRET_NOT_FOUND"
    assert error.status == 500
    assert error.to_dict() == {
        "code": "ACC_RUNTIME_SECRET_NOT_FOUND",
        "status": 500,
        "details": {"name": "CRM_USER_TOKEN"},
    }
    assert "CRM_USER_TOKEN" in str(error)


def test_load_pack_verifies_and_exposes_manifest_ir_and_lookups(tmp_path: Path) -> None:
    pack_path = _build_pack(tmp_path)

    loaded = load_pack(pack_path)

    assert loaded.path == pack_path
    assert loaded.manifest.project_id == "example-crm"
    assert loaded.ir == _SAMPLE_IR
    assert loaded.capability("get_customer") == _SAMPLE_IR["capabilities"]["get_customer"]
    assert loaded.operation("crm.get_customer") == _SAMPLE_IR["operations"]["crm.get_customer"]


def test_load_pack_rejects_legacy_ir_with_a_stable_reason(tmp_path: Path) -> None:
    pack_path = _build_pack(tmp_path)
    _replace_compiled_ir(pack_path, b'{"ir_version":"1"}\n')

    with pytest.raises(RuntimeIRFormatError) as caught:
        load_pack(pack_path)

    assert caught.value.details == {
        "path": "compiled/ir.json",
        "reason": "version_mismatch",
    }


def test_load_pack_calls_core_verification_before_loading_ir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_path = _build_pack(tmp_path)

    def reject_pack(*args: object, **kwargs: object) -> None:
        raise PackFormatError("verification sentinel", path="manifest.json")

    monkeypatch.setattr("acc_runtime.loader.verify_pack", reject_pack)

    with pytest.raises(RuntimePackVerificationError) as caught:
        load_pack(pack_path)

    assert caught.value.code == "ACC_RUNTIME_PACK_VERIFICATION_FAILED"
    assert caught.value.details == {
        "pack_code": "ACC_PACK_FORMAT_INVALID",
        "path": "manifest.json",
    }


def test_load_pack_requires_compiled_ir(tmp_path: Path) -> None:
    pack_path = _build_pack(tmp_path, compiled_ir=None)

    with pytest.raises(RuntimeIRMissingError) as caught:
        load_pack(pack_path)

    assert caught.value.code == "ACC_RUNTIME_IR_MISSING"
    assert caught.value.status == 400
    assert caught.value.details == {"path": "compiled/ir.json"}


def test_load_pack_bounds_compiled_ir_reads(tmp_path: Path) -> None:
    pack_path = _build_pack(tmp_path)

    with pytest.raises(RuntimeIRTooLargeError) as caught:
        load_pack(pack_path, max_ir_bytes=16)

    assert caught.value.code == "ACC_RUNTIME_IR_TOO_LARGE"
    assert caught.value.details == {"limit": 16, "path": "compiled/ir.json"}


@pytest.mark.parametrize(
    ("contents", "reason"),
    [
        (b"\xff", "invalid_utf8"),
        (b"[]", "not_an_object"),
        (b'{"value":NaN}', "invalid_json"),
        (b'{"value":Infinity}', "invalid_json"),
    ],
)
def test_load_pack_rejects_malformed_compiled_ir(
    tmp_path: Path,
    contents: bytes,
    reason: str,
) -> None:
    pack_path = _build_pack(tmp_path)
    _replace_compiled_ir(pack_path, contents)

    with pytest.raises(RuntimeIRFormatError) as caught:
        load_pack(pack_path)

    assert caught.value.code == "ACC_RUNTIME_IR_INVALID"
    assert caught.value.details == {"path": "compiled/ir.json", "reason": reason}


@pytest.mark.parametrize(
    ("kind", "identifier"),
    [("capability", "missing-capability"), ("operation", "missing.operation")],
)
def test_loaded_pack_lookup_errors_are_stable(
    tmp_path: Path,
    kind: str,
    identifier: str,
) -> None:
    loaded = load_pack(_build_pack(tmp_path))

    lookup = loaded.capability if kind == "capability" else loaded.operation
    with pytest.raises(RuntimeLookupError) as caught:
        lookup(identifier)

    assert caught.value.code == "ACC_RUNTIME_DEFINITION_NOT_FOUND"
    assert caught.value.status == 404
    assert caught.value.details == {"id": identifier, "kind": kind}
