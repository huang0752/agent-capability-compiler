"""Load verified compiled IR from ACC capability packs."""

from __future__ import annotations

import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path

from acc_core.io import DEFAULT_MAX_FILE_BYTES
from acc_core.packaging import (
    CapabilityPackError,
    PackManifest,
    PackVerification,
    verify_pack,
)
from acc_runtime.errors import RuntimeError

_COMPILED_IR_PATH = "compiled/ir.json"


class RuntimePackVerificationError(RuntimeError):
    """The capability pack did not pass the core integrity checks."""

    code = "ACC_RUNTIME_PACK_VERIFICATION_FAILED"
    status = 400


class RuntimeIRMissingError(RuntimeError):
    """A verified pack has no compiled runtime IR."""

    code = "ACC_RUNTIME_IR_MISSING"
    status = 400


class RuntimeIRTooLargeError(RuntimeError):
    """The compiled IR exceeds the runtime read bound."""

    code = "ACC_RUNTIME_IR_TOO_LARGE"
    status = 400


class RuntimeIRFormatError(RuntimeError):
    """The compiled IR is not a supported UTF-8 JSON object."""

    code = "ACC_RUNTIME_IR_INVALID"
    status = 400


class RuntimeLookupError(RuntimeError, LookupError):
    """A requested compiled definition does not exist."""

    code = "ACC_RUNTIME_DEFINITION_NOT_FOUND"
    status = 404


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """Verified pack metadata and its compiled runtime definitions."""

    path: Path
    manifest: PackManifest
    ir: dict[str, object]
    verification: PackVerification

    def capability(self, capability_id: str) -> dict[str, object]:
        """Return one compiled capability by its stable identifier."""

        return self._definition("capability", "capabilities", capability_id)

    def operation(self, operation_id: str) -> dict[str, object]:
        """Return one compiled operation by its stable identifier."""

        return self._definition("operation", "operations", operation_id)

    def _definition(
        self,
        kind: str,
        section_name: str,
        identifier: str,
    ) -> dict[str, object]:
        section = self.ir.get(section_name)
        if not isinstance(section, dict):
            raise RuntimeIRFormatError(
                f"compiled IR has no valid {section_name} object",
                details={"path": _COMPILED_IR_PATH, "reason": f"invalid_{section_name}"},
            )
        definition = section.get(identifier)
        if definition is None:
            raise RuntimeLookupError(
                f"compiled {kind} was not found: {identifier}",
                details={"id": identifier, "kind": kind},
            )
        if not isinstance(definition, dict):
            raise RuntimeIRFormatError(
                f"compiled {kind} must be a JSON object",
                details={"path": _COMPILED_IR_PATH, "reason": f"invalid_{kind}"},
            )
        return definition


def _validate_max_ir_bytes(max_ir_bytes: int) -> None:
    if isinstance(max_ir_bytes, bool) or not isinstance(max_ir_bytes, int) or max_ir_bytes <= 0:
        raise ValueError("max_ir_bytes must be a positive integer")


def _verification_error(error: CapabilityPackError) -> RuntimePackVerificationError:
    details: dict[str, object] = {"pack_code": error.code}
    if error.path is not None:
        details["path"] = error.path
    return RuntimePackVerificationError(
        "capability pack verification failed",
        details=details,
    )


def _read_compiled_ir(path: Path, max_ir_bytes: int) -> bytes:
    try:
        with zipfile.ZipFile(path) as archive:
            try:
                info = archive.getinfo(_COMPILED_IR_PATH)
            except KeyError as exc:
                raise RuntimeIRMissingError(
                    "capability pack does not contain compiled IR",
                    details={"path": _COMPILED_IR_PATH},
                ) from exc
            if info.file_size > max_ir_bytes:
                raise RuntimeIRTooLargeError(
                    "compiled IR exceeds the runtime size limit",
                    details={"limit": max_ir_bytes, "path": _COMPILED_IR_PATH},
                )
            with archive.open(info) as member:
                contents = member.read(max_ir_bytes + 1)
    except RuntimeError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimePackVerificationError(
            "capability pack changed or became unreadable after verification",
            details={"pack_code": "ACC_PACK_FORMAT_INVALID", "path": _COMPILED_IR_PATH},
        ) from exc
    if len(contents) > max_ir_bytes:
        raise RuntimeIRTooLargeError(
            "compiled IR exceeds the runtime size limit",
            details={"limit": max_ir_bytes, "path": _COMPILED_IR_PATH},
        )
    return contents


def _parse_compiled_ir(
    contents: bytes,
    *,
    format_version: int,
) -> dict[str, object]:
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeIRFormatError(
            "compiled IR must use UTF-8",
            details={"path": _COMPILED_IR_PATH, "reason": "invalid_utf8"},
        ) from exc
    try:
        value = json.loads(
            text,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeIRFormatError(
            "compiled IR must contain strict JSON",
            details={"path": _COMPILED_IR_PATH, "reason": "invalid_json"},
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeIRFormatError(
            "compiled IR must be a JSON object",
            details={"path": _COMPILED_IR_PATH, "reason": "not_an_object"},
        )
    ir_version = value.get("ir_version")
    if ir_version != str(format_version) and not (format_version == 1 and ir_version is None):
        raise RuntimeIRFormatError(
            "compiled IR version does not match the pack format",
            details={"path": _COMPILED_IR_PATH, "reason": "version_mismatch"},
        )
    return value


def load_pack(
    pack_path: str | os.PathLike[str],
    *,
    max_ir_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> LoadedPack:
    """Verify a pack, then load only its bounded ``compiled/ir.json`` member."""

    _validate_max_ir_bytes(max_ir_bytes)
    try:
        verification = verify_pack(pack_path)
    except CapabilityPackError as exc:
        raise _verification_error(exc) from exc
    contents = _read_compiled_ir(verification.path, max_ir_bytes)
    ir = _parse_compiled_ir(
        contents,
        format_version=verification.manifest.format_version,
    )
    return LoadedPack(
        path=verification.path,
        manifest=verification.manifest,
        ir=ir,
        verification=verification,
    )


__all__ = [
    "LoadedPack",
    "RuntimeIRFormatError",
    "RuntimeIRMissingError",
    "RuntimeIRTooLargeError",
    "RuntimeLookupError",
    "RuntimePackVerificationError",
    "load_pack",
]
