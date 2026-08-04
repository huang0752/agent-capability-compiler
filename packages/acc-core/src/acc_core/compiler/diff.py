"""Canonical semantic diffs for compiled IR and pack manifests."""

from __future__ import annotations

import math
from collections.abc import Mapping

from pydantic import BaseModel, JsonValue


def _json_value(value: object) -> JsonValue:
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json", by_alias=True))
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _json_value(to_dict())
    if not isinstance(value, Mapping) and hasattr(value, "ir"):
        ir = value.ir
        if ir is None:
            raise ValueError("compilation report does not contain compiled IR")
        return _json_value(ir)
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if not isinstance(key, str):
                raise TypeError("semantic diff mappings require string keys")
            normalized[key] = _json_value(value[key])
        return normalized
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise TypeError("semantic diff numbers must be finite JSON values")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"semantic diff requires JSON-compatible data, got {type(value).__name__}")


def _pointer(parent: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}"


def _walk_diff(
    before: JsonValue,
    after: JsonValue,
    path: str,
    added: list[dict[str, JsonValue]],
    removed: list[dict[str, JsonValue]],
    modified: list[dict[str, JsonValue]],
) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        before_keys = set(before)
        after_keys = set(after)
        for key in sorted(after_keys - before_keys):
            added.append({"path": _pointer(path, key), "value": after[key]})
        for key in sorted(before_keys - after_keys):
            removed.append({"path": _pointer(path, key), "value": before[key]})
        for key in sorted(before_keys & after_keys):
            _walk_diff(before[key], after[key], _pointer(path, key), added, removed, modified)
        return

    if isinstance(before, list) and isinstance(after, list):
        common_length = min(len(before), len(after))
        for index in range(common_length, len(after)):
            added.append({"path": _pointer(path, index), "value": after[index]})
        for index in range(common_length, len(before)):
            removed.append({"path": _pointer(path, index), "value": before[index]})
        for index in range(common_length):
            _walk_diff(
                before[index],
                after[index],
                _pointer(path, index),
                added,
                removed,
                modified,
            )
        return

    if type(before) is not type(after) or before != after:
        modified.append({"path": path, "before": before, "after": after})


def semantic_diff(before: object, after: object) -> dict[str, object]:
    """Compare normalized JSON semantics, independent of object key order.

    Inputs may be mappings, Pydantic models, compiled reports exposing ``ir``,
    or pack manifests exposing ``to_dict``.
    """

    normalized_before = _json_value(before)
    normalized_after = _json_value(after)
    added: list[dict[str, JsonValue]] = []
    removed: list[dict[str, JsonValue]] = []
    modified: list[dict[str, JsonValue]] = []
    _walk_diff(normalized_before, normalized_after, "", added, removed, modified)
    return {
        "diff_version": "1",
        "has_changes": bool(added or removed or modified),
        "added": added,
        "removed": removed,
        "modified": modified,
    }


__all__ = ["semantic_diff"]
