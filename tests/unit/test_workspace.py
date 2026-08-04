from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    "module_name",
    ["acc_core", "acc_runtime", "acc_adapter_sdk", "acc_testkit"],
)
def test_workspace_packages_are_importable(module_name: str) -> None:
    module = importlib.import_module(module_name)

    assert module.__doc__
