from __future__ import annotations

from acc_testkit import (
    CallRecorder,
    E2EAssertionError,
    FakeRestSystem,
    Fault,
    McpStdioTestClient,
    RecordingOperationProvider,
    ResponseSpec,
    RouteFixture,
    assert_e2e,
)


def test_primary_testkit_api_is_exported_from_package_root() -> None:
    assert FakeRestSystem.__name__ == "FakeRestSystem"
    assert ResponseSpec.__name__ == "ResponseSpec"
    assert RouteFixture.__name__ == "RouteFixture"
    assert Fault.__name__ == "Fault"
    assert McpStdioTestClient.__name__ == "McpStdioTestClient"
    assert RecordingOperationProvider.__name__ == "RecordingOperationProvider"
    assert CallRecorder.__name__ == "CallRecorder"
    assert E2EAssertionError.__name__ == "E2EAssertionError"
    assert assert_e2e.__name__ == "assert_e2e"
