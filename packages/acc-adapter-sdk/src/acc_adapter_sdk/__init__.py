"""Contracts and server primitives for out-of-process ACC adapters."""

from acc_adapter_sdk.contracts import (
    AdapterActionMethod,
    AdapterActionOperation,
    AdapterActionSafety,
    AdapterBodyTarget,
    AdapterContract,
    AdapterControlTarget,
    AdapterHeaderTarget,
    AdapterHealth,
    AdapterMethod,
    AdapterOperation,
    AdapterRequiredConcurrency,
    AdapterResponseBodyToken,
    AdapterResponseHeaderToken,
    AdapterSourceKeyIdempotency,
)
from acc_adapter_sdk.server import AdapterRegistrationError, AdapterServer
from acc_adapter_sdk.testing import (
    AdapterContractAssertionError,
    assert_adapter_contract,
)

__all__ = [
    "AdapterActionMethod",
    "AdapterActionOperation",
    "AdapterActionSafety",
    "AdapterBodyTarget",
    "AdapterContract",
    "AdapterContractAssertionError",
    "AdapterControlTarget",
    "AdapterHeaderTarget",
    "AdapterHealth",
    "AdapterMethod",
    "AdapterOperation",
    "AdapterRegistrationError",
    "AdapterRequiredConcurrency",
    "AdapterResponseBodyToken",
    "AdapterResponseHeaderToken",
    "AdapterServer",
    "AdapterSourceKeyIdempotency",
    "assert_adapter_contract",
]
