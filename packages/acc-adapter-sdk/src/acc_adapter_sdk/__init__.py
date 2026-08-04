"""Contracts and server primitives for out-of-process ACC adapters."""

from acc_adapter_sdk.contracts import (
    AdapterContract,
    AdapterHealth,
    AdapterMethod,
    AdapterOperation,
)
from acc_adapter_sdk.server import AdapterRegistrationError, AdapterServer
from acc_adapter_sdk.testing import (
    AdapterContractAssertionError,
    assert_adapter_contract,
)

__all__ = [
    "AdapterContract",
    "AdapterContractAssertionError",
    "AdapterHealth",
    "AdapterMethod",
    "AdapterOperation",
    "AdapterRegistrationError",
    "AdapterServer",
    "assert_adapter_contract",
]
