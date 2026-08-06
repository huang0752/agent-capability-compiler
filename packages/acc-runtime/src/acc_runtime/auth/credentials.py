"""Restricted credential sources used by provider authentication strategies."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from acc_core.models import EnvironmentSecretCredentials
from acc_runtime.context import AuthStateKey
from acc_runtime.credentials import SecretValue, resolve_secret


@dataclass(frozen=True, slots=True, repr=False)
class CredentialPair:
    """A redacted identity/password pair unwrapped only at the login boundary."""

    identity: SecretValue
    password: SecretValue

    def __post_init__(self) -> None:
        if not isinstance(self.identity, SecretValue) or not isinstance(self.password, SecretValue):
            raise TypeError("credential pair values must be SecretValue instances")


class CredentialSource(Protocol):
    """Common renewal classification for restricted credential sources."""

    @property
    def renewable(self) -> bool:
        """Whether credentials may be acquired again after a 401 or expiry."""


class RenewableCredentialSource(CredentialSource, Protocol):
    """Reload credentials for an already established PrincipalContext."""

    @property
    def renewable(self) -> Literal[True]:
        """Renewable sources may be read again after expiry or 401."""

    async def acquire(self, auth_state_key: AuthStateKey) -> CredentialPair:
        """Return a redacted pair without accepting a bare state handle."""


class OneShotCredentialSource(CredentialSource, Protocol):
    """Gateway-owned one-shot source interface; this module provides no Store."""

    @property
    def renewable(self) -> Literal[False]:
        """One-shot Gateway credentials are never renewable."""

    async def consume(self) -> CredentialPair:
        """Consume the pre-Principal login input exactly once."""


class EnvironmentCredentialSource:
    """Reload a fixed username/password reference from the process environment."""

    __slots__ = ("_configuration", "_environment")

    def __init__(
        self,
        configuration: EnvironmentSecretCredentials,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._configuration = configuration
        self._environment = environment

    @property
    def renewable(self) -> Literal[True]:
        return True

    async def acquire(self, auth_state_key: AuthStateKey) -> CredentialPair:
        if not isinstance(auth_state_key, AuthStateKey):
            raise TypeError("credential acquisition requires an AuthStateKey")
        return CredentialPair(
            identity=resolve_secret(
                self._configuration.identity_ref,
                self._environment,
            ),
            password=resolve_secret(
                self._configuration.password_ref,
                self._environment,
            ),
        )


__all__ = [
    "CredentialPair",
    "CredentialSource",
    "EnvironmentCredentialSource",
    "OneShotCredentialSource",
    "RenewableCredentialSource",
]
