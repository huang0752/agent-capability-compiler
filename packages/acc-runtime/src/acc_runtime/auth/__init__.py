"""Public provider-authentication strategies and restricted credential sources."""

from acc_runtime.auth.credentials import (
    CredentialPair,
    CredentialSource,
    EnvironmentCredentialSource,
    OneShotCredentialSource,
    RenewableCredentialSource,
)
from acc_runtime.auth.errors import (
    AuthConfigurationError,
    AuthCredentialError,
    AuthError,
    AuthInvalidResponseError,
    AuthLoginRejectedError,
    AuthReauthenticationRequiredError,
    AuthRequestError,
    AuthResponseTooLargeError,
    AuthTimeoutError,
    AuthUpstreamError,
)
from acc_runtime.auth.strategies import (
    AuthAttempt,
    AuthenticationResult,
    BearerSecretAuthStrategy,
    HttpAuthStrategy,
    NoAuthStrategy,
    PasswordBearerAuthStrategy,
)

__all__ = [
    "AuthAttempt",
    "AuthConfigurationError",
    "AuthCredentialError",
    "AuthError",
    "AuthInvalidResponseError",
    "AuthLoginRejectedError",
    "AuthReauthenticationRequiredError",
    "AuthRequestError",
    "AuthResponseTooLargeError",
    "AuthTimeoutError",
    "AuthUpstreamError",
    "AuthenticationResult",
    "BearerSecretAuthStrategy",
    "CredentialPair",
    "CredentialSource",
    "EnvironmentCredentialSource",
    "HttpAuthStrategy",
    "NoAuthStrategy",
    "OneShotCredentialSource",
    "PasswordBearerAuthStrategy",
    "RenewableCredentialSource",
]
