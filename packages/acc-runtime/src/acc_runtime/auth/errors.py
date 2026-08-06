"""Stable, secret-free failures raised by HTTP authentication strategies."""

from acc_runtime.errors import RuntimeError


class AuthError(RuntimeError):
    """Base class whose code remains inside the reviewed auth taxonomy."""

    code = "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID"
    status = 500


class AuthConfigurationError(AuthError):
    """The resolved authentication configuration is unsafe or inconsistent."""

    code = "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID"
    status = 500


class AuthSecretMissingError(AuthError):
    """Required authentication secret material is unavailable."""

    code = "ACC_RUNTIME_AUTH_SECRET_MISSING"
    status = 500


class AuthCredentialError(AuthSecretMissingError):
    """Compatibility name for invalid or unavailable secret material."""


class AuthLoginFailedError(AuthError):
    """The bounded source login exchange failed."""

    code = "ACC_RUNTIME_AUTH_LOGIN_FAILED"
    status = 502


class AuthLoginRejectedError(AuthLoginFailedError):
    """Compatibility subtype for a source login rejection."""

    status = 401


class AuthUpstreamError(AuthLoginFailedError):
    """Compatibility subtype for a source login upstream failure."""


class AuthRequestError(AuthLoginFailedError):
    """Compatibility subtype for a source login network failure."""


class AuthResponseInvalidError(AuthError):
    """The source login response did not satisfy the declared contract."""

    code = "ACC_RUNTIME_AUTH_RESPONSE_INVALID"
    status = 502


class AuthInvalidResponseError(AuthResponseInvalidError):
    """Compatibility name for an invalid source login response."""


class AuthUnauthorizedError(AuthError):
    """The current source authentication is no longer authorized."""

    code = "ACC_RUNTIME_AUTH_UNAUTHORIZED"
    status = 401


class AuthReauthenticationRequiredError(AuthUnauthorizedError):
    """Compatibility subtype for one-shot sessions requiring a new login."""


class AuthTimeoutError(RuntimeError):
    """The bounded source login request timed out."""

    code = "ACC_RUNTIME_HTTP_TIMEOUT"
    status = 504


class AuthResponseTooLargeError(RuntimeError):
    """The source login response exceeded its configured byte limit."""

    code = "ACC_RUNTIME_HTTP_RESPONSE_TOO_LARGE"
    status = 502


__all__ = [
    "AuthConfigurationError",
    "AuthCredentialError",
    "AuthError",
    "AuthInvalidResponseError",
    "AuthLoginFailedError",
    "AuthLoginRejectedError",
    "AuthReauthenticationRequiredError",
    "AuthRequestError",
    "AuthResponseInvalidError",
    "AuthResponseTooLargeError",
    "AuthSecretMissingError",
    "AuthTimeoutError",
    "AuthUnauthorizedError",
    "AuthUpstreamError",
]
