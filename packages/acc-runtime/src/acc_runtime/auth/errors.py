"""Stable, secret-free failures raised by HTTP authentication strategies."""

from acc_runtime.errors import RuntimeError


class AuthError(RuntimeError):
    """Base error for provider-level authentication."""

    code = "ACC_RUNTIME_AUTH_ERROR"
    status = 502


class AuthConfigurationError(AuthError):
    """The resolved authentication endpoint is not a fixed HTTP origin."""

    code = "ACC_RUNTIME_AUTH_CONFIGURATION_INVALID"
    status = 500


class AuthCredentialError(AuthError):
    """A credential source returned empty or malformed secret material."""

    code = "ACC_RUNTIME_AUTH_CREDENTIAL_INVALID"
    status = 500


class AuthLoginRejectedError(AuthError):
    """The source system rejected a login request."""

    code = "ACC_RUNTIME_AUTH_LOGIN_REJECTED"
    status = 401


class AuthUpstreamError(AuthError):
    """The source login endpoint returned an upstream failure."""

    code = "ACC_RUNTIME_AUTH_UPSTREAM_ERROR"
    status = 502


class AuthTimeoutError(AuthError):
    """The bounded source login request timed out."""

    code = "ACC_RUNTIME_AUTH_TIMEOUT"
    status = 504


class AuthRequestError(AuthError):
    """The source login request could not be completed."""

    code = "ACC_RUNTIME_AUTH_REQUEST_FAILED"
    status = 502


class AuthResponseTooLargeError(AuthError):
    """The source login response exceeded its configured byte limit."""

    code = "ACC_RUNTIME_AUTH_RESPONSE_TOO_LARGE"
    status = 502


class AuthInvalidResponseError(AuthError):
    """The source login response did not satisfy the declared contract."""

    code = "ACC_RUNTIME_AUTH_INVALID_RESPONSE"
    status = 502


class AuthReauthenticationRequiredError(AuthError):
    """A non-renewable session must be authenticated again by its caller."""

    code = "ACC_RUNTIME_AUTH_REAUTHENTICATION_REQUIRED"
    status = 401


__all__ = [
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
]
