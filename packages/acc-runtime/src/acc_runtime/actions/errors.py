"""Stable, payload-free errors for the Action state boundary."""

from acc_runtime.errors import RuntimeError


class ActionHandleInvalidError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_HANDLE_INVALID"
    status = 404


class ActionBindingMismatchError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_BINDING_MISMATCH"
    status = 403


class ActionExpiredError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_EXPIRED"
    status = 410


class ActionStateConflictError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_STATE_CONFLICT"
    status = 409


class ActionApprovalInvalidError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_APPROVAL_INVALID"
    status = 403


class ActionApprovalExpiredError(RuntimeError):
    code = "ACC_RUNTIME_ACTION_APPROVAL_EXPIRED"
    status = 410


class ApprovalAuthorityIntegrityError(RuntimeError):
    code = "ACC_RUNTIME_APPROVAL_AUTHORITY_INTEGRITY"
    status = 500


__all__ = [
    "ActionApprovalExpiredError",
    "ActionApprovalInvalidError",
    "ActionBindingMismatchError",
    "ActionExpiredError",
    "ActionHandleInvalidError",
    "ActionStateConflictError",
    "ApprovalAuthorityIntegrityError",
]
