"""保管链服务向 API 和 CLI 暴露的稳定错误。"""


class CustodyChainError(RuntimeError):
    code = "custody_error"
    status = 400


class NotFound(CustodyChainError):
    code = "not_found"
    status = 404


class Conflict(CustodyChainError):
    code = "conflict"
    status = 409


class Forbidden(CustodyChainError):
    code = "forbidden"
    status = 403


class InvalidState(CustodyChainError):
    code = "invalid_state"
    status = 409


class ValidationFailed(CustodyChainError):
    code = "validation_failed"
    status = 422
