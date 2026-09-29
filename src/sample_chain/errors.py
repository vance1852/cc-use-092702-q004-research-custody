"""科研采样许可与保管链服务向 API 和 CLI 暴露的稳定错误。"""


class SampleChainError(RuntimeError):
    code = "chain_error"
    status = 400


class NotFound(SampleChainError):
    code = "not_found"
    status = 404


class Conflict(SampleChainError):
    code = "conflict"
    status = 409


class Forbidden(SampleChainError):
    code = "forbidden"
    status = 403


class InvalidState(SampleChainError):
    code = "invalid_state"
    status = 409


class ValidationFailed(SampleChainError):
    code = "validation_failed"
    status = 422
