from typing import Any

from fastapi import HTTPException


class AgentError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


ERROR_MAP = {
    "INVALID_CREDENTIALS": 401,
    "CLIENT_NOT_FOUND": 404,
    "CONFIG_NOT_FOUND": 404,
    "FORMAT_NOT_FOUND": 404,
    "UNSUPPORTED_CAPABILITY": 400,
    "NOT_FOUND": 404,
    "VALIDATION_ERROR": 422,
    "PAYLOAD_TOO_LARGE": 413,
}


def error_body(code: str, message: str) -> dict[str, Any]:
    return {"success": False, "error": {"code": code, "message": message}}


def raise_agent_error(code: str, message: str, status: int | None = None) -> None:
    raise HTTPException(
        status_code=status or ERROR_MAP.get(code, 400),
        detail=error_body(code, message),
    )
