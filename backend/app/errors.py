"""Common error envelope (DES-005 §1.2). Messages are fixed strings; no internals leak."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("app.errors")

FIXED_MESSAGES: dict[str, str] = {
    "INVALID_REQUEST": "요청 형식이 올바르지 않습니다.",
    "AUTH_REQUIRED": "로그인이 필요합니다.",
    "INVALID_CREDENTIALS": "이메일 또는 비밀번호가 올바르지 않습니다.",
    "TOKEN_EXPIRED": "인증이 만료되었습니다. 다시 로그인해 주세요.",
    "TOKEN_REVOKED": "더 이상 유효하지 않은 인증입니다. 다시 로그인해 주세요.",
    "FORBIDDEN": "이 기능을 사용할 권한이 없습니다.",
    "NOT_FOUND": "요청한 항목을 찾을 수 없습니다.",
    "EMAIL_UNAVAILABLE": "사용할 수 없는 이메일입니다.",
    "BODY_TOO_LARGE": "요청 크기가 너무 큽니다.",
    "VALIDATION_ERROR": "입력값을 확인해 주세요.",
    "RATE_LIMITED": "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
    "AUDIT_UNAVAILABLE": "일시적으로 요청을 처리할 수 없습니다. 잠시 후 다시 시도해 주세요.",
    "SERVICE_NOT_READY": "서비스가 준비되지 않았습니다.",
    "INTERNAL_ERROR": "일시적인 오류가 발생했습니다.",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.headers = headers or {}


def error_response(request: Request, status: int, code: str, headers: dict[str, str] | None = None) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    body = {"request_id": request_id, "error": {"code": code, "message": FIXED_MESSAGES[code]}}
    return JSONResponse(body, status_code=status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(request, exc.status, exc.code, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field details could echo user input, so only the fixed code is returned.
        return error_response(request, 422, "VALIDATION_ERROR")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        mapping = {404: "NOT_FOUND", 405: "INVALID_REQUEST", 401: "AUTH_REQUIRED", 403: "FORBIDDEN"}
        code = mapping.get(exc.status_code, "INVALID_REQUEST")
        return error_response(request, exc.status_code if exc.status_code in mapping else 400, code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled error class=%s request_id=%s", type(exc).__name__, getattr(request.state, "request_id", None)
        )
        return error_response(request, 500, "INTERNAL_ERROR")
