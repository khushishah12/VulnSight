"""Application-level errors with safe, consistent API responses."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base class for expected, client-visible failures."""

    status_code: int = 400
    code: str = "bad_request"

    def __init__(
        self,
        message: str,
        *,
        details: Any | None = None,
        code: str | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if details is not None:
            self.details = details
        else:
            self.details = None
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code


class BadRequestError(AppError):
    status_code = 400
    code = "bad_request"


class UnauthorizedError(AppError):
    status_code = 401
    code = "unauthorized"


class ForbiddenError(AppError):
    status_code = 403
    code = "forbidden"


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class UnprocessableEntityError(AppError):
    status_code = 422
    code = "unprocessable_entity"


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "service_unavailable"
