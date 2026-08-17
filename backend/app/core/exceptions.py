
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class SecOpsException(Exception):
    def __init__(
        self,
        message: str,
        code: str = "BAD_REQUEST",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        field: str | None = None
    ):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(message)


class NotFoundException(SecOpsException):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(
            message=message,
            code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            field=field
        )


class ValidationException(SecOpsException):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_400_BAD_REQUEST,
            field=field
        )


async def secops_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    secops_exc = exc if isinstance(exc, SecOpsException) else SecOpsException(str(exc))
    return JSONResponse(
        status_code=secops_exc.status_code,
        content={
            "error": {
                "code": secops_exc.code,
                "message": secops_exc.message,
                "field": secops_exc.field
            }
        }
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    val_exc = exc if isinstance(exc, RequestValidationError) else RequestValidationError([])
    errors = val_exc.errors()
    first_error = errors[0] if errors else {}
    field_loc = " -> ".join([str(x) for x in first_error.get("loc", [])])
    msg = first_error.get("msg", "Validation error")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": f"{field_loc}: {msg}",
                "field": field_loc
            }
        }
    )


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": str(exc),
                "field": None
            }
        }
    )
