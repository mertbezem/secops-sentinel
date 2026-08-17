from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class StandardErrorDetail(BaseModel):
    code: str
    message: str
    field: str | None = None


class StandardErrorEnvelope(BaseModel):
    error: StandardErrorDetail


# Compatibility aliases
ErrorDetail = StandardErrorDetail
ErrorResponse = StandardErrorEnvelope


class PageEnvelope(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# PaginatedResponse alias
PaginatedResponse = PageEnvelope

# Import IncidentOut for common schema re-export
