from typing import Any

from pydantic import BaseModel, ConfigDict


class RuleResponse(BaseModel):
    code: str
    name: str
    enabled: bool
    params: dict[str, Any]
    weight: float
    mitre_techniques: list[str]
    is_demo: bool

    model_config = ConfigDict(from_attributes=True)


class RuleUpdateParams(BaseModel):
    enabled: bool | None = None
    params: dict[str, Any] | None = None
    weight: float | None = None
