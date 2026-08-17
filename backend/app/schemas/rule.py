from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleResponse(BaseModel):
    code: str = Field(..., description="Kural benzersiz kodu (ör. R001)")
    name: str = Field(..., description="Kural adı")
    enabled: bool = Field(..., description="Kuralın aktiflik durumu")
    params: dict[str, Any] = Field(..., description="Kural eşik ve pencere parametreleri")
    weight: float = Field(..., description="Kural önem ağırlığı")
    mitre_techniques: list[str] = Field(..., description="İlişkili MITRE ATT&CK teknikleri")
    is_demo: bool = Field(..., description="Demo kuralı olup olmadığı")

    model_config = ConfigDict(from_attributes=True)


class RuleUpdateParams(BaseModel):
    enabled: bool | None = Field(None, description="Kuralı aktif/pasif yapma durumu")
    params: dict[str, Any] | None = Field(None, description="Güncellenecek parametre sözlüğü (JSON)")
    weight: float | None = Field(None, description="Güncellenecek kural ağırlığı")
