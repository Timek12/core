from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class KeyBase(BaseModel):
    key_type: str = Field(..., max_length=16)
    encrypted_key: str
    nonce: str
    version: int = Field(default=1)
    active: bool = Field(default=True)
    meta: Optional[str] = None

class KeyCreate(KeyBase):
    pass

class KeyResponse(KeyBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True