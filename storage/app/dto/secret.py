from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

class SecretBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str
    key_id: uuid.UUID
    encrypted_value: str
    version: int = Field(default=1)

class SecretCreate(SecretBase):
    pass

class SecretUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = None
    key_id: Optional[uuid.UUID] = None
    encrypted_value: Optional[str] = None
    version: Optional[int] = None

class SecretResponse(SecretBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True