from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

class SecretBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str
    key_id: uuid.UUID
    dek_id: Optional[uuid.UUID] = None  # Data Encryption Key reference
    encrypted_value: str
    version: int = Field(default=1)
    is_active: bool = Field(default=True)  # Active/inactive status

class SecretCreate(SecretBase):
    user_id: int

class SecretUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = None
    key_id: Optional[uuid.UUID] = None
    dek_id: Optional[uuid.UUID] = None  # Data Encryption Key reference
    encrypted_value: Optional[str] = None
    version: Optional[int] = None
    is_active: Optional[bool] = None  # Allow updating active status

class SecretResponse(SecretBase):
    id: uuid.UUID
    user_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True