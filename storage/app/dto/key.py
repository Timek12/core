from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

class KeyBase(BaseModel):
    key_type: str = Field(..., description="Type of key: root, master, dek")
    encrypted_key: str = Field(..., description="Encrypted key value")
    nonce: str = Field(..., description="Nonce used for encryption")
    version: int = Field(default=1, description="Key version")
    status: str = Field(default='active', description="Key status")
    meta: Optional[str] = Field(None, description="Additional metadata as JSON string")

class KeyCreate(KeyBase):
    pass

class KeyResponse(KeyBase):
    id: uuid.UUID = Field(..., description="Key unique identifier")
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True