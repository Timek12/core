from pydantic import BaseModel, Field, ConfigDict
import uuid
from datetime import datetime

from typing import Optional

class SecretBase(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: str = Field(..., min_length=5, max_length=256, description='Secret name')
    description: str = Field(..., description='Secret description')
    key_id: uuid.UUID = Field(..., description='Secret key')
    value_plaintext: str = Field(..., description='Plaintext secret value')
    version: int = Field(..., description='Secret version')
    created_at: datetime = Field(..., description='Secret creation time')
    updated_at: datetime = Field(..., description='Secret modification time')

class Secret(SecretBase):
    id: uuid.UUID = Field(..., description='Unique identifier of secret')

class SecretCreate(SecretBase):
    pass

class SecretUpdate(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: Optional[str] = Field(None, min_length=5, max_length=256, description='Secret name')
    description: Optional[str] = Field(None, description='Secret description')
    key_id: Optional[uuid.UUID] = Field(None, description='Secret key')
    value_plaintext: Optional[str] = Field(None, description='Plaintext secret value')
    version: Optional[int] = Field(None, description='Secret version')
    created_at: Optional[datetime] = Field(None, description='Secret creation time')
    updated_at: Optional[datetime] = Field(None, description='Secret modification time')