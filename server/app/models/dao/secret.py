from pydantic import BaseModel, Field
import uuid
from datetime import datetime


class SecretBase(BaseModel):
    id: uuid.UUID = Field(..., description='Unique identifier of secret')
    name: str = Field(..., min_length=5, max_length=256, description='Secret name')
    description: str = Field(..., description='Secret description')
    key_id: uuid.UUID = Field(..., description='Secret key')
    encrypted_value: str = Field(..., description='Encrypted secret value')
    version: int = Field(..., description='Secret version')
    created_at: datetime = Field(..., description='Secret creation time')
    updated_at: datetime = Field(..., description='Secret modification time')