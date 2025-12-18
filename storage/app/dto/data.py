from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, field_validator, validator
import json


class DataType(str, Enum):
    """Data type enumeration"""

    TEXT = "text"
    KUBERNETES = "kubernetes"
    CREDENTIALS = "credentials"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"


class KeyValuePair(BaseModel):
    """Generic key-value pair"""

    key: str = Field(..., min_length=1)
    value: str


class DataMetadata(BaseModel):
    """Unencrypted metadata for filtering/display"""

    namespace: Optional[str] = None  # kubernetes
    username: Optional[str] = None  # ssh_key, credentials
    host: Optional[str] = None  # ssh_key
    url: Optional[str] = None  # credentials
    hasPublicKey: Optional[bool] = None  # ssh_key
    hasChain: Optional[bool] = None  # certificate
    hasHeaders: Optional[bool] = None  # api_key


class DataCreateRequest(BaseModel):
    """Request to create a new typed data"""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="")
    data_type: DataType
    fields: Optional[List[KeyValuePair]] = None
    namespace: Optional[str] = None
    data: Optional[List[KeyValuePair]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    apiKey: Optional[str] = None
    headers: Optional[List[KeyValuePair]] = None
    privateKey: Optional[str] = None
    publicKey: Optional[str] = None
    passphrase: Optional[str] = None
    host: Optional[str] = None
    certificate: Optional[str] = None
    chain: Optional[str] = None

    @field_validator("fields", "data", "headers")
    @classmethod
    def validate_key_value_pairs(cls, value):
        if value is not None and len(value) == 0:
            raise ValueError("Cannot be an empty list")
        return value

    def validate_type_specific_fields(self):
        if self.data_type == DataType.TEXT and not self.fields:
            raise ValueError("fields required for text")
        if self.data_type == DataType.KUBERNETES:
            if not self.namespace:
                raise ValueError("namespace required for kubernetes")
            if not self.data:
                raise ValueError("data required for kubernetes")
        if self.data_type == DataType.CREDENTIALS and (not self.username or not self.password):
            raise ValueError("username and password required for credentials")
        if self.data_type == DataType.API_KEY and not self.apiKey:
            raise ValueError("apiKey required for api_key")
        if self.data_type == DataType.SSH_KEY and not self.privateKey:
            raise ValueError("privateKey required for ssh_key")
        if self.data_type == DataType.CERTIFICATE and (not self.certificate or not self.privateKey):
            raise ValueError("certificate and privateKey required for certificate")


class DataUpdateRequest(BaseModel):
    """Request to update an existing data"""

    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = None
    fields: Optional[List[KeyValuePair]] = None
    namespace: Optional[str] = None
    data: Optional[List[KeyValuePair]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    apiKey: Optional[str] = None
    headers: Optional[List[KeyValuePair]] = None
    privateKey: Optional[str] = None
    publicKey: Optional[str] = None
    passphrase: Optional[str] = None
    host: Optional[str] = None
    certificate: Optional[str] = None
    chain: Optional[str] = None
    rotation_interval_days: Optional[int] = None

class DataInternalCreate(BaseModel):
    """Internal payload coming from the server service"""

    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = ""
    data_type: DataType
    encrypted_value: str
    dek_id: UUID
    metadata_json: Optional[str] = None
    rotation_interval_days: Optional[int] = None

class DataInternalUpdate(BaseModel):
    """Internal payload for updating an existing data"""

    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = None
    data_type: Optional[DataType] = None
    encrypted_value: Optional[str] = None
    dek_id: Optional[UUID] = None
    metadata_json: Optional[str] = None
    project_id: Optional[UUID] = None
    rotation_interval_days: Optional[int] = None


class DataResponse(BaseModel):
    """Response with full data (decrypted)"""

    id: str
    user_id: int
    name: str
    description: str
    data_type: DataType
    decrypted_data: Optional[Dict[str, Any]] = None
    encrypted_value: Optional[str] = None
    metadata: Optional[DataMetadata] = None
    version: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    project_id: Optional[UUID] = None
    rotation_interval_days: Optional[int] = None
    next_rotation_date: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataListItem(BaseModel):
    """Lighter version for list views"""

    id: str
    user_id: int
    name: str
    description: str
    data_type: DataType
    metadata: Optional[DataMetadata] = None
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DataVersionResponse(BaseModel):
    """Response for a historical version of data"""

    id: str
    data_id: str
    version: int
    encrypted_value: str
    dek_id: str
    created_at: datetime
    created_by: Optional[int] = None

    class Config:
        from_attributes = True


class DataVersionListResponse(BaseModel):
    """Response for a list of version metadata."""
    versions: List[DataVersionResponse]
    total: int
