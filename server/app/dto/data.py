from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


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
    namespace: Optional[str] = None
    username: Optional[str] = None
    host: Optional[str] = None
    url: Optional[str] = None
    hasPublicKey: Optional[bool] = None
    hasChain: Optional[bool] = None


class DataCreateRequest(BaseModel):
    """Request to create a new typed data from frontend"""
    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="")
    data_type: DataType
    
    # Type-specific fields
    fields: Optional[List[KeyValuePair]] = None
    namespace: Optional[str] = None
    data: Optional[List[KeyValuePair]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    apiKey: Optional[str] = None
    privateKey: Optional[str] = None
    publicKey: Optional[str] = None
    passphrase: Optional[str] = None
    host: Optional[str] = None
    certificate: Optional[str] = None
    chain: Optional[str] = None


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
    privateKey: Optional[str] = None
    publicKey: Optional[str] = None
    passphrase: Optional[str] = None
    host: Optional[str] = None
    certificate: Optional[str] = None
    chain: Optional[str] = None
    project_id: Optional[str] = None


class DataResponse(BaseModel):
    """Response with full data (decrypted)"""
    id: str
    user_id: int
    name: str
    description: str
    data_type: DataType
    decrypted_data: Dict[str, Any]
    metadata: Optional[DataMetadata] = None
    version: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    project_id: Optional[str] = None
    
    class Config:
        from_attributes = True


class DataListItem(BaseModel):
    """Lighter version for list views"""
    id: str
    user_id: int
    name: str
    description: str
    data_type: DataType
    version: int
    metadata: Optional[DataMetadata] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
