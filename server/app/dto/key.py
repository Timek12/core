from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from .common import DataResponse, PaginatedResponse

class KeyType(str, Enum):
    """Supported key types"""
    ROOT = "root"
    MASTER = "master"
    DEK = "dek"
    ENCRYPTION = "encryption"
    SIGNING = "signing"

class KeyStatus(str, Enum):
    """Key status values"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    PENDING_DELETION = "pending_deletion"

class KeyBase(BaseModel):
    """Base key schema"""
    key_type: KeyType = Field(..., description="Type of cryptographic key")
    encrypted_key: str = Field(..., description="Encrypted key material")
    nonce: str = Field(..., description="Nonce used for key encryption")
    version: int = Field(default=1, ge=1, description="Key version for rotation")
    status: KeyStatus = Field(default=KeyStatus.ACTIVE, description="Key status")
    meta: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    @validator('encrypted_key')
    def validate_encrypted_key(cls, v):
        if not v.strip():
            raise ValueError('Encrypted key cannot be empty')
        return v.strip()
    
    @validator('nonce')
    def validate_nonce(cls, v):
        if not v.strip():
            raise ValueError('Nonce cannot be empty')
        return v.strip()

class KeyCreate(KeyBase):
    """Schema for creating a key"""
    purpose: Optional[str] = Field(None, max_length=255, description="Purpose/usage of the key")
    expires_at: Optional[datetime] = Field(None, description="Key expiration time")
    
class KeyUpdate(BaseModel):
    """Schema for updating a key"""
    status: Optional[KeyStatus] = Field(None, description="Update key status")
    meta: Optional[Dict[str, Any]] = Field(None, description="Update metadata")
    expires_at: Optional[datetime] = Field(None, description="Update expiration time")

class KeyResponse(KeyBase):
    """Schema for key response"""
    id: int = Field(..., description="Key unique identifier")
    purpose: Optional[str] = Field(None, description="Key purpose/usage")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(default=0, description="Number of times key was used")
    created_by: Optional[str] = Field(None, description="User who created the key")
    
    class Config:
        from_attributes = True

class KeyListItem(BaseModel):
    """Minimal key info for lists"""
    id: int = Field(..., description="Key unique identifier")
    key_type: KeyType = Field(..., description="Type of key")
    version: int = Field(..., description="Key version")
    status: KeyStatus = Field(..., description="Key status")
    purpose: Optional[str] = Field(None, description="Key purpose")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    usage_count: int = Field(..., description="Usage count")

class KeySearchRequest(BaseModel):
    """Search/filter request for keys"""
    key_type: Optional[KeyType] = Field(None, description="Filter by key type")
    status: Optional[KeyStatus] = Field(None, description="Filter by status")
    purpose: Optional[str] = Field(None, description="Search by purpose")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date")
    expires_soon: Optional[bool] = Field(None, description="Filter keys expiring soon")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")

class KeyRotationRequest(BaseModel):
    """Key rotation request"""
    key_id: int = Field(..., description="Key ID to rotate")
    reason: Optional[str] = Field(None, max_length=500, description="Reason for rotation")
    new_expires_at: Optional[datetime] = Field(None, description="New key expiration time")

class KeyRotationResult(BaseModel):
    """Key rotation result"""
    old_key: KeyListItem = Field(..., description="Previous key info")
    new_key: KeyListItem = Field(..., description="New key info")
    rotation_reason: Optional[str] = Field(None, description="Rotation reason")
    rotated_at: datetime = Field(..., description="Rotation timestamp")
    rotated_by: Optional[str] = Field(None, description="User who performed rotation")

class KeyDeactivationRequest(BaseModel):
    """Key deactivation request"""
    reason: Optional[str] = Field(None, max_length=500, description="Reason for deactivation")

class KeyUsageLog(BaseModel):
    """Key usage audit log"""
    key_id: int = Field(..., description="Key ID")
    operation: str = Field(..., description="Operation performed with key")
    user_id: Optional[str] = Field(None, description="User who used the key")
    timestamp: datetime = Field(..., description="Usage timestamp")
    success: bool = Field(..., description="Whether operation succeeded")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")

class KeyStatsResponse(BaseModel):
    """Key statistics response"""
    total_keys: int = Field(..., description="Total number of keys")
    active_keys: int = Field(..., description="Number of active keys")
    inactive_keys: int = Field(..., description="Number of inactive keys")
    keys_by_type: Dict[KeyType, int] = Field(..., description="Count by key type")
    expiring_soon: List[KeyListItem] = Field(default=[], description="Keys expiring soon")
    most_used_keys: List[KeyListItem] = Field(default=[], description="Most frequently used keys")
    recent_rotations: List[KeyRotationResult] = Field(default=[], description="Recent key rotations")

# Response wrappers
class KeyDataResponse(DataResponse[KeyResponse]):
    """Single key response"""
    pass

class KeyListResponse(PaginatedResponse[KeyListItem]):
    """Paginated keys list response"""
    pass

class KeyRotationResponse(DataResponse[KeyRotationResult]):
    """Key rotation response"""
    pass