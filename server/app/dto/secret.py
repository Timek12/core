from pydantic import BaseModel, Field, validator
from typing import Optional, List
import uuid
from datetime import datetime
from .common import BaseEntity, AuditInfo, DataResponse, PaginatedResponse

class SecretBase(BaseModel):
    """Base secret schema with validation"""
    name: str = Field(..., min_length=1, max_length=256, description="Secret name")
    description: str = Field(..., max_length=1000, description="Secret description")
    key_id: uuid.UUID = Field(..., description="Encryption key ID used for this secret")
    encrypted_value: str = Field(..., description="Encrypted secret value")
    version: int = Field(default=1, ge=1, description="Secret version for rotation")
    tags: Optional[List[str]] = Field(default=[], description="Tags for categorization")
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty or whitespace only')
        return v.strip()
    
    @validator('tags')
    def validate_tags(cls, v):
        if v is None:
            return []
        # Remove duplicates and empty tags
        return list(set([tag.strip() for tag in v if tag.strip()]))

class SecretCreate(SecretBase):
    """Schema for creating a secret"""
    user_id: Optional[str] = Field(None, description="User ID (set automatically from JWT)")

class SecretCreateRequest(BaseModel):
    """Schema for creating a secret from the frontend (before encryption)"""
    name: str = Field(..., min_length=1, max_length=256, description="Secret name")
    value: str = Field(..., min_length=1, description="Secret value (will be encrypted)")
    description: Optional[str] = Field("", max_length=1000, description="Secret description")
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty or whitespace only')
        return v.strip()
    
class SecretUpdateRequest(BaseModel):
    """Schema for updating a secret from the frontend (before encryption)"""
    name: Optional[str] = Field(None, min_length=1, max_length=256, description="Secret name")
    value: Optional[str] = Field(None, min_length=1, description="Secret value (will be encrypted)")
    description: Optional[str] = Field(None, max_length=1000, description="Secret description")
    
    @validator('name')
    def validate_name(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Name cannot be empty or whitespace only')
        return v.strip() if v else v

class SecretUpdate(BaseModel):
    """Schema for updating a secret (internal, after encryption)"""
    name: Optional[str] = Field(None, min_length=1, max_length=256, description="Secret name")
    description: Optional[str] = Field(None, max_length=1000, description="Secret description")
    key_id: Optional[uuid.UUID] = Field(None, description="Encryption key ID")
    dek_id: Optional[uuid.UUID] = Field(None, description="Data Encryption Key ID")
    encrypted_value: Optional[str] = Field(None, description="Encrypted secret value")
    version: Optional[int] = Field(None, ge=1, description="Secret version")
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")
    
    @validator('name')
    def validate_name(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Name cannot be empty or whitespace only')
        return v.strip() if v else v
    
    @validator('tags')
    def validate_tags(cls, v):
        if v is None:
            return None
        return list(set([tag.strip() for tag in v if tag.strip()]))

class SecretResponse(SecretBase):
    """Schema for secret response"""
    id: uuid.UUID = Field(..., description="Secret unique identifier")
    user_id: str = Field(..., description="Owner user ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    is_active: bool = Field(default=True, description="Whether secret is active")
    access_count: int = Field(default=0, description="Number of times accessed")
    last_accessed_at: Optional[datetime] = Field(None, description="Last access timestamp")
    
    class Config:
        from_attributes = True

class SecretListItem(BaseModel):
    """Minimal secret info for lists"""
    id: uuid.UUID = Field(..., description="Secret unique identifier")
    name: str = Field(..., description="Secret name")
    description: str = Field(..., description="Secret description")
    tags: List[str] = Field(default=[], description="Tags")
    version: int = Field(..., description="Secret version")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    is_active: bool = Field(..., description="Whether secret is active")

class SecretSearchRequest(BaseModel):
    """Search/filter request for secrets"""
    query: Optional[str] = Field(None, min_length=1, description="Search query")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")

# Response wrappers
class SecretDataResponse(DataResponse[SecretResponse]):
    """Single secret response"""
    pass

class SecretListResponse(PaginatedResponse[SecretListItem]):
    """Paginated secrets list response"""
    pass

class SecretBulkDeleteRequest(BaseModel):
    """Bulk delete request"""
    secret_ids: List[uuid.UUID] = Field(..., min_length=1, max_length=50, description="Secret IDs to delete")
    
class SecretStatsResponse(BaseModel):
    """Secret statistics response"""
    total_secrets: int = Field(..., description="Total number of secrets")
    active_secrets: int = Field(..., description="Number of active secrets")
    total_access_count: int = Field(..., description="Total access count across all secrets")
    most_accessed_secret: Optional[SecretListItem] = Field(None, description="Most accessed secret")
    recently_created: List[SecretListItem] = Field(default=[], description="Recently created secrets")