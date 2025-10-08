from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    auth_method: str = Field(default='local', max_length=50)
    provider: str = Field(default='local', max_length=50)


class UserCreate(BaseModel):
    """Schema for creating a user."""
    email: EmailStr
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    provider_user_id: Optional[str] = Field(None, max_length=255)
    auth_method: str = Field(default='local', max_length=50)
    provider: str = Field(default='local', max_length=50)
    password_hash: Optional[str] = Field(None, max_length=255)
    email_verified: bool = Field(default=False)


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    provider_user_id: Optional[str] = Field(None, max_length=255)
    password_hash: Optional[str] = Field(None, max_length=255)
    email_verified: Optional[bool] = None


class UserResponse(UserBase):
    """Schema for user response."""
    user_id: int
    provider_user_id: Optional[str] = None
    email_verified: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True  # Pydantic v2


class UserPublic(BaseModel):
    """Public user schema (limited fields for external use)."""
    user_id: int
    email: EmailStr
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    provider: str
    
    class Config:
        from_attributes = True