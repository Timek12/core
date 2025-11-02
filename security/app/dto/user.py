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


class LoginRequest(BaseModel):
    """Schema for user login - credentials in request body."""
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=255)


class UserCreate(BaseModel):
    """Schema for creating a user."""
    email: EmailStr
    name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=6, max_length=255)
    avatar_url: Optional[str] = None
    provider_user_id: Optional[str] = Field(None, max_length=255)
    auth_method: str = Field(default='local', max_length=50)
    provider: str = Field(default='local', max_length=50)
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
    role: str = Field(..., description="User role: user or admin")
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
    role: str = Field(..., description="User role: user or admin")
    
    class Config:
        from_attributes = True