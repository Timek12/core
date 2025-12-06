from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    """Base user schema."""
    email: EmailStr
    name: Optional[str] = None


class LoginRequest(BaseModel):
    """Schema for user login - credentials in request body."""
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=255)


class UserCreate(BaseModel):
    """Schema for creating a user."""
    email: EmailStr
    name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=6, max_length=255)


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    password_hash: Optional[str] = Field(None, max_length=255)


class UserResponse(UserBase):
    """Schema for user response."""
    user_id: int
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
    role: str = Field(..., description="User role: user or admin")
    
    class Config:
        from_attributes = True