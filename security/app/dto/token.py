from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime


# OAuth Token DTOs
class OAuthTokenBase(BaseModel):
    """Base OAuth token schema."""
    user_id: int
    provider: str = Field(..., max_length=50)


class OAuthTokenCreate(OAuthTokenBase):
    """Schema for creating an OAuth refresh token."""
    refresh_token: str
    token_expires_at: Optional[datetime] = None


class OAuthTokenUpdate(BaseModel):
    """Schema for updating an OAuth refresh token."""
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None


class OAuthTokenResponse(OAuthTokenBase):
    """Schema for OAuth token response."""
    id: int
    refresh_token: str
    token_expires_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


# JWT Token DTOs
class JWTTokenBase(BaseModel):
    """Base JWT token schema."""
    user_id: int


class JWTTokenCreate(JWTTokenBase):
    """Schema for creating a JWT refresh token."""
    token_hash: str = Field(..., max_length=255)
    jti: uuid.UUID
    expires_at: datetime
    device_info: Optional[str] = None
    ip_address: Optional[str] = None


class JWTTokenUpdate(BaseModel):
    """Schema for updating a JWT refresh token."""
    revoked: Optional[bool] = None
    revoked_at: Optional[datetime] = None


class JWTTokenResponse(JWTTokenBase):
    """Schema for JWT token response."""
    id: int
    token_hash: str
    jti: uuid.UUID
    expires_at: datetime
    revoked: bool
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class JWTTokenPublic(BaseModel):
    """Public JWT token schema (safe for external use)."""
    jti: uuid.UUID
    expires_at: datetime
    revoked: bool
    device_info: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


# Authentication Response DTOs
class TokenPair(BaseModel):
    """Schema for access and refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class LoginResponse(BaseModel):
    """Schema for login response."""
    user: "UserPublic"
    tokens: TokenPair


class RefreshTokenRequest(BaseModel):
    """Schema for refresh token request."""
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    """Schema for refresh token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RevokeTokenRequest(BaseModel):
    """Schema for token revocation request."""
    token: str  # Can be access or refresh token
    token_type_hint: Optional[str] = None  # "access_token" or "refresh_token"


# Import for forward reference
from app.dto.user import UserPublic
LoginResponse.model_rebuild()