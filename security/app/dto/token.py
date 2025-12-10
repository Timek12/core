from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, TypedDict
import uuid
from datetime import datetime, timezone

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
    """Public JWT token schema."""
    jti: uuid.UUID
    expires_at: datetime
    revoked: bool
    device_info: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    
class TokenPayload(TypedDict):
    user_id: str
    email: str
    roles: list[str]
    token_type: TokenType
    exp: Optional[int]
    iat: Optional[int]
    
    @property
    def is_expired(self) -> bool:
        if self.exp is None:
            return False
        return datetime.fromtimestamp(self.exp, tz=timezone.utc) < datetime.now(timezone.utc)
    
@dataclass
class UserInfo:
    """Represents authenticated user"""    
    user_id: str
    email: str
    roles: list[str]
    
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
    token_type_hint: Optional[TokenType] = None


# Session DTOs
class SessionInfo(BaseModel):
    """Schema for session information."""
    jti: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime
    expires_at: datetime


class SessionsResponse(BaseModel):
    """Schema for sessions list response."""
    active_sessions: int
    sessions: list[SessionInfo]


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


class LogoutAllResponse(BaseModel):
    """Response for logout from all devices."""
    message: str
    revoked_tokens: int


class TokenVerificationResponse(BaseModel):
    """Response for token verification."""
    valid: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    expires_at: Optional[int] = None


class TokenVerificationError(Exception):
    """Base exception for token verification errors"""
    pass

class ExpiredTokenError(TokenVerificationError):
    """Token has expired"""
    pass

class InvalidTokenError(TokenVerificationError):
    """Token is invalid"""
    pass

# Import for forward reference
from app.dto.user import UserPublic
LoginResponse.model_rebuild()