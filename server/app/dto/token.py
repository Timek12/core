from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, TypedDict
import uuid
from datetime import datetime, timezone

from fastapi import status

class TokenVerificationError(Exception):
    """Base exception for token verification errors"""
    pass

class ExpiredTokenError(TokenVerificationError):
    """Token has expired"""
    pass

class InvalidTokenError(TokenVerificationError):
    """Token is invalid (tampered, wrong signature, etc.)"""
    pass

class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
  
class TokenAlgorithm(str, Enum):
    HS256 = "HS256"
       
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    
@dataclass
class TokenPayload:
    user_id: str
    email: str
    roles: list[str]
    token_type: TokenType
    exp: Optional[int] = None
    iat: Optional[int] = None
    
    @property
    def is_expired(self) -> bool:
        if self.exp is None:
            return False
        return datetime.fromtimestamp(self.exp, tz=timezone.utc) < datetime.now(timezone.utc)
    
@dataclass
class UserInfo:
    user_id: str
    email: str
    roles: list[str]
    
class TokenError(Exception):
    def __init__(self, message: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)
        
class InalidTokenError(TokenError):
    def __init__(self, detail: str = "Invalid token"):
        super().__init__(detail, status.HTTP_401_UNAUTHORIZED)
        
class InsufficientPermissionsError(TokenError):
    """User doesn't have required permissions"""
    def __init__(self, required_role: str):
        super().__init__(
            f"Role '{required_role}' required",
            status.HTTP_403_FORBIDDEN
        )
