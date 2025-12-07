import jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import os

from app.dto.token import (
    ExpiredTokenError,
    InvalidTokenError,
    TokenAlgorithm,
    TokenError,
    TokenPayload,
    TokenType,
    UserInfo,
    UserRole,
)
        
class JWTValidator:
    """Handles JWT validation"""
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = TokenAlgorithm.HS256):
        self.secret_key = secret_key or os.getenv("JWT_SECRET_KEY")
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY must be set")
        self.algorithm = algorithm
        
    def verify_token(self, token: str) -> TokenPayload:
        """Verify JWT token and return typed payload"""
        if not self.secret_key:
             raise ValueError("JWT_SECRET_KEY must be set")
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            token_payload = TokenPayload(
                user_id=payload.get("sub"),
                email=payload.get("email"),
                roles=payload.get("roles", []),
                token_type=TokenType(payload.get("type", "access")),
                exp=payload.get("exp"),
                iat=payload.get("iat")
            )
            
            if token_payload.token_type != TokenType.ACCESS:
                raise InvalidTokenError("Token is not an access token")
            
            return token_payload
        except jwt.ExpiredSignatureError as e:
            raise ExpiredTokenError() from e
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Token verification failed: {str(e)}") from e
        except ValueError as e:
            raise InvalidTokenError(f"Invalid token payload: {str(e)}") from e


jwt_validator = JWTValidator()
security = HTTPBearer()


