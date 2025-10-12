import jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Callable
import os

from core.server.app.dto.token import ExpiredTokenError, InvalidTokenError, TokenError, TokenPayload, TokenType, UserInfo, UserRole
from core.storage.app.dto.token import TokenAlgorithm

class JWTValidator:
    """Handles JWT validation"""
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = TokenAlgorithm.HS256):
        self.secret_key = secret_key or os.getenv("JWT_SECRET_KEY")
        self.algorithm = algorithm
        
    def verify_token(self, token: str) -> TokenPayload:
        """Verify JWT token and return typed payload"""
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
        except ValueError as e:  # TokenType enum conversion failed
            raise InvalidTokenError(f"Invalid token payload: {str(e)}") from e


jwt_validator = JWTValidator()
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserInfo:
    try:
        payload = jwt_validator.verify_token(credentials.credentials)
    
        return UserInfo(
            user_id=payload.user_id,
            email=payload.email,
            roles=payload.roles
        )
    except TokenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    
# Factory pattern

def require_role(required_role: str) -> Callable:
    """Creates a dependency that checks for required role."""
    async def role_checker(
        current_user: UserInfo = Depends(get_current_user)
    ) -> UserInfo:
        if required_role not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required"
            )
        return current_user
    
    return role_checker

def require_roles(required_roles: list[str]) -> Callable:
    """Creates a dependency that checks for required role."""
    async def role_checker(
        current_user: UserInfo = Depends(get_current_user)
    ) -> UserInfo:
        if not any(role in current_user.roles for role in required_roles):
            roles_str = ", ".join(required_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of roles [{roles_str}] required"
            )
        return current_user
    
    return role_checker

def get_admin_user(
    current_user: UserInfo = Depends(require_role(UserRole.ADMIN))
) -> UserInfo:
    """
    Nested dependency
    Depends on require_role, which depends on get_current_user
    Chain: get_admin_user -> require_role(admin) -> get_current_user -> security
    When using this in route, all dependencies execute automatically
    """
    
    return current_user