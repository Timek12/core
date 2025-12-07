from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from typing import Callable

from app.db.db import get_db
from app.utils.jwt_utils import jwt_validator, security
from app.dto.token import UserInfo, TokenError, UserRole

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
