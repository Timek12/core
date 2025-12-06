from typing import Annotated
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.db.db import get_db
from app.services.auth_service import AuthService
from app.dto.user import UserResponse

# OAuth2 scheme for token authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Session = Depends(get_db)
) -> UserResponse:
    """Extract and validate user from access token."""
    auth_service = AuthService(db)

    user = auth_service.get_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return UserResponse.from_orm(user)
    

async def require_admin(
    current_user: Annotated[UserResponse, Depends(get_current_user)]
) -> UserResponse:
    """Require user to have admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def get_client_info(request: Request) -> tuple[str, str]:
    """Extract device info and IP address from request."""
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = request.client.host if request.client else "unknown"
    return user_agent, ip_address

def get_audit_logger() -> "RedisAuditLogger":
    """Get Redis audit logger"""
    from app.clients.audit_logger import RedisAuditLogger
    return RedisAuditLogger()

def get_auth_service(
    db: Session = Depends(get_db)
) -> AuthService:
    """Get AuthService instance with dependencies"""
    return AuthService(db)
