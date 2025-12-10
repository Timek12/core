from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Callable
from dataclasses import dataclass

from app.clients.storage_client import StorageClient
from app.clients.security_client import SecurityClient
from app.utils.jwt_utils import JWTValidator
from app.dto.token import TokenError, UserInfo, UserRole
from app.dto.client_info import ClientInfo

security = HTTPBearer()
jwt_validator = JWTValidator()

def get_storage_client(request: Request) -> StorageClient:
    """Dependency to get StorageClient with shared HTTP client"""
    return StorageClient(client=request.app.state.http_client)

def get_security_client(request: Request) -> SecurityClient:
    """Dependency to get SecurityClient with shared HTTP client"""
    return SecurityClient(client=request.app.state.http_client)

def get_client_info(request: Request) -> ClientInfo:
    """Extract device info and IP address from request."""
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = request.client.host if request.client else "unknown"
    return ClientInfo(device_info=user_agent, ip_address=ip_address)

def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""

async def get_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Get the raw JWT token string"""
    return credentials.credentials

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