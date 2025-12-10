from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from app.services.auth_service import AuthService
from app.dto.user import UserCreate, UserPublic, LoginRequest, UserResponse
from app.dto.token import (
    TokenPair, LoginResponse, RefreshTokenRequest, 
    RefreshTokenResponse, TokenVerificationResponse,
    RevokeTokenRequest, MessageResponse
)
from app.dependencies import get_client_info, oauth2_scheme, get_audit_logger, get_current_user, get_auth_service
from app.clients.audit_logger import RedisAuditLogger
from app.dto.client_info import ClientInfo

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def register(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    client_info: ClientInfo = Depends(get_client_info),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger),
    auth_service: AuthService = Depends(get_auth_service)
):
    """ Register a new user based on email password and name."""

    try:
        user = auth_service.create_user(user_data)

        tokens = auth_service.create_token_pair(
            user, client_info.device_info, client_info.ip_address)
            
        # Audit Log
        background_tasks.add_task(
            audit_logger.log_event,
            action="register",
            status="success",
            user_id=str(user.user_id),
            resource_type="user",
            resource_id=str(user.user_id),
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"User registered: {user.email}"
        )

        return LoginResponse(
            user=UserPublic.from_orm(user),
            tokens=tokens
        )
    except ValueError as e:
        # Audit Log Failure
        background_tasks.add_task(
            audit_logger.log_event,
            action="register",
            status="failure",
            resource_type="user",
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Registration failed: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=LoginResponse)
def login(
    credentials: LoginRequest,
    background_tasks: BackgroundTasks,
    client_info: ClientInfo = Depends(get_client_info),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Login user based on email and password."""

    # Authenticate
    user = auth_service.authenticate_user(credentials.email, credentials.password)
    if not user:
        # Audit Log Failure
        background_tasks.add_task(
            audit_logger.log_event,
            action="login",
            status="failure",
            resource_type="user",
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Login failed for email: {credentials.email}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create token pair
    tokens = auth_service.create_token_pair(user, client_info.device_info, client_info.ip_address)
    
    # Audit Log Success
    background_tasks.add_task(
        audit_logger.log_event,
        action="login",
        status="success",
        user_id=str(user.user_id),
        resource_type="user",
        resource_id=str(user.user_id),
        ip_address=client_info.ip_address,
        user_agent=client_info.device_info,
        details="Login successful"
    )

    return LoginResponse(user=UserPublic.from_orm(user), tokens=tokens)


@router.post("/refresh", response_model=TokenPair)
def refresh_token(
    refresh_request: RefreshTokenRequest,
    client_info: ClientInfo = Depends(get_client_info),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh both access and refresh tokens."""

    token_pair = auth_service.refresh_token_pair(
        refresh_request.refresh_token, 
        device_info=client_info.device_info,
        ip_address=client_info.ip_address
    )
    
    if not token_pair:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    return token_pair


@router.post("/verify", response_model=TokenVerificationResponse)
def verify_token(
    token: Annotated[str, Depends(oauth2_scheme)],
    auth_service: AuthService = Depends(get_auth_service)
):
    """Verify if access token is valid."""

    payload = auth_service.verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return TokenVerificationResponse(
        valid=True,
        user_id=payload.get("user_id"),
        email=payload.get("email"),
        expires_at=payload.get("exp")
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    revoke_request: RevokeTokenRequest, 
    background_tasks: BackgroundTasks,
    current_user: Annotated[UserResponse, Depends(get_current_user)], 
    auth_service: AuthService = Depends(get_auth_service),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Logout by revoking refresh token."""

    success = auth_service.revoke_token(revoke_request.token)
    if not success:
        background_tasks.add_task(
            audit_logger.log_event,
            action="logout",
            status="failure",
            user_id=str(current_user.user_id),
            resource_type="session",
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details="Logout failed: Invalid token or already revoked"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or already revoked"
        )
    
    # Audit Log
    background_tasks.add_task(
        audit_logger.log_event,
        action="logout",
        status="success",
        user_id=str(current_user.user_id),
        resource_type="session",
        ip_address=client_info.ip_address,
        user_agent=client_info.device_info,
        details="User logged out"
    )

    return MessageResponse(message="Successfully logged out")
