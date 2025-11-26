from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
import uuid

from app.db.db import get_db
from app.services.auth_service import AuthService
from app.dto.user import UserResponse
from app.dto.token import (
    MessageResponse, LogoutAllResponse, SessionsResponse, 
    SessionInfo, RevokeTokenRequest
)
from app.dependencies import get_current_active_user, get_current_user, get_audit_logger, get_client_info
from app.clients.audit_logger import RedisAuditLogger

router = APIRouter(prefix="/auth", tags=["sessions"])

@router.post("/logout", response_model=MessageResponse)
def logout(
    revoke_request: RevokeTokenRequest, 
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[UserResponse, Depends(get_current_user)], 
    db: Session = Depends(get_db),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger)
):
    """Logout by revoking refresh token."""

    auth_service = AuthService(db)

    success = auth_service.revoke_token(revoke_request.refresh_token)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or already revoked"
        )
    
    # Audit Log
    device_info, ip_address = get_client_info(request)
    background_tasks.add_task(
        audit_logger.log_event,
        action="logout",
        status="success",
        user_id=str(current_user.user_id),
        resource_type="session",
        ip_address=ip_address,
        user_agent=device_info,
        details="User logged out"
    )

    return MessageResponse(message="Successfully logged out")


@router.post("/logout-all", response_model=LogoutAllResponse)
def logout_all_devices(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[UserResponse, Depends(get_current_active_user)], 
    db: Session = Depends(get_db),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger)
):
    """Logout from all devices by revoking all user's refresh tokens."""

    auth_service = AuthService(db)

    count = auth_service.revoke_all_user_tokens(current_user.user_id)
    
    # Audit Log
    device_info, ip_address = get_client_info(request)
    background_tasks.add_task(
        audit_logger.log_event,
        action="logout_all",
        status="success",
        user_id=str(current_user.user_id),
        resource_type="session",
        ip_address=ip_address,
        user_agent=device_info,
        details=f"Logged out from all devices. Revoked {count} tokens."
    )

    return LogoutAllResponse(
        message="Successfully logged out from all devices",
        revoked_tokens=count
    )


@router.get("/sessions", response_model=SessionsResponse)
def get_active_sessions(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)],
    db: Session = Depends(get_db)
):
    """Get all active sessions (refresh tokens) for current user."""

    auth_service = AuthService(db)

    sessions = auth_service.jwt_repo.find_active_by_user_id(
        current_user.user_id)

    return SessionsResponse(
        active_sessions=len(sessions),
        sessions=[
            SessionInfo(
                jti=str(session.jti),
                device_info=session.device_info,
                ip_address=str(session.ip_address) if session.ip_address else None,
                created_at=session.created_at,
                expires_at=session.expires_at
            )
            for session in sessions
        ]
    )


@router.delete("/sessions/{jti}", response_model=MessageResponse)
def revoke_session(
    jti: str,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[UserResponse, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger)
):
    """Revoke a specific session by JTI."""

    auth_service = AuthService(db)

    try:
        jti_uuid = uuid.UUID(jti)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JTI format"
        )

    # Verify the session belongs to current user
    token = auth_service.jwt_repo.find_by_jti(jti_uuid)
    if not token or token.user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    success = auth_service.jwt_repo.revoke_token(jti_uuid)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to revoke session"
        )
    
    # Audit Log
    device_info, ip_address = get_client_info(request)
    background_tasks.add_task(
        audit_logger.log_event,
        action="revoke_session",
        status="success",
        user_id=str(current_user.user_id),
        resource_type="session",
        resource_id=str(jti),
        ip_address=ip_address,
        user_agent=device_info,
        details="Session revoked"
    )

    return MessageResponse(message="Session revoked successfully")
