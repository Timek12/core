from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from sqlalchemy.orm import Session

from app.services.auth_service import AuthService
from app.dto.user import UserResponse, UserPublic
from app.dto.token import MessageResponse
from app.dependencies import require_admin, get_current_user, get_audit_logger, get_client_info, get_auth_service
from app.db.schema import UserRole
from app.clients.audit_logger import RedisAuditLogger

router = APIRouter(prefix="/auth", tags=["users"])

@router.get("/me", response_model=UserPublic)
def get_current_user_info(current_user: Annotated[UserResponse, Depends(get_current_user)]):
    """Get current authenticated user information."""
    return UserPublic.from_orm(current_user)


@router.get("/{user_id}/public", response_model=UserPublic)
def get_user_public(
    user_id: int,
    _current_user: Annotated[UserResponse, Depends(get_current_user)],
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get public user info by ID (accessible to all authenticated users)."""
    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    return UserPublic.from_orm(user)

# Admin-only endpoints

@router.get("/admin/users", response_model=list[UserResponse])
def list_all_users(
    _current_admin: Annotated[UserResponse, Depends(require_admin)],
    auth_service: AuthService = Depends(get_auth_service)
):
    """List all users."""
    users = auth_service.user_repo.find_all()
    return [UserResponse.from_orm(user) for user in users]


@router.put("/admin/users/{user_id}", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_update: dict,
    request: Request,
    background_tasks: BackgroundTasks,
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    auth_service: AuthService = Depends(get_auth_service),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger)
):
    """Update user role."""
    
    # Extract device info
    device_info, ip_address = get_client_info(request)

    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        background_tasks.add_task(
            audit_logger.log_event,
            action="update_role",
            status="failure",
            resource_type="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=device_info,
            details=f"User not found: {user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Validate role
    new_role = role_update.get("role")
    if new_role not in ["user", "admin"]:
        background_tasks.add_task(
            audit_logger.log_event,
            action="update_role",
            status="failure",
            resource_type="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Invalid role: {new_role}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be one of: user or admin"
        )
    
    # Prevent admin from removing their own admin role
    if user_id == current_admin.user_id and new_role != "admin":
        background_tasks.add_task(
            audit_logger.log_event,
            action="update_role",
            status="failure",
            resource_type="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=device_info,
            details="Admin attempted to remove own admin role"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin role"
        )
    
    # Update role
    old_role = user.role.value if hasattr(user.role, 'value') else str(user.role)
    user.role = UserRole(new_role)
    updated_user = auth_service.user_repo.save(user)
    
    # Audit Log Success
    background_tasks.add_task(
        audit_logger.log_event,
        action="update_role",
        status="success",
        user_id=str(current_admin.user_id),
        resource_type="user",
        resource_id=str(user_id),
        ip_address=ip_address,
        user_agent=device_info,
        details=f"Role updated from {old_role} to {new_role}"
    )

    return UserResponse.from_orm(updated_user)


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    background_tasks: BackgroundTasks,
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    auth_service: AuthService = Depends(get_auth_service),
    audit_logger: RedisAuditLogger = Depends(get_audit_logger)
):
    """Delete user."""
    
    # Extract device info
    device_info, ip_address = get_client_info(request)

    # Prevent admin from deleting themselves
    if user_id == current_admin.user_id:
        background_tasks.add_task(
            audit_logger.log_event,
            action="delete_user",
            status="failure",
            resource_type="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=device_info,
            details="Admin attempted to delete own account"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        background_tasks.add_task(
            audit_logger.log_event,
            action="delete_user",
            status="failure",
            resource_type="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=device_info,
            details=f"User not found: {user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    user_email = user.email
    auth_service.user_repo.delete(user)

    # Audit Log Success
    background_tasks.add_task(
        audit_logger.log_event,
        action="delete_user",
        status="success",
        user_id=str(current_admin.user_id),
        resource_type="user",
        resource_id=str(user_id),
        ip_address=ip_address,
        user_agent=device_info,
        details=f"User deleted: {user_email}"
    )

    return MessageResponse(message=f"User {user_id} deleted successfully")
