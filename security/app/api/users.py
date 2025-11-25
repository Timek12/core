from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.db import get_db
from app.services.auth_service import AuthService
from app.dto.user import UserResponse, UserPublic
from app.dto.token import MessageResponse
from app.dependencies import get_current_active_user, require_admin, get_current_user

router = APIRouter(prefix="/auth", tags=["users"])

@router.get("/me", response_model=UserPublic)
def get_current_user_info(current_user: Annotated[UserResponse, Depends(get_current_active_user)]):
    """Get current authenticated user information."""
    return UserPublic.from_orm(current_user)


# Admin-only endpoints

@router.get("/admin/users", response_model=list[UserResponse])
def list_all_users(
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    db: Session = Depends(get_db)
):
    """List all users."""
    auth_service = AuthService(db)
    users = auth_service.user_repo.find_all()
    return [UserResponse.from_orm(user) for user in users]


@router.get("/admin/users/{user_id}", response_model=UserResponse)
def get_user_by_id(
    user_id: int,
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    db: Session = Depends(get_db)
):
    """Get user by ID."""
    auth_service = AuthService(db)
    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    return UserResponse.from_orm(user)


@router.put("/admin/users/{user_id}", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_update: dict,
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    db: Session = Depends(get_db)
):
    """Update user role."""
    auth_service = AuthService(db)
    
    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Validate role
    new_role = role_update.get("role")
    if new_role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be one of: user or admin"
        )
    
    # Prevent admin from removing their own admin role
    if user_id == current_admin.user_id and new_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin role"
        )
    
    # Update role
    from app.db.schema import UserRole
    user.role = UserRole(new_role)
    updated_user = auth_service.user_repo.save(user)
    
    return UserResponse.from_orm(updated_user)


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    current_admin: Annotated[UserResponse, Depends(require_admin)],
    db: Session = Depends(get_db)
):
    """Delete user."""
    auth_service = AuthService(db)
    
    # Prevent admin from deleting themselves
    if user_id == current_admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = auth_service.user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    auth_service.user_repo.delete(user)

    return MessageResponse(message=f"User {user_id} deleted successfully")
