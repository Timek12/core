from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.db import get_db
from app.services.auth_service import AuthService
from app.dto.user import UserCreate, UserResponse, UserPublic, LoginRequest
from app.dto.token import (
    TokenPair, LoginResponse, RefreshTokenRequest, 
    RefreshTokenResponse, RevokeTokenRequest, SessionsResponse,
    MessageResponse, LogoutAllResponse, TokenVerificationResponse, SessionInfo
)

router = APIRouter(prefix="/auth", tags=["authentication"])

# OAuth2 scheme for token authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Dependency to get current user from  access token

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


async def get_current_active_user(
    current_user: Annotated[UserResponse, Depends(get_current_user)]
) -> UserResponse:
    """Ensure user is active"""
    if not current_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )

    return current_user


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

# Public endpoints

@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def register(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """ Register a new user based on email password and name."""
    auth_service = AuthService(db)

    try:
        user = auth_service.create_user(user_data)

        device_info, ip_address = get_client_info(request)

        user_entity = auth_service.user_repo.find_by_id(user.user_id)
        tokens = auth_service.create_token_pair(
            user_entity, device_info, ip_address)

        return LoginResponse(
            user=UserPublic.from_orm(user_entity),
            tokens=tokens
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/token", response_model=TokenPair)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    request: Request,
    db: Session = Depends(get_db)
):
    """OAuth2 compatible token login."""

    auth_service = AuthService(db)

    # Authenticate user (email and password)
    user = auth_service.authenticate_user(
        form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get client info
    device_info, ip_address = get_client_info(request)

    # Create token pair
    tokens = auth_service.create_token_pair(user, device_info, ip_address)

    return tokens


@router.post("/login", response_model=LoginResponse)
def login_json(
    credentials: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """JSON login endpoint - accepts email/password in request body"""

    auth_service = AuthService(db)

    # Authenticate
    user = auth_service.authenticate_user(credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get client info
    device_info, ip_address = get_client_info(request)

    # Create token pair
    tokens = auth_service.create_token_pair(user, device_info, ip_address)

    return LoginResponse(user=UserPublic.from_orm(user), tokens=tokens)


@router.post("/refresh", response_model=RefreshTokenResponse)
def refresh_token(refresh_request: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh access token using refresh token (returns only access token)."""

    auth_service = AuthService(db)

    try:
        access_token = auth_service.refresh_access_token(
            refresh_request.refresh_token)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

        return RefreshTokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_service.access_token_expire_minutes * 60
        )
    except HTTPException:
        raise
    except Exception as e:
        # Log the error and return a proper JSON response
        print(f"Error in refresh endpoint: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error during token refresh: {str(e)}"
        )

@router.post("/refresh-pair", response_model=TokenPair)
def refresh_token_pair(refresh_request: RefreshTokenRequest, request: Request, db: Session = Depends(get_db)):
    """Refresh both access and refresh tokens."""

    auth_service = AuthService(db)
    
    # Extract device info
    device_info = request.headers.get("User-Agent", "Unknown")
    ip_address = request.client.host if request.client else "Unknown"

    token_pair = auth_service.refresh_token_pair(
        refresh_request.refresh_token, 
        device_info=device_info,
        ip_address=ip_address
    )
    
    if not token_pair:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    return token_pair

# Protected endpoints


@router.get("/me", response_model=UserPublic)
def get_current_user_info(current_user: Annotated[UserResponse, Depends(get_current_active_user)]):
    """Get current authenticated user information."""
    return UserPublic.from_orm(current_user)


@router.post("/logout", response_model=MessageResponse)
def logout(revoke_request: RevokeTokenRequest, _: Annotated[UserResponse, Depends(get_current_user)], db: Session = Depends(get_db)):
    """Logout by revoking refresh token."""

    auth_service = AuthService(db)

    success = auth_service.revoke_token(revoke_request.token)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or already revoked"
        )

    return MessageResponse(message="Successfully logged out")


@router.post("/logout-all", response_model=LogoutAllResponse)
def logout_all_devices(current_user: Annotated[UserResponse, Depends(get_current_active_user)], db: Session = Depends(get_db)):
    """Logout from all devices by revoking all user's refresh tokens."""

    auth_service = AuthService(db)

    count = auth_service.revoke_all_user_tokens(current_user.user_id)

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
    current_user: Annotated[UserResponse, Depends(get_current_active_user)],
    db: Session = Depends(get_db)
):
    """Revoke a specific session by JTI."""

    import uuid

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

    return MessageResponse(message="Session revoked successfully")


@router.post("/verify", response_model=TokenVerificationResponse)
def verify_token(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
):
    """Verify if access token is valid."""

    auth_service = AuthService(db)

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
