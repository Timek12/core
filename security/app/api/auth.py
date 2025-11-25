from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.db import get_db
from app.services.auth_service import AuthService
from app.dto.user import UserCreate, UserPublic, LoginRequest
from app.dto.token import (
    TokenPair, LoginResponse, RefreshTokenRequest, 
    RefreshTokenResponse, TokenVerificationResponse
)
from app.dependencies import get_client_info, oauth2_scheme

router = APIRouter(prefix="/auth", tags=["authentication"])

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
