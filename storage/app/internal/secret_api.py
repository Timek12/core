from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import uuid

from app.db.db import get_db
from app.services.secret_service import SecretService
from app.dto.secret import SecretCreate, SecretUpdate, SecretResponse
from app.utils.jwt_utils import get_current_user

router = APIRouter(prefix="/internal/secrets", tags=["secrets"])

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import uuid

from app.db.db import get_db
from app.services.secret_service import SecretService
from app.dto.secret import SecretCreate, SecretUpdate, SecretResponse
from app.utils.jwt_utils import get_current_user, UserInfo

router = APIRouter(prefix="/internal/secrets", tags=["secrets"])

@router.get("", response_model=List[SecretResponse])
def get_all_secrets(
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Get all secrets for authenticated user"""
    service = SecretService(db)
    # Filter by user_id from JWT token
    return service.get_secrets_by_user_id(current_user.user_id)

@router.get("/{secret_id}", response_model=SecretResponse)
def get_secret(
    secret_id: uuid.UUID, 
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Get specific secret - validate ownership"""
    service = SecretService(db)
    secret = service.get_secret_by_id(secret_id)
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    # Validate ownership
    if str(secret.user_id) != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return secret

@router.post("", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
def create_secret(
    secret_data: SecretCreate, 
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Create secret for authenticated user"""
    service = SecretService(db)
    # Set user_id from JWT token
    secret_data.user_id = current_user.user_id
    return service.create_secret(secret_data)

@router.put("", response_model=SecretResponse)
def update_secret(
    secret_id: uuid.UUID,
    secret_data: SecretUpdate, 
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Update secret - validate ownership"""
    service = SecretService(db)
    
    # First check if secret exists and user owns it
    existing_secret = service.get_secret_by_id(secret_id)
    if not existing_secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    if str(existing_secret.user_id) != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    secret = service.update_secret(secret_id, secret_data)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    return secret

@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(
    secret_id: uuid.UUID, 
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Delete secret - validate ownership"""
    service = SecretService(db)
    
    # First check if secret exists and user owns it
    existing_secret = service.get_secret_by_id(secret_id)
    if not existing_secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    if str(existing_secret.user_id) != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    deleted = service.delete_secret(secret_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )

@router.get("/{secret_id}", response_model=SecretResponse)
def get_secret(secret_id: uuid.UUID, db: Session = Depends(get_db), _: dict = Depends(get_current_user)):
    service = SecretService(db)
    secret = service.get_secret_by_id(secret_id)
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    return secret

@router.post("", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
def create_secret(secret_data: SecretCreate, db: Session = Depends(get_db)):
    service = SecretService(db)
    return service.create_secret(secret_data)

@router.put("", response_model=SecretResponse)
def update_secret(
    secret_id: uuid.UUID,
    secret_data: SecretUpdate, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    service = SecretService(db)
    secret = service.update_secret(secret_id, secret_data)

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    return secret

@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(secret_id: uuid.UUID, db: Session = Depends(get_db),     current_user: dict = Depends(get_current_user)):
    service = SecretService(db)
    deleted = service.delete_secret(secret_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    