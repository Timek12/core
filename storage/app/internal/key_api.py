from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import uuid

from app.db.db import get_db
from app.services.key_service import KeyService
from app.dto.key import KeyCreate, KeyResponse
from app.utils.jwt_utils import get_current_user, UserInfo, require_role

router = APIRouter(prefix="/internal/keys", tags=["keys"])

@router.get("/{key_id}", response_model=KeyResponse)
def get_key_by_id(
    key_id: uuid.UUID, 
    db: Session = Depends(get_db),
    _: UserInfo = Depends(get_current_user)
):
    """Get key by ID - requires authentication"""
    service = KeyService(db)
    key = service.get_key_by_id(key_id)

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found"
        )
    
    return key

@router.get("/type/{key_type}", response_model=KeyResponse)
def get_key_by_type(
    key_type: str, 
    db: Session = Depends(get_db),
    _: UserInfo = Depends(get_current_user)
):
    """Get key by type - requires authentication"""
    service = KeyService(db)
    key = service.get_key_by_type(key_type)

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found"
        )
    
    return key


@router.post("", response_model=KeyResponse, status_code=status.HTTP_201_CREATED)
def create_key(
    key_data: KeyCreate, 
    db: Session = Depends(get_db),
    _: UserInfo = Depends(require_role("admin"))
):
    """Create key - requires admin role"""
    service = KeyService(db)
    return service.create_key(key_data)

@router.patch("/{key_id}/deactivate", response_model=KeyResponse)
def deactivate_key(
    key_id: uuid.UUID, 
    db: Session = Depends(get_db),
    _: UserInfo = Depends(require_role("admin"))
):
    """Deactivate key - requires admin role"""
    service = KeyService(db)
    key = service.deactivate_key(key_id)

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found"
        )
    
    return key