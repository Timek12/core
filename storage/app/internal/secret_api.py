from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import uuid

from app.db.db import get_db
from app.services.secret_service import SecretService
from app.dto.secret import SecretCreate, SecretUpdate, SecretResponse

router = APIRouter(prefix="/internal/secrets", tags=["secrets"])

@router.get("", response_model=List[SecretResponse])
def get_all_secrets(db: Session = Depends(get_db)):
    service = SecretService(db)
    return service.get_all_secrets()

@router.get("/{secret_id}", response_model=SecretResponse)
def get_secret(secret_id: uuid.UUID, db: Session = Depends(get_db)):
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
    db: Session = Depends(get_db)
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
def delete_secret(secret_id: uuid.UUID, db: Session = Depends(get_db)):
    service = SecretService(db)
    deleted = service.delete_secret(secret_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    