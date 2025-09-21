from typing import List
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
import uuid
from datetime import datetime

from models.dto.secret import Secret, SecretCreate, SecretUpdate
from services.secret_service import SecretService
from dependencies import get_db
from database import engine
from models.dao.secret import Base

# Create tables
Base.metadata.create_all(bind=engine)

api = FastAPI(title="LunaGuard Secrets API", version="1.0.0")

@api.get('/health')
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@api.get('/secrets', response_model=List[Secret])
def get_secrets(db: Session = Depends(get_db)):
    """Get all secrets."""
    service = SecretService(db)
    return service.get_all_secrets()

@api.get('/secrets/{secret_id}', response_model=Secret)
def get_secret(secret_id: str, db: Session = Depends(get_db)):
    """Get a secret by ID."""
    try:
        secret_uuid = uuid.UUID(secret_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    service = SecretService(db)
    secret = service.get_secret_by_id(secret_uuid)
    
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    return secret

@api.post('/secrets', response_model=Secret)
def create_secret(secret: SecretCreate, db: Session = Depends(get_db)):
    """Create a new secret."""
    service = SecretService(db)
    created_secret = service.create_secret(secret)
    
    if not created_secret:
        raise HTTPException(status_code=500, detail="Failed to create secret")
    
    return created_secret

@api.put('/secrets/{secret_id}', response_model=Secret)
def update_secret(secret_id: str, updated_secret: SecretUpdate, db: Session = Depends(get_db)):
    """Update an existing secret."""
    try:
        secret_uuid = uuid.UUID(secret_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    service = SecretService(db)
    secret = service.update_secret(secret_uuid, updated_secret)
    
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    return secret

@api.delete('/secrets/{secret_id}', response_model=Secret)
def delete_secret(secret_id: str, db: Session = Depends(get_db)):
    """Delete a secret by ID."""
    try:
        secret_uuid = uuid.UUID(secret_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    service = SecretService(db)
    secret = service.delete_secret(secret_uuid)
    
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    return secret 