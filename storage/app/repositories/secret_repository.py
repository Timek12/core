from typing import List, Optional
from sqlalchemy.orm import Session
import uuid

from app.db.schema import Secrets

class SecretRepository:
    """Repository for Secret entity data access operations."""
    
    def __init__(self, db: Session):
        self.db = db

    def find_all(self) -> List[Secrets]:
        """Get all secrets."""
        return self.db.query(Secrets).all()
    
    def find_by_user_id(self, user_id: int) -> List[Secrets]:
        """Find all secrets for a specific user."""
        return self.db.query(Secrets).filter(Secrets.user_id == user_id).all()
    
    def find_by_id(self, secret_id: uuid.UUID) -> Optional[Secrets]:
        """Find secret by ID."""
        return self.db.query(Secrets).filter(Secrets.id == secret_id).first()
    
    def save(self, secret: Secrets) -> Secrets:
        """Save a new secret."""
        self.db.add(secret)
        self.db.commit()
        self.db.refresh(secret)
        return secret
    
    def update(self, secret: Secrets) -> Secrets:
        """Update existing secret."""
        self.db.add(secret)
        self.db.commit()
        self.db.refresh(secret)
        return secret
    
    def update(self, secret: Secrets) -> Secrets:
        self.db.commit()
        self.db.refresh(secret)
        return secret
    
    def delete(self, secret: Secrets) -> None:
        """Delete a secret."""
        self.db.delete(secret)
        self.db.commit()