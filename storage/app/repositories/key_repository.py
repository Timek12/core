from typing import List, Optional
from sqlalchemy.orm import Session
import uuid
from app.db.schema import EncryptionKeys

class KeyRepository:
    """Repository for EncryptionKeys entity data access operations."""

    def __init__(self, db: Session):
        self.db = db

    def find_by_id(self, key_id: uuid.UUID) -> Optional[EncryptionKeys]:
        """Find key by ID."""
        return self.db.query(EncryptionKeys).filter(EncryptionKeys.id == key_id).first()
    
    def find_by_type(self, key_type: str) -> Optional[EncryptionKeys]:
        """Find the most recent active key by type."""
        return self.db.query(EncryptionKeys).filter(
            EncryptionKeys.key_type == key_type,
            EncryptionKeys.status == 'active'
        ).order_by(EncryptionKeys.id.desc()).first()
    
    def find_all_active(self, key_type: Optional[str] = None) -> List[EncryptionKeys]:
        """Find all active EncryptionKeys, optionally filtered by type."""
        query = self.db.query(EncryptionKeys).filter(EncryptionKeys.status == 'active')
        if key_type:
            query = query.filter(EncryptionKeys.key_type == key_type)
        return query.order_by(EncryptionKeys.created_at.desc()).all()
    
    def save(self, key: EncryptionKeys) -> EncryptionKeys:
        """Save a new key."""
        self.db.add(key)
        self.db.commit()
        self.db.refresh(key)
        return key
    
    def update(self, key: EncryptionKeys) -> EncryptionKeys:
        """Update existing key."""
        self.db.commit()
        self.db.refresh(key)
        return key
    