from typing import Optional
import uuid
from sqlalchemy.orm import Session

from app.db.schema import EncryptionKeys

class DEKRepository:
    """Repository for DEK operations using EncryptionKeys table"""

    def __init__(self, db: Session):
        self.db = db

    def find_by_id(self, dek_id: uuid.UUID) -> Optional[EncryptionKeys]:
        """Find DEK by ID"""
        return self.db.query(EncryptionKeys).filter(
            EncryptionKeys.id == dek_id,
            EncryptionKeys.key_type == 'dek'
        ).first()

    def save(self, dek: EncryptionKeys) -> EncryptionKeys:
        """Save a new DEK"""
        self.db.add(dek)
        self.db.commit()
        self.db.refresh(dek)
        return dek

    def update(self, dek: EncryptionKeys) -> EncryptionKeys:
        """Update an existing DEK"""
        self.db.commit()
        self.db.refresh(dek)
        return dek

    def deactivate(self, dek_id: uuid.UUID) -> bool:
        """Deactivate a DEK (for key rotation)"""
        dek = self.find_by_id(dek_id)
        if not dek:
            return False
        
        dek.status = 'rotated'
        self.db.commit()
        return True
