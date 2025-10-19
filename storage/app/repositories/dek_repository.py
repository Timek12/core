"""
Repository for Data Encryption Keys (DEKs)
"""
from typing import List, Optional
import uuid
from sqlalchemy.orm import Session

from app.db.schema import DataEncryptionKeys


class DEKRepository:
    """Repository for DEK operations"""

    def __init__(self, db: Session):
        self.db = db

    def find_by_id(self, dek_id: uuid.UUID) -> Optional[DataEncryptionKeys]:
        """Find DEK by ID"""
        return self.db.query(DataEncryptionKeys).filter(
            DataEncryptionKeys.id == dek_id
        ).first()

    def find_all_active(self) -> List[DataEncryptionKeys]:
        """Find all active DEKs"""
        return self.db.query(DataEncryptionKeys).filter(
            DataEncryptionKeys.is_active == True
        ).order_by(DataEncryptionKeys.created_at.desc()).all()

    def save(self, dek: DataEncryptionKeys) -> DataEncryptionKeys:
        """Save a new DEK"""
        self.db.add(dek)
        self.db.commit()
        self.db.refresh(dek)
        return dek

    def update(self, dek: DataEncryptionKeys) -> DataEncryptionKeys:
        """Update an existing DEK"""
        self.db.commit()
        self.db.refresh(dek)
        return dek

    def deactivate(self, dek_id: uuid.UUID) -> bool:
        """Deactivate a DEK (for key rotation)"""
        dek = self.find_by_id(dek_id)
        if not dek:
            return False
        
        dek.is_active = False
        self.db.commit()
        return True
