from typing import Optional
import uuid
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.repositories.key_repository import KeyRepository
from app.db.schema import EncryptionKeys


class DEKService:
    """Service for managing Data Encryption Keys"""

    def __init__(self, db: Session):
        self.repository = KeyRepository(db)

    def create_dek(self, encrypted_dek: str, nonce: str) -> EncryptionKeys:
        """Create a new DEK (already encrypted with KEK)"""
        dek = EncryptionKeys(
            id=uuid.uuid4(),
            key_type='dek',
            encrypted_key=encrypted_dek,
            nonce=nonce,
            version=1,
            status='active',
            created_at=datetime.now(timezone.utc)
        )
        
        return self.repository.save(dek)

    def get_dek(self, dek_id: uuid.UUID) -> Optional[EncryptionKeys]:
        """ Get a DEK by ID """
        return self.repository.find_by_id(dek_id)

    def rotate_dek(self, old_dek_id: uuid.UUID, new_encrypted_dek: str, new_nonce: str) -> EncryptionKeys:
        """ Rotate a DEK (create new one and deactivate old one) """
        # Deactivate old DEK
        self.repository.deactivate(old_dek_id)
        
        # Create new DEK
        new_dek = EncryptionKeys(
            id=uuid.uuid4(),
            key_type='dek',
            encrypted_key=new_encrypted_dek,
            nonce=new_nonce,
            version=1,
            status='active',
            created_at=datetime.now(timezone.utc)
        )
        
        return self.repository.save(new_dek)


