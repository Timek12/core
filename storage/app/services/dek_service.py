"""
Service for Data Encryption Key (DEK) operations
"""
from typing import Optional
import uuid
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.repositories.dek_repository import DEKRepository
from app.db.schema import DataEncryptionKeys


class DEKService:
    """Service for managing Data Encryption Keys"""

    def __init__(self, db: Session):
        self.repository = DEKRepository(db)

    def create_dek(self, encrypted_dek: str, nonce: str) -> DataEncryptionKeys:
        """
        Create a new DEK (already encrypted with master key)
        
        Args:
            encrypted_dek: The DEK encrypted with the master key (hex string)
            nonce: The nonce used for encryption (hex string)
        
        Returns:
            The created DEK record
        """
        dek = DataEncryptionKeys(
            id=uuid.uuid4(),
            encrypted_dek=encrypted_dek,
            nonce=nonce,
            version=1,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        
        return self.repository.save(dek)

    def get_dek(self, dek_id: uuid.UUID) -> Optional[DataEncryptionKeys]:
        """
        Get a DEK by ID
        
        Args:
            dek_id: The UUID of the DEK
        
        Returns:
            The DEK record or None if not found
        """
        return self.repository.find_by_id(dek_id)

    def rotate_dek(self, old_dek_id: uuid.UUID, new_encrypted_dek: str, new_nonce: str) -> DataEncryptionKeys:
        """
        Rotate a DEK (create new one and deactivate old one)
        
        Args:
            old_dek_id: The UUID of the DEK to rotate
            new_encrypted_dek: The new DEK encrypted with master key (hex string)
            new_nonce: The nonce used for new DEK encryption (hex string)
        
        Returns:
            The new DEK record
        """
        # Deactivate old DEK
        self.repository.deactivate(old_dek_id)
        
        # Create new DEK
        new_dek = DataEncryptionKeys(
            id=uuid.uuid4(),
            encrypted_dek=new_encrypted_dek,
            nonce=new_nonce,
            version=1,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            rotated_at=datetime.now(timezone.utc)
        )
        
        return self.repository.save(new_dek)

    def get_all_active_deks(self):
        """Get all active DEKs"""
        return self.repository.find_all_active()
