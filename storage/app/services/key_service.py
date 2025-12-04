from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid

from app.repositories.key_repository import KeyRepository
from app.dto.key import KeyCreate, KeyResponse
from app.db.schema import EncryptionKeys

class KeyService:
    def __init__(self, db: Session):
        self.repository = KeyRepository(db)

    def get_key_by_id(self, key_id: uuid.UUID) -> Optional[KeyResponse]:
        key = self.repository.find_by_id(key_id)
        return KeyResponse.from_orm(key) if key else None
    
    def get_key_by_type(self, key_type: str) -> Optional[KeyResponse]:
        key = self.repository.find_by_type(key_type)
        return KeyResponse.from_orm(key) if key else None
    
    def create_key(self, key_data: KeyCreate) -> KeyResponse:
        key = EncryptionKeys(
            key_type=key_data.key_type,
            encrypted_key=key_data.encrypted_key,
            nonce=key_data.nonce,
            version=key_data.version,
            meta=key_data.meta,
            created_at=datetime.now(timezone.utc)
        )

        saved_key = self.repository.save(key)
        return KeyResponse.from_orm(saved_key)
    
    def deactivate_key(self, key_id: uuid.UUID) -> Optional[KeyResponse]:
        key = self.repository.find_by_id(key_id)
        if not key:
            return None
        
        key.status = 'deactivated'
        updated_key = self.repository.update(key)
        return KeyResponse.from_orm(updated_key) if updated_key else None
    
