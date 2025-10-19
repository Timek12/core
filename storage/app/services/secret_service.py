from typing import List, Optional
from sqlalchemy.orm import Session
import uuid
from datetime import datetime, timezone

from app.repositories.secret_repository import SecretRepository
from app.dto.secret import SecretCreate, SecretUpdate, SecretResponse
from app.db.schema import Secrets

class SecretService:
    """Service for secret business logic."""

    def __init__(self, db: Session):
        self.repository = SecretRepository(db)
    
    def get_all_secrets(self) -> List[SecretResponse]:
        secrets = self.repository.find_all()
        return [SecretResponse.from_orm(secret) for secret in secrets]
    
    def get_secrets_by_user_id(self, user_id: int) -> List[SecretResponse]:
        """Get all secrets for a specific user"""
        secrets = self.repository.find_by_user_id(user_id)
        return [SecretResponse.from_orm(secret) for secret in secrets]

    def get_secret_by_id(self, secret_id: uuid.UUID) -> Optional[SecretResponse]:
        secret = self.repository.find_by_id(secret_id)
        return SecretResponse.from_orm(secret) if secret else None
    
    def create_secret(self, secret_data: SecretCreate) -> SecretResponse:
        secret = Secrets(
            id=uuid.uuid4(),
            user_id=secret_data.user_id,
            name=secret_data.name, 
            description=secret_data.description,
            key_id=secret_data.key_id,
            encrypted_value=secret_data.encrypted_value,
            version=secret_data.version,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        saved_secret = self.repository.save(secret)
        return SecretResponse.from_orm(saved_secret)
    
    def update_secret(self, secret_id: uuid.UUID, secret_data: SecretUpdate) -> Optional[SecretResponse]:
        secret = self.repository.find_by_id(secret_id)
        if not secret:
            return None
        
        # Use dict() for Pydantic v1 compatibility
        update_dict = dict(secret_data)
        for field, value in update_dict.items():
            if value is not None:
                setattr(secret, field, value)

        secret.updated_at = datetime.now(timezone.utc)

        updated_secret = self.repository.update(secret)
        return SecretResponse.from_orm(updated_secret)
    
    def delete_secret(self, secret_id: uuid.UUID) -> bool:
        secret = self.repository.find_by_id(secret_id)
        if not secret:
            return False
        
        self.repository.delete(secret)
        return True