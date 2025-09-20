from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import uuid
from datetime import datetime

from ..models.dao.secret import SecretDAO
from ..models.dto.secret import Secret, SecretCreate, SecretUpdate


class SecretService:
    def __init__(self, db: Session):
        self.db = db
    
    def get_all_secrets(self) -> List[Secret]:
        """Get all secrets from database."""
        try:
            dao_secrets = self.db.query(SecretDAO).all()
            return [self._dao_to_dto(dao_secret) for dao_secret in dao_secrets]
        except SQLAlchemyError:
            return []
    
    def get_secret_by_id(self, secret_id: uuid.UUID) -> Optional[Secret]:
        """Get a secret by ID."""
        try:
            dao_secret = self.db.query(SecretDAO).filter(SecretDAO.id == secret_id).first()
            return self._dao_to_dto(dao_secret) if dao_secret else None
        except SQLAlchemyError:
            return None
    
    def create_secret(self, secret_create: SecretCreate) -> Optional[Secret]:
        """Create a new secret."""
        try:
            dao_secret = SecretDAO(
                name=secret_create.name,
                description=secret_create.description,
                key_id=secret_create.key_id,
                encrypted_value=secret_create.encrypted_value,
                version=secret_create.version,
                created_at=secret_create.created_at,
                updated_at=secret_create.updated_at
            )
            
            self.db.add(dao_secret)
            self.db.commit()
            self.db.refresh(dao_secret)
            
            return self._dao_to_dto(dao_secret)
        except SQLAlchemyError:
            self.db.rollback()
            return None
    
    def update_secret(self, secret_id: uuid.UUID, secret_update: SecretUpdate) -> Optional[Secret]:
        """Update an existing secret."""
        try:
            dao_secret = self.db.query(SecretDAO).filter(SecretDAO.id == secret_id).first()
            if not dao_secret:
                return None
            
            # Update only provided fields
            if secret_update.name is not None:
                dao_secret.name = secret_update.name
            if secret_update.description is not None:
                dao_secret.description = secret_update.description
            if secret_update.key_id is not None:
                dao_secret.key_id = secret_update.key_id
            if secret_update.encrypted_value is not None:
                dao_secret.encrypted_value = secret_update.encrypted_value
            if secret_update.version is not None:
                dao_secret.version = secret_update.version
            
            dao_secret.updated_at = datetime.utcnow()
            
            self.db.commit()
            self.db.refresh(dao_secret)
            
            return self._dao_to_dto(dao_secret)
        except SQLAlchemyError:
            self.db.rollback()
            return None
    
    def delete_secret(self, secret_id: uuid.UUID) -> Optional[Secret]:
        """Delete a secret by ID."""
        try:
            dao_secret = self.db.query(SecretDAO).filter(SecretDAO.id == secret_id).first()
            if not dao_secret:
                return None
            
            deleted_secret = self._dao_to_dto(dao_secret)
            self.db.delete(dao_secret)
            self.db.commit()
            
            return deleted_secret
        except SQLAlchemyError:
            self.db.rollback()
            return None
    
    def _dao_to_dto(self, dao_secret: SecretDAO) -> Secret:
        """Convert DAO to DTO."""
        return Secret(
            id=dao_secret.id,
            name=dao_secret.name,
            description=dao_secret.description,
            key_id=dao_secret.key_id,
            encrypted_value=dao_secret.encrypted_value,
            version=dao_secret.version,
            created_at=dao_secret.created_at,
            updated_at=dao_secret.updated_at
        )
