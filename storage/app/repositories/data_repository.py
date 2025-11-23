from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional
import uuid

from sqlalchemy.orm import Session

from app.db.schema import Data
from app.dto.data import DataInternalCreate, DataInternalUpdate


class DataRepository:
    """Repository for data operations"""

    def __init__(self, db: Session):
        self.db = db

    def create_data(self, user_id: int, data: DataInternalCreate) -> Data:
        """Persist a new data for a user."""
        data_item = Data(
            user_id=user_id,
            name=data.name,
            description=data.description or "",
            data_type=data.data_type.value if hasattr(data.data_type, "value") else str(data.data_type),
            metadata_json=data.metadata_json,
            encrypted_value=data.encrypted_value,
            dek_id=uuid.UUID(str(data.dek_id)),
            ttl_seconds=data.ttl_seconds,
            expires_at=data.expires_at,
            is_active=True,
            version=1,
        )
        self.db.add(data_item)
        self.db.commit()
        self.db.refresh(data_item)
        return data_item

    def get_data_for_user(self, data_id: uuid.UUID, user_id: int) -> Optional[Data]:
        """Fetch a data that belongs to the given user."""
        return (
            self.db.query(Data)
            .filter(
                Data.id == data_id,
                Data.user_id == user_id,
                Data.is_active.is_(True),
            )
            .first()
        )

    def list_data_for_user(self, user_id: int, data_type: Optional[str] = None) -> List[Data]:
        """Return active data for a user, optionally filtered by type."""
        query = self.db.query(Data).filter(
            Data.user_id == user_id,
            Data.is_active.is_(True),
        )
        if data_type:
            query = query.filter(Data.data_type == data_type)
        return query.order_by(Data.created_at.desc()).all()

    def update_data(self, data_item: Data, data: DataInternalUpdate) -> Data:
        """Apply updates to a data record."""
        if data.name is not None:
            data_item.name = data.name
        if data.description is not None:
            data_item.description = data.description
        if data.data_type is not None:
            data_item.data_type = (
                data.data_type.value if hasattr(data.data_type, "value") else str(data.data_type)
            )
        if data.metadata_json is not None:
            data_item.metadata_json = data.metadata_json
        if data.encrypted_value is not None:
            data_item.encrypted_value = data.encrypted_value
        if data.dek_id is not None:
            data_item.dek_id = uuid.UUID(str(data.dek_id))
        if data.ttl_seconds is not None:
            data_item.ttl_seconds = data.ttl_seconds
        if data.expires_at is not None:
            data_item.expires_at = data.expires_at

        data_item.version = (data_item.version or 0) + 1
        data_item.updated_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(data_item)
        return data_item

    def delete_data_for_user(self, data_item: Data) -> None:
        """Soft delete a data owned by the authenticated user."""
        data_item.is_active = False
        data_item.updated_at = datetime.now(timezone.utc)
        self.db.commit()

    def delete_data_admin(self, data_item: Data) -> None:
        """Soft delete a data as an admin."""
        data_item.is_active = False
        data_item.updated_at = datetime.now(timezone.utc)
        self.db.commit()

    def list_all_data(self, data_type: Optional[str] = None) -> List[Data]:
        """Return all active data across users."""
        query = self.db.query(Data).filter(Data.is_active.is_(True))
        if data_type:
            query = query.filter(Data.data_type == data_type)
        return query.order_by(Data.created_at.desc()).all()

    def list_data_for_user_admin(
        self, user_id: int, data_type: Optional[str] = None
    ) -> List[Data]:
        """Return data for a specific user for admin operations."""
        query = self.db.query(Data).filter(
            Data.user_id == user_id,
            Data.is_active.is_(True),
        )
        if data_type:
            query = query.filter(Data.data_type == data_type)
        return query.order_by(Data.created_at.desc()).all()

    def get_by_id(self, data_id: uuid.UUID) -> Optional[Data]:
        """Fetch a data without user constraints."""
        return self.db.query(Data).filter(Data.id == data_id, Data.is_active.is_(True)).first()
