from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.repositories.data_repository import DataRepository
from app.dto.data import DataInternalCreate, DataInternalUpdate
from app.utils.typed_data_helpers import parse_metadata_json, is_expired


class DataService:
    """Business logic for typed data stored in the storage service."""

    def __init__(self, data_repository: DataRepository):
        self.repository = data_repository

    @staticmethod
    def _ensure_uuid(value: Any) -> uuid.UUID:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))

    @staticmethod
    def _iso_datetime(value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    @staticmethod
    def _compute_expiration(ttl_seconds: Optional[int], expires_at: Optional[datetime]) -> Optional[datetime]:
        if expires_at is not None:
            return expires_at
        if ttl_seconds and ttl_seconds > 0:
            return datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        return None

    @staticmethod
    def _serialize(data_item) -> Dict[str, Any]:
        return {
            "id": str(data_item.id),
            "user_id": data_item.user_id,
            "name": data_item.name,
            "description": data_item.description,
            "data_type": data_item.data_type,
            "metadata": parse_metadata_json(data_item.metadata_json),
            "metadata_json": data_item.metadata_json,
            "ttl_seconds": data_item.ttl_seconds,
            "expires_at": DataService._iso_datetime(data_item.expires_at),
            "version": data_item.version if data_item.version is not None else 1,
            "is_active": data_item.is_active,
            "created_at": DataService._iso_datetime(data_item.created_at),
            "updated_at": DataService._iso_datetime(data_item.updated_at),
            "encrypted_value": data_item.encrypted_value,
            "dek_id": str(data_item.dek_id),
        }

    def create_data(self, user_id: int, payload: DataInternalCreate) -> Dict[str, Any]:
        expires_at = self._compute_expiration(payload.ttl_seconds, payload.expires_at)
        create_payload = payload.copy(update={"expires_at": expires_at})
        data_item = self.repository.create_data(user_id, create_payload)
        return self._serialize(data_item)

    def get_data(self, data_id: uuid.UUID, user_id: int) -> Optional[Dict[str, Any]]:
        data_item = self.repository.get_data_for_user(data_id, user_id)
        if not data_item or is_expired(data_item.expires_at):
            return None
        return self._serialize(data_item)

    def list_data(self, user_id: int, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        data_list = self.repository.list_data_for_user(user_id, data_type)
        return [self._serialize(data_item) for data_item in data_list if not is_expired(data_item.expires_at)]

    def update_data(
        self,
        data_id: uuid.UUID,
        user_id: int,
        payload: DataInternalUpdate,
    ) -> Optional[Dict[str, Any]]:
        data_item = self.repository.get_data_for_user(data_id, user_id)
        if not data_item:
            return None

        expires_at = self._compute_expiration(payload.ttl_seconds, payload.expires_at)
        update_payload = payload.copy(update={"expires_at": expires_at})
        updated = self.repository.update_data(data_item, update_payload)
        return self._serialize(updated)

    def delete_data(self, data_id: uuid.UUID, user_id: int) -> bool:
        data_item = self.repository.get_data_for_user(data_id, user_id)
        if not data_item:
            return False
        self.repository.delete_data_for_user(data_item)
        return True

    # Admin operations

    def get_all_data_admin(self, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        data_list = self.repository.list_all_data(data_type)
        return [self._serialize(data_item) for data_item in data_list]

    def get_data_for_user_admin(
        self, user_id: int, data_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        data_list = self.repository.list_data_for_user_admin(user_id, data_type)
        return [self._serialize(data_item) for data_item in data_list]

    def delete_data_admin(self, data_id: uuid.UUID) -> bool:
        data_item = self.repository.get_by_id(data_id)
        if not data_item:
            return False
        self.repository.delete_data_admin(data_item)
        return True
