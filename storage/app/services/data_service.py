from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.repositories.data_repository import DataRepository
from app.dto.data import DataInternalCreate, DataInternalUpdate, DataVersionResponse, DataVersionListResponse
import json

def parse_metadata_json(metadata_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not metadata_json:
        return None
    try:
        return json.loads(metadata_json)
    except json.JSONDecodeError:
        return None

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
    def _serialize(data_item) -> Dict[str, Any]:
        return {
            "id": str(data_item.id),
            "user_id": data_item.user_id,
            "name": data_item.name,
            "description": data_item.description,
            "data_type": data_item.data_type,
            "metadata": parse_metadata_json(data_item.metadata_json),
            "metadata_json": data_item.metadata_json,
            "version": data_item.version if data_item.version is not None else 1,
            "is_active": data_item.is_active,
            "created_at": DataService._iso_datetime(data_item.created_at),
            "updated_at": DataService._iso_datetime(data_item.updated_at),
            "encrypted_value": data_item.encrypted_value,
            "dek_id": str(data_item.dek_id),
            "project_id": str(data_item.project_id) if data_item.project_id else None,
            "rotation_interval_days": data_item.rotation_interval_days,
            "next_rotation_date": DataService._iso_datetime(data_item.next_rotation_date),
        }

    @staticmethod
    def _serialize_version(version) -> DataVersionResponse:
        return DataVersionResponse(
            id=str(version.id),
            data_id=str(version.data_id),
            version=version.version,
            encrypted_value=version.encrypted_value,
            dek_id=str(version.dek_id),
            created_at=version.created_at,
            created_by=version.created_by
        )

    def create_data(self, user_id: int, payload: DataInternalCreate, project_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
        data_item = self.repository.create_data(user_id, payload, project_id)
        return self._serialize(data_item)

    def get_data(self, data_id: uuid.UUID, user_id: int) -> Optional[Dict]:
        """Retrieve a data item (encrypted)."""
        data_item = self.repository.get_accessible_data(data_id, user_id)
        if not data_item:
            return None
        return self._serialize(data_item)

    def list_data(self, user_id: int, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        data_list = self.repository.list_data_for_user(user_id, data_type)
        return [self._serialize(data_item) for data_item in data_list]

    def list_data_for_project(self, project_id: uuid.UUID, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        data_list = self.repository.list_data_for_project(project_id, data_type)
        return [self._serialize(data_item) for data_item in data_list]

    def get_data_for_project(self, data_id: uuid.UUID, project_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        data_item = self.repository.get_data_for_project(data_id, project_id)
        if not data_item:
            return None
        return self._serialize(data_item)

    def update_data(
        self,
        data_id: uuid.UUID,
        user_id: int,
        payload: DataInternalUpdate,
    ) -> Optional[Dict[str, Any]]:
        data_item = self.repository.get_accessible_data(data_id, user_id)
        if not data_item:
            return None

        updated = self.repository.update_data(data_item, payload, user_id)
        return self._serialize(updated)

    def get_versions(self, data_id: uuid.UUID, user_id: int) -> Optional[DataVersionListResponse]:
        """Get version history for a data item."""
        # Check user has access
        data_item = self.repository.get_accessible_data(data_id, user_id)
        
        if not data_item:
            return None
        
        versions = self.repository.get_versions(data_id)
        version_dtos = [self._serialize_version(v) for v in versions]
        return DataVersionListResponse(versions=version_dtos, total=len(version_dtos))

    def get_version(self, data_id: uuid.UUID, version_num: int, user_id: int) -> Optional[DataVersionResponse]:
        """Get a specific version of a data item."""
        # Check user has access
        data_item = self.repository.get_accessible_data(data_id, user_id)
        if not data_item:
            return None
        
        version = self.repository.get_version(data_id, version_num)
        if not version:
            return None
        return self._serialize_version(version)

    def delete_data(self, data_id: uuid.UUID, user_id: int) -> bool:
        # Try to find by ownership first
        data_item = self.repository.get_accessible_data(data_id, user_id)
        
        # If not owner, check if it's a project secret (Server has already validated RBAC)
        if not data_item:
            data_item = self.repository.get_by_id(data_id)
            if data_item and data_item.project_id:
                # Allowed: Server authorized this deletion for a project secret
                pass
            else:
                # Not found or not authorized
                return False
                
        self.repository.delete_data_for_user(data_item)
        return True

    # Admin operations

    def get_all_data_admin(self, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        data_list = self.repository.list_all_data(data_type)
        return [self._serialize(data_item) for data_item in data_list]


    def delete_data_admin(self, data_id: uuid.UUID) -> bool:
        data_item = self.repository.get_by_id(data_id)
        if not data_item:
            return False
        self.repository.delete_data_admin(data_item)
        return True

    def get_due_rotations(self, limit: int = 50) -> List[Dict[str, Any]]:
        data_list = self.repository.get_due_rotations(limit)
        return [self._serialize(data_item) for data_item in data_list]
