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

    def create_data(self, user_id: int, data: DataInternalCreate, project_id: Optional[uuid.UUID] = None) -> Data:
        """Persist a new data for a user or project."""
        data_item = Data(
            user_id=user_id,
            name=data.name,
            description=data.description or "",
            data_type=data.data_type.value if hasattr(data.data_type, "value") else str(data.data_type),
            metadata_json=data.metadata_json,
            encrypted_value=data.encrypted_value,
            dek_id=uuid.UUID(str(data.dek_id)),
            is_active=True,
            version=1,
            project_id=project_id
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
                Data.project_id.is_(None) # Only personal data
            )
            .first()
        )

    def get_accessible_data(self, data_id: uuid.UUID, user_id: int) -> Optional[Data]:
        """Fetch data if user is owner OR project member."""
        from app.db.schema import ProjectMember
        
        # Check if user is owner (personal or project secret created by them)
        data = (
            self.db.query(Data)
            .filter(
                Data.id == data_id,
                Data.user_id == user_id,
                Data.is_active.is_(True)
            )
            .first()
        )
        if data:
            return data
            
        # Check if user is member of the project the secret belongs to
        return (
            self.db.query(Data)
            .join(ProjectMember, Data.project_id == ProjectMember.project_id)
            .filter(
                Data.id == data_id,
                ProjectMember.user_id == user_id,
                Data.is_active.is_(True)
            )
            .first()
        )

    def list_data_for_user(self, user_id: int, data_type: Optional[str] = None) -> List[Data]:
        """Return active data for a user, optionally filtered by type."""
        query = self.db.query(Data).filter(
            Data.user_id == user_id,
            Data.is_active.is_(True),
            Data.project_id.is_(None) # Only personal data
        )
        if data_type:
            query = query.filter(Data.data_type == data_type)
        return query.order_by(Data.created_at.desc()).all()

    def list_data_for_project(self, project_id: uuid.UUID, data_type: Optional[str] = None) -> List[Data]:
        """Return active data for a project."""
        query = self.db.query(Data).filter(
            Data.project_id == project_id,
            Data.is_active.is_(True)
        )
        if data_type:
            query = query.filter(Data.data_type == data_type)
        return query.order_by(Data.created_at.desc()).all()

    def get_data_for_project(self, data_id: uuid.UUID, project_id: uuid.UUID) -> Optional[Data]:
        """Fetch a data that belongs to the given project."""
        return (
            self.db.query(Data)
            .filter(
                Data.id == data_id,
                Data.project_id == project_id,
                Data.is_active.is_(True),
            )
            .first()
        )

    def update_data(self, data_item: Data, data: DataInternalUpdate, user_id: int) -> Data:
        """Update data fields."""
        # Create a version snapshot before updating
        self.create_version(data_item, user_id)
        
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
        if data.project_id is not None:
            data_item.project_id = data.project_id

        data_item.version = (data_item.version or 0) + 1
        data_item.updated_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(data_item)
        return data_item

    def create_version(self, data_item: Data, created_by: int):
        """Create a version snapshot before updating."""
        from app.db.schema import DataVersion
        version = DataVersion(
            data_id=data_item.id,
            version=data_item.version or 1,
            encrypted_value=data_item.encrypted_value,
            dek_id=data_item.dek_id,
            created_by=created_by
        )
        self.db.add(version)

    def get_versions(self, data_id: uuid.UUID):
        """Get all versions for a data item."""
        from app.db.schema import DataVersion
        return (
            self.db.query(DataVersion)
            .filter(DataVersion.data_id == data_id)
            .order_by(DataVersion.version.desc())
            .all()
        )

    def get_version(self, data_id: uuid.UUID, version_num: int):
        """Get a specific historical version."""
        from app.db.schema import DataVersion
        return (
            self.db.query(DataVersion)
            .filter(
                DataVersion.data_id == data_id,
                DataVersion.version == version_num
            )
            .first()
        )

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
