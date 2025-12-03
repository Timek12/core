from typing import List, Optional, Dict, Any
import uuid
from datetime import timezone, datetime

from app.repositories.project_repository import ProjectRepository
from app.dto.project import ProjectInternalCreate, ProjectMemberAdd
from app.db.schema import Project, ProjectMember

class ProjectService:
    """Business logic for projects."""

    def __init__(self, project_repository: ProjectRepository):
        self.repository = project_repository

    @staticmethod
    def _iso_datetime(value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    @staticmethod
    def _serialize_project(project: Project) -> Dict[str, Any]:
        return {
            "id": str(project.id),
            "name": project.name,
            "created_by": project.created_by,
            "created_at": ProjectService._iso_datetime(project.created_at)
        }

    @staticmethod
    def _serialize_member(member: ProjectMember) -> Dict[str, Any]:
        return {
            "project_id": str(member.project_id),
            "user_id": member.user_id,
            "role": member.role,
            "joined_at": ProjectService._iso_datetime(member.joined_at)
        }

    def create_project(self, user_id: int, payload: ProjectInternalCreate) -> Dict[str, Any]:
        project = self.repository.create_project(user_id, payload)
        return self._serialize_project(project)

    def get_project(self, project_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        project = self.repository.get_project(project_id)
        if not project:
            return None
        return self._serialize_project(project)

    def update_project(self, project_id: uuid.UUID, name: str) -> Optional[Dict[str, Any]]:
        project = self.repository.update_project(project_id, name)
        if not project:
            return None
        return self._serialize_project(project)

    def list_projects_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        projects = self.repository.list_projects_for_user(user_id)
        return [self._serialize_project(project) for project in projects]

    def add_member(self, project_id: uuid.UUID, payload: ProjectMemberAdd) -> Dict[str, Any]:
        member = self.repository.add_member(project_id, payload)
        return self._serialize_member(member)

    def remove_member(self, project_id: uuid.UUID, user_id: int) -> None:
        self.repository.remove_member(project_id, user_id)

    def get_members(self, project_id: uuid.UUID) -> List[Dict[str, Any]]:
        members = self.repository.get_members(project_id)
        return [self._serialize_member(member) for member in members]

    def is_member(self, project_id: uuid.UUID, user_id: int) -> bool:
        return self.repository.is_member(project_id, user_id)

    def get_member_role(self, project_id: uuid.UUID, user_id: int) -> Optional[str]:
        return self.repository.get_member_role(project_id, user_id)

    def delete_project(self, project_id: uuid.UUID) -> bool:
        return self.repository.delete_project(project_id)
