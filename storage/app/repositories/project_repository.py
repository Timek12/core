from typing import List, Optional
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.db.schema import Project, ProjectMember
from app.dto.project import ProjectInternalCreate, ProjectMemberAdd

class ProjectRepository:
    """Repository for project operations"""

    def __init__(self, db: Session):
        self.db = db

    def create_project(self, user_id: int, project_data: ProjectInternalCreate) -> Project:
        """Create a new project and add creator as owner"""
        project = Project(
            name=project_data.name,
            created_by=user_id
        )
        self.db.add(project)
        self.db.flush() # Get ID

        # Add creator as owner
        member = ProjectMember(
            project_id=project.id,
            user_id=user_id,
            role='owner'
        )
        self.db.add(member)
        
        self.db.commit()
        self.db.refresh(project)
        return project

    def get_project(self, project_id: uuid.UUID) -> Optional[Project]:
        """Get project by ID"""
        return self.db.query(Project).filter(Project.id == project_id).first()

    def get_project_by_name(self, name: str) -> Optional[Project]:
        """Get project by name"""
        return self.db.query(Project).filter(Project.name == name).first()

    def update_project(self, project_id: uuid.UUID, name: str) -> Optional[Project]:
        """Update project name"""
        project = self.get_project(project_id)
        if not project:
            return None
        
        project.name = name
        self.db.commit()
        self.db.refresh(project)
        return project

    def list_projects_for_user(self, user_id: int) -> List[Project]:
        """List all projects a user is a member of"""
        return (
            self.db.query(Project)
            .join(ProjectMember, Project.id == ProjectMember.project_id)
            .filter(ProjectMember.user_id == user_id)
            .order_by(Project.created_at.desc())
            .all()
        )

    def add_member(self, project_id: uuid.UUID, member_data: ProjectMemberAdd) -> ProjectMember:
        """Add a member to a project"""
        member = ProjectMember(
            project_id=project_id,
            user_id=member_data.user_id,
            role=member_data.role
        )
        self.db.add(member)
        self.db.commit()
        self.db.refresh(member)
        return member

    def remove_member(self, project_id: uuid.UUID, user_id: int) -> None:
        """Remove a member from a project"""
        self.db.query(ProjectMember).filter(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id
        ).delete()
        self.db.commit()

    def get_members(self, project_id: uuid.UUID) -> List[ProjectMember]:
        """List all members of a project"""
        return (
            self.db.query(ProjectMember)
            .filter(ProjectMember.project_id == project_id)
            .all()
        )

    def is_member(self, project_id: uuid.UUID, user_id: int) -> bool:
        """Check if user is a member of the project"""
        return (
            self.db.query(ProjectMember)
            .filter(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id
            )
            .first()
        ) is not None

    def get_member_role(self, project_id: uuid.UUID, user_id: int) -> Optional[str]:
        """Get user's role in the project"""
        member = (
            self.db.query(ProjectMember)
            .filter(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id
            )
            .first()
        )
        return member.role if member else None

    def delete_project(self, project_id: uuid.UUID) -> bool:
        """Delete a project and all its related data (members, secrets)."""
        project = self.get_project(project_id)
        if not project:
            return False

        # 1. Delete all project members
        self.db.query(ProjectMember).filter(ProjectMember.project_id == project_id).delete()
        
        # 2. Delete all secrets associated with the project
        from app.db.schema import Data
        self.db.query(Data).filter(Data.project_id == project_id).delete()
        
        # 3. Delete the project itself
        self.db.delete(project)
        
        self.db.commit()
        return True
