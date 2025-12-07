import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.services.project_service import ProjectService
from app.repositories.project_repository import ProjectRepository
from app.services.project_service import ProjectService
from app.repositories.project_repository import ProjectRepository
from app.dependencies import get_db, get_current_user
from app.dto.project import ProjectInternalCreate, ProjectMemberAdd, ProjectResponse, ProjectMemberResponse
from app.dto.token import UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/projects", tags=["projects"])

def get_project_service(db: Session = Depends(get_db)) -> ProjectService:
    repository = ProjectRepository(db)
    return ProjectService(repository)

def _parse_user_id(user_info: UserInfo) -> int:
    try:
        return int(user_info.user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id") from exc

@router.post("", status_code=status.HTTP_201_CREATED)
def create_project(
    request: ProjectInternalCreate,
    current_user: UserInfo = Depends(get_current_user),
    service: ProjectService = Depends(get_project_service),
):
    """Create a new project."""
    user_id = _parse_user_id(current_user)
    try:
        return service.create_project(user_id, request)
    except Exception as exc:
        logger.error("Failed to create project: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@router.get("/user/{user_id}")
def list_projects_for_user(
    user_id: int,
    service: ProjectService = Depends(get_project_service),
):
    """List projects for a specific user."""
    return service.list_projects_for_user(user_id)

@router.get("/{project_id}")
def get_project(
    project_id: uuid.UUID,
    service: ProjectService = Depends(get_project_service),
):
    """Get project details."""
    project = service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project

@router.put("/{project_id}")
def update_project(
    project_id: uuid.UUID,
    request: ProjectInternalCreate,
    service: ProjectService = Depends(get_project_service),
):
    """Update project details."""
    project = service.update_project(project_id, request.name)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project

@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: uuid.UUID,
    service: ProjectService = Depends(get_project_service),
):
    """Delete a project."""
    service.delete_project(str(project_id))
    return None

@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
def add_member(
    project_id: uuid.UUID,
    request: ProjectMemberAdd,
    service: ProjectService = Depends(get_project_service),
):
    """Add a member to a project."""
    try:
        return service.add_member(project_id, request)
    except Exception as exc:
        logger.error("Failed to add member: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    project_id: uuid.UUID,
    user_id: int,
    service: ProjectService = Depends(get_project_service),
):
    """Remove a member from a project."""
    service.remove_member(project_id, user_id)
    return None

@router.get("/{project_id}/members")
def get_members(
    project_id: uuid.UUID,
    service: ProjectService = Depends(get_project_service),
):
    """List members of a project."""
    return service.get_members(project_id)

@router.get("/{project_id}/members/{user_id}/check")
def is_member(
    project_id: uuid.UUID,
    user_id: int,
    service: ProjectService = Depends(get_project_service),
):
    """Check if user is a member of the project."""
    return {"is_member": service.is_member(project_id, user_id)}

@router.get("/{project_id}/members/{user_id}/role")
def get_member_role(
    project_id: uuid.UUID,
    user_id: int,
    service: ProjectService = Depends(get_project_service),
):
    """Get user's role in the project."""
    role = service.get_member_role(project_id, user_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    return {"role": role}
