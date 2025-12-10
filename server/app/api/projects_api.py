from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
import logging

from app.services.project_service import ProjectService
from app.clients.storage_client import StorageClient
from app.utils.redis_state import get_state_manager
from app.dto.token import UserInfo
from app.dependencies import get_storage_client, get_client_info, get_current_user, get_token_from_request
from pydantic import BaseModel
from app.dto.client_info import ClientInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/projects", tags=["projects"])

class ProjectCreateRequest(BaseModel):
    name: str

class ProjectMemberAddRequest(BaseModel):
    user_id: int
    role: str = "member"

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreateRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Create a new project"""
    try:
        state_manager = await get_state_manager()
        project_service = ProjectService(storage_client, state_manager)
        
        result = await project_service.create_project(project_data.name, token)
        
        # Audit Log
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="create_project",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="project",
            resource_id=str(result['id']),
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Created project: {project_data.name}"
        )
        
        return result
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("")
async def list_projects(
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """List projects for the authenticated user"""
    try:
        project_service = ProjectService(storage_client)
        return await project_service.list_projects_for_user(int(user_info.user_id), token)
    except Exception as e:
        logger.error(f"Error listing projects: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/{project_id}")
async def get_project(
    project_id: str,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get project details"""
    try:
        project_service = ProjectService(storage_client)
        
        # Verify membership
        is_member = await project_service.is_member(project_id, int(user_info.user_id), token)
        if not is_member:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")
            
        return await project_service.get_project(project_id, token)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.put("/{project_id}")
async def update_project(
    project_id: str,
    project_data: ProjectCreateRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Update project details"""
    try:
        state_manager = await get_state_manager()
        project_service = ProjectService(storage_client, state_manager)
        
        project = await project_service.get_project(project_id, token)
        if project['created_by'] != int(user_info.user_id):
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the project owner can update the project")

        result = await project_service.update_project(project_id, project_data.name, token)
        
        # Audit Log
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="update_project",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="project",
            resource_id=project_id,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Updated project name to: {project_data.name}"
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating project: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    project_id: str,
    member_data: ProjectMemberAddRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Add a member to the project"""
    try:
        state_manager = await get_state_manager()
        project_service = ProjectService(storage_client, state_manager)
        
        # Verify membership and role
        role = await project_service.get_member_role(project_id, int(user_info.user_id), token)
        if not role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")
        
        if role not in ['owner', 'admin']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only project owners and admins can add members")

        result = await project_service.add_member(project_id, member_data.user_id, member_data.role, token)
        
        # Audit Log
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="add_project_member",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="project",
            resource_id=project_id,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Added user {member_data.user_id} to project as {member_data.role}"
        )
        
        return result
    except Exception as e:
        logger.error(f"Error adding member: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    project_id: str,
    user_id: int,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Remove a member from the project"""
    try:

        state_manager = await get_state_manager()
        project_service = ProjectService(storage_client, state_manager)
        
        # Verify membership and role
        role = await project_service.get_member_role(project_id, int(user_info.user_id), token)
        if not role:
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")

        if role not in ['owner', 'admin']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only project owners and admins can remove members")

        await project_service.remove_member(project_id, user_id, token)
        
        # Audit Log
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="remove_project_member",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="project",
            resource_id=project_id,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Removed user {user_id} from project"
        )
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing member: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/{project_id}/members")
async def get_members(
    project_id: str,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """List project members"""
    try:
        project_service = ProjectService(storage_client)
        
        is_member = await project_service.is_member(project_id, int(user_info.user_id), token)
        if not is_member:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")

        return await project_service.get_members(project_id, token)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing members: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_token_from_request),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Delete a project"""
    try:
        state_manager = await get_state_manager()
        project_service = ProjectService(storage_client, state_manager)
        
        await project_service.delete_project(project_id, int(user_info.user_id), token)
        
        # Audit Log
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="delete_project",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="project",
            resource_id=project_id,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info,
            details=f"Deleted project {project_id}"
        )
        
        return None
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting project: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
