from typing import List, Dict, Any
import logging

from app.clients.storage_client import StorageClient
from app.utils.redis_state import RedisStateManager

logger = logging.getLogger(__name__)

class ProjectService:
    def __init__(self, storage_client: StorageClient = None, state_manager: RedisStateManager = None):
        self.storage_client = storage_client or StorageClient()
        self.state_manager = state_manager

    async def create_project(self, name: str, jwt_token: str) -> Dict[str, Any]:
        """Create a new project"""
        logger.info(f"Creating project '{name}'")
        return await self.storage_client.create_project({"name": name}, jwt_token)

    async def list_projects_for_user(self, user_id: int, jwt_token: str) -> List[Dict[str, Any]]:
        """List projects for a user"""
        return await self.storage_client.list_projects_for_user(user_id, jwt_token)

    async def get_project(self, project_id: str, jwt_token: str) -> Dict[str, Any]:
        """Get project details"""
        return await self.storage_client.get_project(project_id, jwt_token)

    async def update_project(self, project_id: str, name: str, jwt_token: str) -> Dict[str, Any]:
        """Update project details"""
        return await self.storage_client.update_project(project_id, name, jwt_token)

    async def add_member(self, project_id: str, user_id: int, role: str, jwt_token: str) -> Dict[str, Any]:
        """Add member to project"""
        logger.info(f"Adding user {user_id} to project {project_id} with role {role}")
        return await self.storage_client.add_member(
            project_id, 
            {"user_id": user_id, "role": role}, 
            jwt_token
        )

    async def remove_member(self, project_id: str, user_id: int, jwt_token: str) -> None:
        """Remove member from project"""
        logger.info(f"Removing user {user_id} from project {project_id}")
        await self.storage_client.remove_member(project_id, user_id, jwt_token)

    async def get_members(self, project_id: str, jwt_token: str) -> List[Dict[str, Any]]:
        """List project members"""
        return await self.storage_client.get_members(project_id, jwt_token)

    async def is_member(self, project_id: str, user_id: int, jwt_token: str) -> bool:
        """Check if user is a member of the project"""
        return await self.storage_client.is_member(project_id, user_id, jwt_token)

    async def get_member_role(self, project_id: str, user_id: int, jwt_token: str) -> str:
        """Get user's role in the project"""
        members = await self.get_members(project_id, jwt_token)
        for member in members:
            if member['user_id'] == user_id:
                return member['role']
        return None

    async def delete_project(self, project_id: str, user_id: int, jwt_token: str) -> None:
        """Delete a project (owner only)"""
        project = await self.get_project(project_id, jwt_token)
        if not project:
            raise ValueError("Project not found")
        
        if project['created_by'] != user_id:
            raise ValueError("Only the project owner can delete the project")
            
        logger.info(f"Deleting project {project_id} by user {user_id}")
        await self.storage_client.delete_project(project_id, jwt_token)
