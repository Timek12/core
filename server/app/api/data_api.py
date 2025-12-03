from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, BackgroundTasks
from typing import List, Optional
import logging

from app.dto.data import DataCreateRequest, DataUpdateRequest, DataResponse, DataListItem
from app.services.data_service import DataService
from app.services.crypto_service import CryptoService
from app.clients.storage_client import StorageClient
from app.utils.jwt_utils import get_current_user
from app.utils.redis_state import get_state_manager
from app.dto.token import UserInfo
from app.dependencies import get_storage_client, get_client_info

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/data", tags=["data"])


def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""


@router.get("", response_model=List[DataListItem])
async def get_data(
    request: Request,
    background_tasks: BackgroundTasks,
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get all data for authenticated user"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        result = await data_service.get_data_for_user(user_info.user_id, token, data_type)
        
        # Audit Log (Read List)
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="read_data_list",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Listed data (type: {data_type or 'all'})"
        )
        
        return result
    except Exception as e:
        logger.error(f"Error getting data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/{data_id}", response_model=DataResponse)
async def get_data_item(
    data_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get a specific data item by ID with decryption"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        result = await data_service.get_data(data_id, token)
        
        # Audit Log (Read Item)
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="read_data",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=data_id,
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Read data: {result['name']}"
        )
        
        return result
    except Exception as e:
        logger.error(f"Error getting data {data_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found"
        )


@router.post("", status_code=status.HTTP_201_CREATED, response_model=DataResponse)
async def create_data(
    data: DataCreateRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    project_id: Optional[str] = Query(None),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Create a new typed data"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        result = await data_service.create_data(data, token, project_id)
        
        # Audit Log
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="create_data",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=str(result['id']),
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Created data: {data.name} ({data.data_type}) Project: {project_id}"
        )
        
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error creating data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/project/{project_id}", response_model=List[DataListItem])
async def list_data_for_project(
    project_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """List data belonging to a project"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        # Check membership
        is_member = await storage_client.is_member(project_id, int(user_info.user_id), token)
        if not is_member:
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")

        result = await data_service.list_data_for_project(project_id, token, data_type)
        
        # Audit Log
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="read_project_data_list",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=project_id, 
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Listed project data (type: {data_type or 'all'})"
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/project/{project_id}/{data_id}", response_model=DataResponse)
async def get_data_for_project(
    project_id: str,
    data_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get a specific project data item by ID with decryption"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        # Check membership
        is_member = await storage_client.is_member(project_id, int(user_info.user_id), token)
        if not is_member:
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project")
        
        result = await data_service.get_data_for_project(project_id, data_id, token)
        
        # Audit Log
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="read_project_data",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=data_id,
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Read project data: {result['name']}"
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project data {data_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found"
        )


@router.put("/{data_id}", response_model=DataResponse)
async def update_data(
    data_id: str,
    data: DataUpdateRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Update an existing data"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        result = await data_service.update_data(data_id, data, token, str(user_info.user_id))
        
        # Audit Log
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="update_data",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=data_id,
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Updated data: {data.name}"
        )
        
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error updating data {data_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Data not found"
        )


@router.delete("/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_data(
    data_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    user_info: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Delete a data"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        data_service = DataService(storage_client, state_manager)
        
        # First, get the data to check ownership
        try:
            data_item = await data_service.get_data(data_id, token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data not found"
            )
        
        # Check permissions
        is_owner = str(data_item.get('user_id')) == str(user_info.user_id)
        project_id = data_item.get('project_id')
        
        if not is_owner:
            # If not owner, check if project admin/owner
            if project_id:
                role = await storage_client.get_member_role(project_id, int(user_info.user_id), token)
                if role not in ['owner', 'admin']:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Only the owner or project admin can delete this secret"
                    )
            else:
                # Personal secret, strict ownership
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only the owner can delete this secret"
                )
        
        success = await data_service.delete_data(data_id, token)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data not found"
            )
            
        # Audit Log
        device_info, ip_address = get_client_info(request)
        background_tasks.add_task(
            state_manager.log_audit_event,
            action="delete_data",
            status="success",
            user_id=str(user_info.user_id),
            resource_type="data",
            resource_id=data_id,
            ip_address=ip_address,
            user_agent=device_info,
            details=f"Deleted data: {data_item.get('name', 'unknown')}"
        )
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting data {data_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
