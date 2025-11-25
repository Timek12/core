from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Optional
import httpx
import logging

from app.utils.jwt_utils import get_admin_user
from app.dto.token import UserInfo
from app.clients.storage_client import StorageClient
from app.dependencies import get_storage_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""


@router.get("/data")
async def get_all_data(
    request: Request,
    data_type: Optional[str] = None,
    _: UserInfo = Depends(get_admin_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get all data across all users with optional type filtering"""
    try:
        token = get_token_from_request(request)
        
        # Use admin endpoint to get all data
        data_list = await storage_client.get_all_data_admin(data_type, token)
        
        return data_list
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error getting all data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/data/user/{user_id}")
async def get_user_data(
    user_id: int,
    request: Request,
    data_type: Optional[str] = None,
    _: UserInfo = Depends(get_admin_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get all data for a specific user with optional type filtering"""
    try:
        token = get_token_from_request(request)
        
        data_list = await storage_client.get_data_for_user(str(user_id), data_type, token)
        
        return {"data": data_list, "user_id": user_id}
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error getting user data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/data/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_any_data(
    data_id: str,
    request: Request,
    _: UserInfo = Depends(get_admin_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Delete any user's data (admin only)"""
    try:
        token = get_token_from_request(request)
        
        success = await storage_client.delete_data_admin(data_id, token)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data not found"
            )
        
        return None
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
