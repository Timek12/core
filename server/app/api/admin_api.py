from fastapi import APIRouter, Depends, HTTPException, status, Request
import httpx
import logging
import os

from app.utils.jwt_utils import get_admin_user
from app.dto.token import UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""


@router.get("/secrets")
async def get_all_secrets(
    request: Request,
    _: UserInfo = Depends(get_admin_user)
):
    """Get all secrets across all users"""
    try:
        token = get_token_from_request(request)
        storage_url = os.getenv("STORAGE_SERVICE_URL", "http://storage:8002")
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{storage_url}/internal/secrets/admin/all",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to get all secrets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/secrets/user/{user_id}")
async def get_user_secrets(
    user_id: int,
    request: Request,
    _: UserInfo = Depends(get_admin_user)
):
    """Get all secrets for a specific user"""
    try:
        token = get_token_from_request(request)
        storage_url = os.getenv("STORAGE_SERVICE_URL", "http://storage:8002")
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{storage_url}/internal/secrets/admin/user/{user_id}",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to get user secrets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/secrets/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_any_secret(
    secret_id: str,
    request: Request,
    _: UserInfo = Depends(get_admin_user)
):
    """Delete any user's secret"""
    try:
        token = get_token_from_request(request)
        storage_url = os.getenv("STORAGE_SERVICE_URL", "http://storage:8002")
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{storage_url}/internal/secrets/admin/{secret_id}",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to delete secret: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
