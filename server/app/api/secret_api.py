from fastapi import APIRouter, Depends, HTTPException, status, Request
import httpx
import logging

from app.utils.jwt_utils import get_current_user
from app.dto.secret import SecretCreateRequest, SecretResponse
from app.clients.storage_client import StorageClient
from app.services.secret_service import SecretService
from app.utils.redis_state import get_state_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/secrets", tags=["secrets"])

def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""

@router.get("")
async def get_secrets(request: Request, current_user = Depends(get_current_user)):
    """Get all user secrets and decrypt them"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        storage_client = StorageClient()
        secret_service = SecretService(storage_client=storage_client, state_manager=state_manager)
        
        secrets = await secret_service.get_secrets_for_user(
            user_id=current_user.user_id,
            jwt_token=token
        )
        
        return secrets
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to get secrets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{secret_id}")
async def get_secret(secret_id: str, request: Request, current_user = Depends(get_current_user)):
    """Get a specific secret and decrypt it"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        storage_client = StorageClient()
        secret_service = SecretService(storage_client=storage_client, state_manager=state_manager)
        
        secret = await secret_service.get_secret_by_id(
            secret_id=secret_id,
            jwt_token=token
        )
        
        return secret
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to get secret: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
async def create_secret(
    secret_data: SecretCreateRequest, 
    request: Request, 
    current_user = Depends(get_current_user)
):
    """Create a new secret using DEK architecture"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        storage_client = StorageClient()
        secret_service = SecretService(storage_client=storage_client, state_manager=state_manager)
        
        result = await secret_service.create_secret(
            name=secret_data.name,
            value=secret_data.value,
            description=secret_data.description or "",
            user_id=current_user.user_id,
            jwt_token=token
        )
        
        return result
    except ValueError as e:
        if "sealed" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Storage service error: {e.response.text}")
    except Exception as e:
        logger.error(f"Failed to create secret: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create secret: {str(e)}")


@router.put("/{secret_id}")
async def update_secret(
    secret_id: str,
    secret_data: dict,
    request: Request,
    current_user = Depends(get_current_user)
):
    """Update a secret"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        storage_client = StorageClient()
        secret_service = SecretService(storage_client=storage_client, state_manager=state_manager)
        
        result = await secret_service.update_secret(
            secret_id=secret_id,
            update_data=secret_data,
            jwt_token=token
        )
        
        return result
    except ValueError as e:
        if "sealed" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
        elif "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to update secret: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    secret_id: str, 
    request: Request, 
    current_user = Depends(get_current_user)
):
    """Delete a secret"""
    try:
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        storage_client = StorageClient()
        secret_service = SecretService(storage_client=storage_client, state_manager=state_manager)
        
        await secret_service.delete_secret(
            secret_id=secret_id,
            jwt_token=token
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"Storage service error: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    except Exception as e:
        logger.error(f"Failed to delete secret: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))