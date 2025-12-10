from fastapi import APIRouter, HTTPException, Depends
from app.services.crypto_service import CryptoService
from app.clients.storage_client import StorageClient
from app.utils.redis_state import get_state_manager
from app.dependencies import get_storage_client, get_client_info, get_current_user, require_role, get_token
from app.dto.token import UserInfo
from app.dto.crypto import (
    InitRequest, 
    UnsealRequest, 
    StatusResponse, 
    VaultStatus
)
from app.dto.client_info import ClientInfo
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/crypto", tags=["crypto"])

@router.post("/init", response_model=StatusResponse)
async def init(
    req: InitRequest, 
    current_user: UserInfo = Depends(require_role("admin")), 
    token: str = Depends(get_token),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Initialize the vault with Redis state management"""
    try:
        state_manager = await get_state_manager()
        crypto_service = CryptoService(storage_client=storage_client, state_manager=state_manager)
        
        result = await crypto_service.initialize_vault(
            external_token=req.external_token,
            user_id=current_user.user_id,
            jwt_token=token,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info
        )
        
        return StatusResponse(
            vault=VaultStatus(
                sealed=result["sealed"], 
                initialized=result["initialized"],
                version="1.0"
            ),
            message=f"Vault initialized successfully. Root ID: {result['root_id']}, Master ID: {result['master_id']}"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to initialize vault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unseal", response_model=StatusResponse)
async def unseal(
    req: UnsealRequest, 
    current_user: UserInfo = Depends(require_role("admin")), 
    token: str = Depends(get_token),
    storage_client: StorageClient = Depends(get_storage_client),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Unseal the vault using Redis for session management"""
    try:
        state_manager = await get_state_manager()
        crypto_service = CryptoService(storage_client=storage_client, state_manager=state_manager)
        
        result = await crypto_service.unseal_vault(
            external_token=req.external_token,
            user_id=current_user.user_id,
            jwt_token=token,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info
        )
        
        return StatusResponse(
            vault=VaultStatus(
                sealed=result["sealed"],
                initialized=result["initialized"],
                version="1.0"
            ),
            message="Vault unsealed successfully"
        )
    except ValueError as e:
        if "Invalid external token" in str(e):
            raise HTTPException(status_code=403, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to unseal vault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/seal", response_model=StatusResponse)
async def seal(
    current_user: UserInfo = Depends(require_role("admin")),
    client_info: ClientInfo = Depends(get_client_info)
):
    """Seal the vault by clearing Redis session data"""
    try:
        state_manager = await get_state_manager()
        crypto_service = CryptoService(state_manager=state_manager)
        
        result = await crypto_service.seal_vault(
            user_id=current_user.user_id,
            ip_address=client_info.ip_address,
            user_agent=client_info.device_info
        )
        
        return StatusResponse(
            vault=VaultStatus(
                sealed=result["sealed"],
                initialized=result["initialized"],
                version="1.0"
            ),
            message="Vault sealed successfully - all sessions cleared"
        )
    except Exception as e:
        logger.error(f"Failed to seal vault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status", response_model=StatusResponse)
async def status(
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get vault status from Redis state"""
    try:
        state_manager = await get_state_manager()
        crypto_service = CryptoService(storage_client=storage_client, state_manager=state_manager)
        
        result = await crypto_service.get_vault_status()
        
        return StatusResponse(
            vault=VaultStatus(
                sealed=result["sealed"],
                initialized=result["initialized"],
                version=result["version"]
            ),
            message="Vault status retrieved"
        )
    except Exception as e:
        logger.error(f"Failed to get vault status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))