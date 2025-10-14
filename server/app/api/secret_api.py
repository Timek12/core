import uuid
from fastapi import APIRouter, Depends, HTTPException, status
import json
import httpx

from app.utils.jwt_utils import get_current_user

from app.dto.secret import SecretCreate, SecretResponse, SecretUpdate
from app.clients.storage_client import StorageClient

router = APIRouter(prefix="/api/secrets", tags=["secrets"])
storage_client = StorageClient()

@router.get("")
async def get_secrets(current_user = Depends(get_current_user)):
    try:
        secrets = await storage_client.get_secrets(current_user.user_id)
        return secrets
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")

@router.get("/{secret_id}")
async def get_secret(current_user = Depends(get_current_user)):
    try:
        secrets = await storage_client.get_secrets(current_user.user_id)
        return secrets
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")    
    
@router.post("")
async def create_secret(secret_data: SecretCreate, current_user = Depends(get_current_user)):
    try:
        enriched_data = json.loads(secret_data.model_dump_json())  # Convert UUIDs to strings
        enriched_data["user_id"] = current_user.user_id
        
        result = await storage_client.create_secret(enriched_data)

        return result
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    

@router.put("", response_model=SecretResponse)
def update_secret(
    secret_id: uuid.UUID,
    secret_data: SecretUpdate, 
    _ = Depends(get_current_user)
):
    secret = storage_client.update_secret(secret_id, secret_data)

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    return secret

@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(secret_id: uuid.UUID, _ = Depends(get_current_user)):
    deleted = storage_client.delete_secret(secret_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    