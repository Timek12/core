import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Request
import json
import httpx

from app.utils.jwt_utils import get_current_user

from app.dto.secret import SecretCreate, SecretCreateRequest, SecretResponse, SecretUpdate
from app.clients.storage_client import StorageClient

router = APIRouter(prefix="/api/secrets", tags=["secrets"])
storage_client = StorageClient()

def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""

@router.get("")
async def get_secrets(request: Request, current_user = Depends(get_current_user)):
    """
    Get all user secrets and decrypt them using DEK architecture:
    1. Fetch secrets from storage
    2. For each secret, fetch its DEK
    3. Decrypt DEK with master key
    4. Decrypt secret value with DEK
    """
    try:
        from app.services.crypto_service import CryptoService
        from app.utils.redis_state import get_state_manager
        
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        
        secrets = await storage_client.get_secrets_for_user(str(current_user.user_id), token)
        
        # Decrypt secrets if vault is unsealed
        if not await state_manager.is_vault_sealed():
            master_key_hex = await state_manager.get_master_key()
            if master_key_hex:
                master_key = bytes.fromhex(master_key_hex)
                crypto_service = CryptoService()
                
                for secret in secrets:
                    try:
                        # Skip if no DEK (backward compatibility)
                        if not secret.get("dek_id"):
                            secret["decrypted_value"] = None
                            secret["decrypt_error"] = "No DEK associated with this secret"
                            continue
                        
                        # Fetch the DEK
                        dek_record = await storage_client.get_dek(secret["dek_id"])
                        
                        # Decrypt the DEK with master key
                        dek_nonce = bytes.fromhex(dek_record["nonce"])
                        encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
                        dek = crypto_service.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
                        
                        # Decrypt the secret value with DEK
                        encrypted_data = json.loads(secret["encrypted_value"])
                        secret_nonce = bytes.fromhex(encrypted_data["nonce"])
                        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
                        decrypted = crypto_service.aesgcm_decrypt(dek, secret_nonce, ciphertext)
                        
                        secret["decrypted_value"] = decrypted.decode()
                        
                        # Clear sensitive data
                        del dek
                    except Exception as e:
                        secret["decrypted_value"] = None
                        secret["decrypt_error"] = str(e)
                
                # Clear master key from memory
                del master_key
        
        return secrets
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")

@router.get("/{secret_id}")
async def get_secret(secret_id: str, request: Request, current_user = Depends(get_current_user)):
    """
    Get a specific secret and decrypt it using DEK architecture
    """
    try:
        from app.services.crypto_service import CryptoService
        from app.utils.redis_state import get_state_manager
        
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        
        secret = await storage_client.get_secret(secret_id, token)
        
        # Decrypt secret if vault is unsealed
        if not await state_manager.is_vault_sealed():
            master_key_hex = await state_manager.get_master_key()
            if master_key_hex and secret.get("dek_id"):
                master_key = bytes.fromhex(master_key_hex)
                crypto_service = CryptoService()
                
                try:
                    # Fetch the DEK
                    dek_record = await storage_client.get_dek(secret["dek_id"])
                    
                    # Decrypt the DEK with master key
                    dek_nonce = bytes.fromhex(dek_record["nonce"])
                    encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
                    dek = crypto_service.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
                    
                    # Decrypt the secret value with DEK
                    encrypted_data = json.loads(secret["encrypted_value"])
                    secret_nonce = bytes.fromhex(encrypted_data["nonce"])
                    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
                    decrypted = crypto_service.aesgcm_decrypt(dek, secret_nonce, ciphertext)
                    
                    secret["decrypted_value"] = decrypted.decode()
                    
                    # Clear sensitive data
                    del dek, master_key
                except Exception as e:
                    secret["decrypted_value"] = None
                    secret["decrypt_error"] = str(e)
        
        return secret
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")    
    
@router.post("")
async def create_secret(secret_data: SecretCreateRequest, request: Request, current_user = Depends(get_current_user)):
    """
    Create a new secret using DEK (Data Encryption Key) architecture:
    1. Generate a random DEK (32 bytes)
    2. Encrypt the secret value with the DEK
    3. Encrypt the DEK with the master key
    4. Store both the encrypted secret and encrypted DEK
    """
    try:
        import os
        from app.services.crypto_service import CryptoService
        from app.utils.redis_state import get_state_manager
        
        token = get_token_from_request(request)
        state_manager = await get_state_manager()
        crypto_service = CryptoService()
        
        # Check if vault is unsealed
        if await state_manager.is_vault_sealed():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Vault is sealed. Please unseal the vault first."
            )
        
        # Get master key from Redis
        master_key_hex = await state_manager.get_master_key()
        if not master_key_hex:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No master key available. Vault may need to be unsealed."
            )
        
        master_key = bytes.fromhex(master_key_hex)
        
        # Step 1: Generate a random DEK (Data Encryption Key)
        dek = os.urandom(32)  # 256-bit key
        
        # Step 2: Encrypt the secret value with the DEK
        secret_nonce, encrypted_secret = crypto_service.aesgcm_encrypt(dek, secret_data.value.encode())
        
        # Step 3: Encrypt the DEK with the master key
        dek_nonce, encrypted_dek = crypto_service.aesgcm_encrypt(master_key, dek)
        
        # Step 4: Store the encrypted DEK in the database
        dek_data = {
            "encrypted_dek": encrypted_dek.hex(),
            "nonce": dek_nonce.hex()
        }
        dek_record = await storage_client.create_dek(dek_data, token)
        
        # Step 5: Get master key ID from storage
        master_keys = await storage_client.get_all_keys(key_type="master", jwt_token=token)
        if not master_keys or len(master_keys) == 0:
            raise HTTPException(status_code=500, detail="Master key not found in storage")
        
        # Step 6: Store the secret with reference to the DEK
        storage_data = {
            "user_id": str(current_user.user_id),
            "name": secret_data.name,
            "description": secret_data.description or "",
            "key_id": master_keys[0]["id"],  # Reference to master key
            "dek_id": dek_record["id"],  # Reference to DEK
            "encrypted_value": json.dumps({
                "nonce": secret_nonce.hex(),
                "ciphertext": encrypted_secret.hex()
            }),
            "version": 1,
        }
        
        result = await storage_client.create_secret(storage_data, token)
        
        # Clear sensitive data from memory
        del dek, master_key
        
        return result
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Storage service error: {e.response.text}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create secret: {str(e)}")
    

@router.put("/{secret_id}")
async def update_secret(
    secret_id: str,
    secret_data: dict,  # Accept raw dict to handle both name/description and value updates
    request: Request,
    current_user = Depends(get_current_user)
):
    """
    Update a secret. If value is provided, creates new DEK and re-encrypts.
    """
    try:
        import os
        from app.services.crypto_service import CryptoService
        from app.utils.redis_state import get_state_manager
        
        token = get_token_from_request(request)
        
        update_data = {}
        
        # Handle simple metadata updates (name, description)
        if "name" in secret_data:
            update_data["name"] = secret_data["name"]
        if "description" in secret_data:
            update_data["description"] = secret_data["description"]
        
        # Handle value update (requires encryption)
        if "value" in secret_data and secret_data["value"]:
            state_manager = await get_state_manager()
            crypto_service = CryptoService()
            
            # Check if vault is unsealed
            if await state_manager.is_vault_sealed():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Vault is sealed. Cannot update secret value."
                )
            
            # Get master key from Redis
            master_key_hex = await state_manager.get_master_key()
            if not master_key_hex:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="No master key available."
                )
            
            master_key = bytes.fromhex(master_key_hex)
            
            # Generate new DEK for the updated secret
            dek = os.urandom(32)
            
            # Encrypt the new secret value with the DEK
            secret_nonce, encrypted_secret = crypto_service.aesgcm_encrypt(dek, secret_data["value"].encode())
            
            # Encrypt the DEK with the master key
            dek_nonce, encrypted_dek = crypto_service.aesgcm_encrypt(master_key, dek)
            
            # Store the new encrypted DEK
            dek_data = {
                "encrypted_dek": encrypted_dek.hex(),
                "nonce": dek_nonce.hex()
            }
            dek_record = await storage_client.create_dek(dek_data)
            
            # Update the encrypted value and DEK reference
            update_data["dek_id"] = dek_record["id"]
            update_data["encrypted_value"] = json.dumps({
                "nonce": secret_nonce.hex(),
                "ciphertext": encrypted_secret.hex()
            })
            update_data["version"] = (update_data.get("version", 1)) + 1  # Increment version
            
            # Clear sensitive data
            del dek, master_key
        
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        secret = await storage_client.update_secret(secret_id, update_data, token)

        if not secret:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret not found"
            )
        
        return secret
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")

@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(secret_id: str, request: Request, current_user = Depends(get_current_user)):
    try:
        token = get_token_from_request(request)
        deleted = await storage_client.delete_secret(secret_id, token)

        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret not found"
            )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Storage service error")
    