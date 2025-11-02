from typing import List, Dict, Optional
import os
import json
import logging

from app.clients.storage_client import StorageClient
from app.utils.redis_state import RedisStateManager
from app.services.crypto_service import CryptoService

logger = logging.getLogger(__name__)

class SecretService:
    def __init__(self, storage_client: StorageClient = None, state_manager: RedisStateManager = None):
        self.storage_client = storage_client or StorageClient()
        self.state_manager = state_manager
        self.crypto_service = CryptoService()

    async def create_secret(
        self, 
        name: str, 
        value: str, 
        description: str, 
        user_id: str, 
        jwt_token: str
    ) -> Dict:
        """
        Create a new secret using DEK (Data Encryption Key) architecture:
        1. Validate vault is unsealed
        2. Retrieve master key from Redis
        3. Generate a random DEK (32 bytes)
        4. Encrypt the secret value with the DEK (using AES-GCM)
        5. Encrypt the DEK with the master key (using AES-GCM)
        6. Store encrypted DEK in database
        7. Get master key ID from storage
        8. Store encrypted secret with reference to DEK and master key
        """
        logger.info(f"Creating secret '{name}' for user {user_id}")
        
        # Step 1: Check if vault is unsealed
        if await self.state_manager.is_vault_sealed():
            raise ValueError("Vault is sealed. Please unseal the vault first.")
        
        # Step 2: Get master key from Redis
        master_key_hex = await self.state_manager.get_master_key()
        if not master_key_hex:
            vault_status = await self.state_manager.get_vault_status()
            logger.error(f"Master key not found. Vault status: {vault_status}")
            raise ValueError("No master key available. Vault may need to be unsealed.")
        
        logger.info(f"Master key retrieved, length: {len(master_key_hex)}")
        master_key = bytes.fromhex(master_key_hex)
        
        # Step 3: Generate a random DEK (Data Encryption Key)
        dek = os.urandom(32)  # 256-bit key
        
        # Step 4: Encrypt the secret value with the DEK
        secret_nonce, encrypted_secret = self.crypto_service.aesgcm_encrypt(dek, value.encode())
        
        # Step 5: Encrypt the DEK with the master key
        dek_nonce, encrypted_dek = self.crypto_service.aesgcm_encrypt(master_key, dek)
        
        # Step 6: Store the encrypted DEK in the database
        dek_data = {
            "encrypted_dek": encrypted_dek.hex(),
            "nonce": dek_nonce.hex()
        }
        dek_record = await self.storage_client.create_dek(dek_data, jwt_token)
        
        # Step 7: Get master key ID from storage (now returns UUID)
        master_keys = await self.storage_client.get_all_keys(key_type="master", jwt_token=jwt_token)
        if not master_keys or len(master_keys) == 0:
            raise ValueError("Master key not found in storage")
        
        # Keep as UUID string
        master_key_id = master_keys[0]["id"]
        logger.info(f"Using master key ID: {master_key_id} (type: UUID)")
        
        # Step 8: Store the secret with reference to the DEK
        storage_data = {
            "user_id": int(user_id),
            "name": name,
            "description": description or "",
            "key_id": master_key_id,  # Pass UUID string directly
            "dek_id": str(dek_record["id"]),  # Ensure this is also a UUID string
            "encrypted_value": json.dumps({
                "nonce": secret_nonce.hex(),
                "ciphertext": encrypted_secret.hex()
            }),
            "version": 1,
        }
        
        result = await self.storage_client.create_secret(storage_data, jwt_token)
        logger.info(f"Secret created successfully with ID: {result.get('id')}")
        
        if 'user_id' in result:
            result['user_id'] = str(result['user_id'])
        
        # Clear sensitive data from memory
        del dek, master_key
        
        return result

    async def get_secrets_for_user(self, user_id: str, jwt_token: str) -> List[Dict]:
        """
        Get all user secrets and decrypt them using DEK architecture:
        1. Fetch all secrets for user from storage
        2. Check if vault is unsealed
        3. For each secret:
           a. Fetch its DEK from storage
           b. Decrypt DEK with master key
           c. Decrypt secret value with DEK
           d. Add decrypted value to response
        """
        logger.info(f"Fetching secrets for user {user_id}")
        
        # Step 1: Fetch secrets from storage
        secrets = await self.storage_client.get_secrets_for_user(str(user_id), jwt_token)
        
        # Step 2: Decrypt secrets if vault is unsealed
        if not await self.state_manager.is_vault_sealed():
            master_key_hex = await self.state_manager.get_master_key()
            if master_key_hex:
                master_key = bytes.fromhex(master_key_hex)
                
                for secret in secrets:
                    try:
                        # Skip if no DEK (backward compatibility)
                        if not secret.get("dek_id"):
                            secret["decrypted_value"] = None
                            secret["decrypt_error"] = "No DEK associated with this secret"
                            continue
                        
                        # Step 3a: Fetch the DEK
                        dek_record = await self.storage_client.get_dek(secret["dek_id"])
                        
                        # Step 3b: Decrypt the DEK with master key
                        dek_nonce = bytes.fromhex(dek_record["nonce"])
                        encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
                        dek = self.crypto_service.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
                        
                        # Step 3c: Decrypt the secret value with DEK
                        encrypted_data = json.loads(secret["encrypted_value"])
                        secret_nonce = bytes.fromhex(encrypted_data["nonce"])
                        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
                        decrypted = self.crypto_service.aesgcm_decrypt(dek, secret_nonce, ciphertext)
                        
                        # Step 3d: Add decrypted value
                        secret["decrypted_value"] = decrypted.decode()
                        
                        # Clear sensitive data
                        del dek
                    except Exception as e:
                        logger.error(f"Error decrypting secret {secret.get('id')}: {e}")
                        secret["decrypted_value"] = None
                        secret["decrypt_error"] = str(e)
                
                # Clear master key from memory
                del master_key
        
        for secret in secrets:
            if 'user_id' in secret:
                secret['user_id'] = str(secret['user_id'])
        
        return secrets

    async def get_secret_by_id(self, secret_id: str, jwt_token: str) -> Dict:
        """
        Get a specific secret and decrypt it
        """
        logger.info(f"Fetching secret {secret_id}")
        
        secret = await self.storage_client.get_secret(secret_id, jwt_token)
        
        # Decrypt secret if vault is unsealed
        if not await self.state_manager.is_vault_sealed():
            master_key_hex = await self.state_manager.get_master_key()
            if master_key_hex and secret.get("dek_id"):
                master_key = bytes.fromhex(master_key_hex)
                
                try:
                    # Fetch the DEK
                    dek_record = await self.storage_client.get_dek(secret["dek_id"])
                    
                    # Decrypt the DEK with master key
                    dek_nonce = bytes.fromhex(dek_record["nonce"])
                    encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
                    dek = self.crypto_service.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
                    
                    # Decrypt the secret value with DEK
                    encrypted_data = json.loads(secret["encrypted_value"])
                    secret_nonce = bytes.fromhex(encrypted_data["nonce"])
                    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
                    decrypted = self.crypto_service.aesgcm_decrypt(dek, secret_nonce, ciphertext)
                    
                    secret["decrypted_value"] = decrypted.decode()
                    
                    # Clear sensitive data
                    del dek, master_key
                except Exception as e:
                    logger.error(f"Error decrypting secret: {e}")
                    secret["decrypted_value"] = None
                    secret["decrypt_error"] = str(e)
        
        if 'user_id' in secret:
            secret['user_id'] = str(secret['user_id'])
        
        return secret

    async def update_secret(
        self, 
        secret_id: str, 
        update_data: Dict, 
        jwt_token: str
    ) -> Dict:
        """
        Update a secret. If value is provided, creates new DEK and re-encrypts.
        """
        logger.info(f"Updating secret {secret_id}")
        
        final_update_data = {}
        
        # Handle metadata updates
        if "name" in update_data:
            final_update_data["name"] = update_data["name"]
        if "description" in update_data:
            final_update_data["description"] = update_data["description"]
        
        # Handle value update
        if "value" in update_data and update_data["value"]:
            # Check if vault is unsealed
            if await self.state_manager.is_vault_sealed():
                raise ValueError("Vault is sealed. Cannot update secret value.")
            
            # Get master key
            master_key_hex = await self.state_manager.get_master_key()
            if not master_key_hex:
                raise ValueError("No master key available.")
            
            master_key = bytes.fromhex(master_key_hex)
            
            # Generate new DEK for the updated secret
            dek = os.urandom(32)
            
            # Encrypt the new secret value with the DEK
            secret_nonce, encrypted_secret = self.crypto_service.aesgcm_encrypt(dek, update_data["value"].encode())
            
            # Encrypt the DEK with the master key
            dek_nonce, encrypted_dek = self.crypto_service.aesgcm_encrypt(master_key, dek)
            
            # Store the new encrypted DEK
            dek_data = {
                "encrypted_dek": encrypted_dek.hex(),
                "nonce": dek_nonce.hex()
            }
            dek_record = await self.storage_client.create_dek(dek_data, jwt_token)
            
            # Update the encrypted value and DEK reference
            final_update_data["dek_id"] = dek_record["id"]
            final_update_data["encrypted_value"] = json.dumps({
                "nonce": secret_nonce.hex(),
                "ciphertext": encrypted_secret.hex()
            })
            
            # Clear sensitive data
            del dek, master_key
        
        if not final_update_data:
            raise ValueError("No fields to update")
        
        result = await self.storage_client.update_secret(secret_id, final_update_data, jwt_token)
        
        if not result:
            raise ValueError("Secret not found")
        
        if 'user_id' in result:
            result['user_id'] = str(result['user_id'])
        
        return result

    async def delete_secret(self, secret_id: str, jwt_token: str) -> bool:
        """
        Delete a secret
        """
        logger.info(f"Deleting secret {secret_id}")
        
        deleted = await self.storage_client.delete_secret(secret_id, jwt_token)
        
        if not deleted:
            raise ValueError("Secret not found")
        
        return True