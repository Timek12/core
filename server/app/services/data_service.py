from typing import List, Dict, Optional
import os
import json
import logging

from app.clients.storage_client import StorageClient
from app.utils.redis_state import RedisStateManager
from app.utils.data_helpers import parse_metadata_json
from app.services.crypto_service import CryptoService
from app.dto.data import DataCreateRequest, DataUpdateRequest, DataType

logger = logging.getLogger(__name__)

class DataService:
    def __init__(self, storage_client: StorageClient = None, state_manager: RedisStateManager = None):
        self.storage_client = storage_client or StorageClient()
        self.state_manager = state_manager
        self.crypto_service = CryptoService()

    async def create_data(
        self, 
        data: DataCreateRequest,
        jwt_token: str
    ) -> Dict:
        """
        Create a new typed data using DEK (Data Encryption Key) architecture:
        1. Validate vault is unsealed
        2. Retrieve master key from Redis
        3. Generate a random DEK (32 bytes)
        4. Encrypt the data payload with the DEK (using AES-GCM)
        5. Encrypt the DEK with the master key (using AES-GCM)
        6. Store encrypted DEK in database
        7. Get master key ID from storage
        8. Store encrypted data with reference to DEK and master key
        """
        logger.info(f"Creating data '{data.name}' of type {data.data_type}")
        
        # Step 1: Check if vault is unsealed
        if await self.state_manager.is_vault_sealed():
            raise ValueError("Vault is sealed. Please unseal the vault first.")
        
        # Step 2: Get master key from Redis
        master_key_hex = await self.state_manager.get_master_key()
        if not master_key_hex:
            vault_status = await self.state_manager.get_vault_status()
            logger.error(f"Master key not found. Vault status: {vault_status}")
            raise ValueError("No master key available. Vault may need to be unsealed.")
        
        master_key = bytes.fromhex(master_key_hex)
        
        # Prepare payload and metadata based on type
        payload = {}
        metadata = {}
        
        if data.data_type == DataType.TEXT_WITH_TTL:
            payload = {"fields": [f.dict() for f in data.fields]} if data.fields else {}
            
        elif data.data_type == DataType.KUBERNETES:
            payload = {"data": [f.dict() for f in data.data]} if data.data else {}
            metadata["namespace"] = data.namespace
            
        elif data.data_type == DataType.CREDENTIALS:
            payload = {"password": data.password}
            metadata["username"] = data.username
            metadata["url"] = data.url
            
        elif data.data_type == DataType.API_KEY:
            payload = {"apiKey": data.apiKey}
            
        elif data.data_type == DataType.SSH_KEY:
            payload = {
                "privateKey": data.privateKey,
                "passphrase": data.passphrase
            }
            if data.publicKey:
                payload["publicKey"] = data.publicKey
                metadata["hasPublicKey"] = True
            metadata["host"] = data.host
            metadata["username"] = data.username
            
        elif data.data_type == DataType.CERTIFICATE:
            payload = {
                "certificate": data.certificate,
                "privateKey": data.privateKey,
                "passphrase": data.passphrase
            }
            if data.chain:
                payload["chain"] = data.chain
                metadata["hasChain"] = True

        # Serialize payload
        payload_json = json.dumps(payload)
        
        # Step 3: Generate a random DEK (Data Encryption Key)
        dek = os.urandom(32)  # 256-bit key
        
        # Step 4: Encrypt the data value with the DEK
        data_nonce, encrypted_data_val = self.crypto_service.aesgcm_encrypt(dek, payload_json.encode())
        
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
        
        # Step 8: Store the data with reference to the DEK
        storage_data = {
            "name": data.name,
            "description": data.description or "",
            "data_type": data.data_type,
            "key_id": master_key_id,
            "dek_id": str(dek_record["id"]),
            "encrypted_value": json.dumps({
                "nonce": data_nonce.hex(),
                "ciphertext": encrypted_data_val.hex()
            }),
            "metadata_json": json.dumps(metadata),
            "ttl_seconds": data.ttl,
            "version": 1,
        }
        
        result = await self.storage_client.create_data(storage_data, jwt_token)
        logger.info(f"Data created successfully with ID: {result.get('id')}")
        
        if 'user_id' in result:
            result['user_id'] = str(result['user_id'])
            
        # Add decrypted data to result for response
        result['decrypted_data'] = payload
        
        result['metadata'] = parse_metadata_json(result.get('metadata_json')) or metadata
        
        # Clear sensitive data from memory
        del dek, master_key
        
        return result

    async def _decrypt_data_item(self, data_item: Dict, master_key: bytes) -> None:
        """Decrypt a single data item in place"""
        try:
            if not data_item.get("dek_id"):
                data_item["decrypted_data"] = {}
                data_item["decrypt_error"] = "No DEK associated with this data"
                return
            
            dek_record = await self.storage_client.get_dek(data_item["dek_id"])
            
            dek_nonce = bytes.fromhex(dek_record["nonce"])
            encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
            dek = self.crypto_service.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
            
            encrypted_data = json.loads(data_item["encrypted_value"])
            data_nonce = bytes.fromhex(encrypted_data["nonce"])
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            decrypted = self.crypto_service.aesgcm_decrypt(dek, data_nonce, ciphertext)
            
            data_item["decrypted_data"] = json.loads(decrypted.decode())
            
            del dek
        except Exception as e:
            logger.error(f"Error decrypting data {data_item.get('id')}: {e}")
            data_item["decrypted_data"] = {}
            data_item["decrypt_error"] = str(e)

    async def get_data_for_user(self, user_id: str, jwt_token: str, data_type: Optional[str] = None) -> List[Dict]:
        """
        Get all user data and decrypt them using DEK architecture:
        1. Fetch all data for user from storage
        2. Check if vault is unsealed
        3. For each data item:
           a. Fetch its DEK from storage
           b. Decrypt DEK with master key
           c. Decrypt data value with DEK
           d. Add decrypted value to response
        """
        logger.info(f"Fetching data for user {user_id}")
        
        # Step 1: Fetch data from storage
        data_list = await self.storage_client.get_all_data(data_type=data_type, jwt_token=jwt_token)
        
        # Step 2: Decrypt data if vault is unsealed
        if not await self.state_manager.is_vault_sealed():
            master_key_hex = await self.state_manager.get_master_key()
            if master_key_hex:
                master_key = bytes.fromhex(master_key_hex)
                
                for data_item in data_list:
                    data_item['metadata'] = parse_metadata_json(data_item.get('metadata_json'))
                    await self._decrypt_data_item(data_item, master_key)
                
                del master_key
        
        else:
            for data_item in data_list:
                data_item["decrypted_data"] = {}
                data_item['metadata'] = parse_metadata_json(data_item.get('metadata_json'))
        
        for data_item in data_list:
            if 'user_id' in data_item:
                data_item['user_id'] = str(data_item['user_id'])
        
        return data_list

    async def get_data(self, data_id: str, jwt_token: str) -> Dict:
        """
        Get a specific data and decrypt it
        """
        logger.info(f"Fetching data {data_id}")
        
        data_item = await self.storage_client.get_data(data_id, jwt_token)
        
        data_item['metadata'] = parse_metadata_json(data_item.get('metadata_json'))
        
        if not await self.state_manager.is_vault_sealed():
            master_key_hex = await self.state_manager.get_master_key()
            if master_key_hex:
                master_key = bytes.fromhex(master_key_hex)
                await self._decrypt_data_item(data_item, master_key)
                del master_key
            else:
                data_item["decrypted_data"] = {}
        else:
            data_item["decrypted_data"] = {}
        
        if 'user_id' in data_item:
            data_item['user_id'] = str(data_item['user_id'])
            
        return data_item

    async def update_data(
        self, 
        data_id: str, 
        update_request: DataUpdateRequest, 
        jwt_token: str
    ) -> Dict:
        """
        Update a data. If payload fields are provided, creates new DEK and re-encrypts.
        """
        logger.info(f"Updating data {data_id}")
        
        # Fetch existing data to get type and current values
        current_data = await self.get_data(data_id, jwt_token)
        data_type = current_data["data_type"]
        
        final_update_data = {}
        metadata = {}
        
        # Handle metadata updates
        if update_request.name:
            final_update_data["name"] = update_request.name
        if update_request.description is not None:
            final_update_data["description"] = update_request.description
            
        # Check if we need to update payload
        payload_changed = False
        payload = {}
        
        # Get current decrypted data
        current_decrypted = current_data.get("decrypted_data", {})
        
        # Helper to check and update field
        def update_field(field_name, request_val):
            nonlocal payload_changed
            if request_val is not None:
                payload[field_name] = request_val
                payload_changed = True
            elif field_name in current_decrypted:
                payload[field_name] = current_decrypted[field_name]

        # Helper for list of objects (fields, data)
        def update_list_field(field_name, request_val):
            nonlocal payload_changed
            if request_val is not None:
                payload[field_name] = [f.dict() for f in request_val]
                payload_changed = True
            elif field_name in current_decrypted:
                payload[field_name] = current_decrypted[field_name]

        if data_type == DataType.TEXT_WITH_TTL:
            update_list_field("fields", update_request.fields)
            
        elif data_type == DataType.KUBERNETES:
            update_list_field("data", update_request.data)
            if update_request.namespace:
                metadata["namespace"] = update_request.namespace
            
        elif data_type == DataType.CREDENTIALS:
            update_field("password", update_request.password)
            if update_request.username:
                metadata["username"] = update_request.username
            if update_request.url:
                metadata["url"] = update_request.url
            
        elif data_type == DataType.API_KEY:
            update_field("apiKey", update_request.apiKey)
            
        elif data_type == DataType.SSH_KEY:
            update_field("privateKey", update_request.privateKey)
            update_field("passphrase", update_request.passphrase)
            update_field("publicKey", update_request.publicKey)
            if update_request.publicKey:
                metadata["hasPublicKey"] = True
            if update_request.host:
                metadata["host"] = update_request.host
            if update_request.username:
                metadata["username"] = update_request.username
            
        elif data_type == DataType.CERTIFICATE:
            update_field("certificate", update_request.certificate)
            update_field("privateKey", update_request.privateKey)
            update_field("passphrase", update_request.passphrase)
            update_field("chain", update_request.chain)
            if update_request.chain:
                metadata["hasChain"] = True

        # Handle re-encryption if payload changed
        if payload_changed:
            # Check if vault is unsealed
            if await self.state_manager.is_vault_sealed():
                raise ValueError("Vault is sealed. Cannot update data value.")
            
            # Get master key
            master_key_hex = await self.state_manager.get_master_key()
            if not master_key_hex:
                raise ValueError("No master key available.")
            
            master_key = bytes.fromhex(master_key_hex)
            
            # Generate new DEK for the updated data
            dek = os.urandom(32)
            
            # Serialize payload
            payload_json = json.dumps(payload)
            
            # Encrypt the new data value with the DEK
            data_nonce, encrypted_data_val = self.crypto_service.aesgcm_encrypt(dek, payload_json.encode())
            
            # Encrypt the DEK with the master key
            dek_nonce, encrypted_dek = self.crypto_service.aesgcm_encrypt(master_key, dek)
            
            # Store the new encrypted DEK
            dek_data = {
                "encrypted_dek": encrypted_dek.hex(),
                "nonce": dek_nonce.hex()
            }
            dek_record = await self.storage_client.create_dek(dek_data, jwt_token)
            
            final_update_data["dek_id"] = str(dek_record["id"])
            final_update_data["encrypted_value"] = json.dumps({
                "nonce": data_nonce.hex(),
                "ciphertext": encrypted_data_val.hex()
            })
            
            # Clear sensitive data
            del dek, master_key

        if metadata:
            current_metadata = parse_metadata_json(current_data.get("metadata_json"))
            current_metadata.update(metadata)
            final_update_data["metadata_json"] = json.dumps(current_metadata)

        if update_request.ttl is not None:
            final_update_data["ttl_seconds"] = update_request.ttl
            
        if not final_update_data:
            return current_data
            
        result = await self.storage_client.update_data(data_id, final_update_data, jwt_token)
        
        return await self.get_data(data_id, jwt_token)

    async def delete_data(self, data_id: str, jwt_token: str) -> bool:
        """
        Delete a data
        """
        logger.info(f"Deleting data {data_id}")
        
        deleted = await self.storage_client.delete_data(data_id, jwt_token)
        
        if not deleted:
            raise ValueError("Data not found")
        
        return True