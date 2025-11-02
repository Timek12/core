import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Dict, Tuple
from datetime import datetime
import os
import json
import logging

from app.clients.storage_client import StorageClient
from app.utils.redis_state import RedisStateManager

logger = logging.getLogger(__name__)

class CryptoService:
    def __init__(self, storage_client: StorageClient = None, state_manager: RedisStateManager = None):
        self.storage_client = storage_client or StorageClient()
        self.state_manager = state_manager

    @staticmethod
    def hkdf_derive(key: bytes, salt: bytes, info: bytes = b"123456789", length: int = 32) -> bytes:
        """Derive a key using HKDF"""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        return hkdf.derive(key)

    @staticmethod
    def aesgcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ct

    @staticmethod
    def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data using AES-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    async def initialize_vault(self, external_token: str, user_id: str, jwt_token: str) -> Dict:
        """
        Initialize the vault with hierarchical key structure:
        1. Generate Root Key (32 bytes random)
        2. Generate Master Key (32 bytes random)
        3. Derive KEK from external token using HKDF
        4. Encrypt Root Key with KEK
        5. Encrypt Master Key with Root Key
        6. Store both encrypted keys in storage service
        7. Store metadata in Redis
        """
        logger.info(f"Initializing vault for user {user_id}")
        
        # Check if already initialized
        if await self.state_manager.is_vault_initialized():
            raise ValueError("Vault already initialized")

        # Step 1 & 2: Generate keys
        root_key = os.urandom(32)
        master_key = os.urandom(32)
        
        # Step 3: Derive KEK from external token
        salt = os.urandom(16)
        kek = self.hkdf_derive(external_token.encode("utf-8"), salt)

        # Step 4: Encrypt root key with KEK
        root_nonce, root_ct = self.aesgcm_encrypt(kek, root_key)
        
        # Step 5: Encrypt master key with root key
        master_nonce, master_ct = self.aesgcm_encrypt(root_key, master_key)

        # Step 6: Store keys in storage service
        root_key_data = {
            'key_type': 'root',
            'encrypted_key': root_ct.hex(),
            'nonce': root_nonce.hex(),
            'version': 1,
            'status': 'active',
            'meta': json.dumps({"salt": salt.hex(), "kek_derived": True})
        }
        
        master_key_data = {
            'key_type': 'master', 
            'encrypted_key': master_ct.hex(),
            'nonce': master_nonce.hex(),
            'version': 1,
            'status': 'active',
            'meta': json.dumps({"derived_from": "root"})
        }

        root_response = await self.storage_client.create_key(root_key_data, jwt_token)
        master_response = await self.storage_client.create_key(master_key_data, jwt_token)

        # Step 7: Store root key metadata in Redis
        await self.state_manager.store_root_key_info({
            "storage_id": root_response['id'],
            "salt": salt.hex(),
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat()
        })

        # Mark vault as initialized and sealed
        await self.state_manager.set_vault_initialized(user_id)
        await self.state_manager.set_vault_sealed(True, user_id)

        # Clear sensitive data from memory
        del root_key, master_key, kek

        logger.info(f"Vault initialized successfully. Root ID: {root_response['id']}, Master ID: {master_response['id']}")
        
        return {
            "root_id": root_response['id'],
            "master_id": master_response['id'],
            "sealed": True,
            "initialized": True
        }

    async def unseal_vault(self, external_token: str, user_id: str, jwt_token: str) -> Dict:
        """
        Unseal the vault:
        1. Fetch root key metadata from Redis
        2. Fetch encrypted root key from storage
        3. Derive KEK from external token (same as init)
        4. Decrypt root key with KEK
        5. Fetch encrypted master key from storage
        6. Decrypt master key with root key
        7. Store decrypted master key in Redis with TTL
        8. Mark vault as unsealed
        """
        logger.info(f"Unsealing vault for user {user_id}")
        
        # Check if initialized
        if not await self.state_manager.is_vault_initialized():
            raise ValueError("Vault not initialized")

        # Step 1: Get root key info from Redis
        root_key_info = await self.state_manager.get_root_key_info()
        if not root_key_info:
            raise ValueError("Root key metadata not found")

        storage_id = root_key_info["storage_id"]
        if isinstance(storage_id, str):
            storage_id = uuid.UUID(storage_id)
        
        root_key_data = await self.storage_client.get_key_by_id(storage_id, jwt_token)
    
        
        # Step 5: Find and fetch master key
        master_keys = await self.storage_client.get_all_keys(key_type="master", jwt_token=jwt_token)
        if not master_keys:
            raise ValueError("Master key not found")
        master_key_data = master_keys[0]

        # Step 3: Derive KEK from external token
        salt = bytes.fromhex(root_key_info["salt"])
        kek = self.hkdf_derive(external_token.encode("utf-8"), salt)
        
        # Step 4: Decrypt root key
        root_ct = bytes.fromhex(root_key_data["encrypted_key"])
        root_nonce = bytes.fromhex(root_key_data["nonce"])

        try:
            root_key = self.aesgcm_decrypt(kek, root_nonce, root_ct)
        except Exception as e:
            logger.error(f"Failed to decrypt root key: {e}")
            raise ValueError("Invalid external token")

        # Step 6: Decrypt master key with root key
        master_ct = bytes.fromhex(master_key_data["encrypted_key"])
        master_nonce = bytes.fromhex(master_key_data["nonce"])

        try:
            master_key = self.aesgcm_decrypt(root_key, master_nonce, master_ct)
        except Exception as e:
            logger.error(f"Failed to decrypt master key: {e}")
            raise ValueError("Master key decryption failed")

        # Step 7: Store decrypted master key in Redis with TTL
        await self.state_manager.store_master_key(master_key.hex(), ttl_hours=1)

        # Step 8: Mark vault as unsealed
        await self.state_manager.set_vault_sealed(False, user_id)

        # Clear sensitive data from memory
        del root_key, master_key, kek

        logger.info("Vault unsealed successfully")
        
        return {
            "sealed": False,
            "initialized": True
        }

    async def seal_vault(self, user_id: str) -> Dict:
        """
        Seal the vault:
        1. Clear all sensitive keys from Redis (master key, derived keys)
        2. Mark vault as sealed
        """
        logger.info(f"Sealing vault for user {user_id}")
        
        # Clear sensitive keys
        await self.state_manager.clear_sensitive_keys()
        
        # Mark vault as sealed
        await self.state_manager.set_vault_sealed(True, user_id)

        logger.info("Vault sealed successfully")
        
        return {
            "sealed": True,
            "initialized": await self.state_manager.is_vault_initialized()
        }

    async def get_vault_status(self) -> Dict:
        """
        Get current vault status from Redis
        """
        is_initialized = await self.state_manager.is_vault_initialized()
        is_sealed = await self.state_manager.is_vault_sealed()
        
        return {
            "sealed": is_sealed,
            "initialized": is_initialized,
            "version": "1.0"
        }