import base64
import json
import os
import secrets
import uuid
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.clients.storage_client import StorageClient
from app.utils.redis_state import RedisStateManager

logger = logging.getLogger(__name__)


class CryptoService:
    def __init__(self, storage_client: Optional[StorageClient] = None, state_manager: Optional[RedisStateManager] = None):
        self.storage_client = storage_client or StorageClient()
        self.state_manager = state_manager

    def _ensure_state_manager(self) -> RedisStateManager:
        if not self.state_manager:
            raise ValueError("RedisStateManager is required")
        return self.state_manager

    @staticmethod
    def hkdf_derive(key: bytes, salt: bytes, info: bytes = b"123456789", length: int = 32) -> bytes:
        """Derive key using HKDF-SHA256."""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        return hkdf.derive(key)

    @staticmethod
    def aesgcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data with AES-GCM. Returns (nonce, ciphertext)."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ct

    @staticmethod
    def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt AES-GCM data."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    async def initialize_vault(self, external_token: str, user_id: str, jwt_token: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict:
        """Initialize vault: generate keys, encrypt with KEK, store in Storage/Redis."""
        logger.info(f"Initializing vault for user {user_id}")
        
        state_manager = self._ensure_state_manager()
        if await state_manager.is_vault_initialized():
            raise ValueError("Vault already initialized")

        # Generate keys
        root_key = os.urandom(32)
        master_key = os.urandom(32)
        
        # Derive KEK
        salt = os.urandom(16)
        kek = self.hkdf_derive(external_token.encode("utf-8"), salt)

        # Encrypt keys
        root_nonce, root_ct = self.aesgcm_encrypt(kek, root_key)
        master_nonce, master_ct = self.aesgcm_encrypt(root_key, master_key)

        # Store in Storage Service
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

        # Store metadata in Redis
        await state_manager.store_root_key_info({
            "storage_id": root_response['id'],
            "salt": salt.hex(),
            "created_by": user_id,
            "created_at": datetime.utcnow().isoformat()
        })

        # Set status
        await state_manager.set_vault_initialized(user_id, ip_address, user_agent)
        await state_manager.set_vault_sealed(True, user_id, ip_address, user_agent)

        # Cleanup
        del root_key, master_key, kek

        logger.info(f"Vault initialized. Root ID: {root_response['id']}")
        
        return {
            "root_id": root_response['id'],
            "master_id": master_response['id'],
            "sealed": True,
            "initialized": True
        }

    async def unseal_vault(self, external_token: str, user_id: str, jwt_token: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict:
        """Unseal vault: decrypt Root Key with KEK, then Master Key, cache Master Key in Redis."""
        logger.info(f"Unsealing vault for user {user_id}")
        
        state_manager = self._ensure_state_manager()
        if not await state_manager.is_vault_initialized():
            raise ValueError("Vault not initialized")

        # Get Root Key info
        root_key_info = await state_manager.get_root_key_info()
        if not root_key_info:
            raise ValueError("Root key metadata not found")

        storage_id = root_key_info["storage_id"]
        if isinstance(storage_id, str):
            storage_id = uuid.UUID(storage_id)
        
        root_key_data = await self.storage_client.get_key_by_id(storage_id, jwt_token)
    
        # Get Master Key info
        master_keys = await self.storage_client.get_all_keys(key_type="master", jwt_token=jwt_token)
        if not master_keys:
            raise ValueError("Master key not found")
        master_key_data = master_keys[0]

        # Derive KEK
        salt = bytes.fromhex(root_key_info["salt"])
        kek = self.hkdf_derive(external_token.encode("utf-8"), salt)
        
        # Decrypt Root Key
        root_ct = bytes.fromhex(root_key_data["encrypted_key"])
        root_nonce = bytes.fromhex(root_key_data["nonce"])

        try:
            root_key = self.aesgcm_decrypt(kek, root_nonce, root_ct)
        except Exception as e:
            logger.error(f"Failed to decrypt root key: {e}")
            raise ValueError("Invalid external token")

        # Decrypt Master Key
        master_ct = bytes.fromhex(master_key_data["encrypted_key"])
        master_nonce = bytes.fromhex(master_key_data["nonce"])

        try:
            master_key = self.aesgcm_decrypt(root_key, master_nonce, master_ct)
        except Exception as e:
            logger.error(f"Failed to decrypt master key: {e}")
            raise ValueError("Master key decryption failed")

        # Cache Master Key
        await state_manager.store_master_key(master_key.hex())
        await state_manager.set_vault_sealed(False, user_id, ip_address, user_agent)

        # Cleanup
        del root_key, master_key, kek

        logger.info("Vault unsealed successfully")
        
        return {
            "sealed": False,
            "initialized": True
        }

    async def seal_vault(self, user_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict:
        """Seal vault: clear sensitive keys from Redis."""
        logger.info(f"Sealing vault for user {user_id}")
        
        state_manager = self._ensure_state_manager()
        await state_manager.clear_sensitive_keys()
        await state_manager.set_vault_sealed(True, user_id, ip_address, user_agent)

        logger.info("Vault sealed successfully")
        
        return {
            "sealed": True,
            "initialized": await state_manager.is_vault_initialized()
        }

    async def get_vault_status(self) -> Dict:
        """Get vault status."""
        state_manager = self._ensure_state_manager()
        return {
            "sealed": await state_manager.is_vault_sealed(),
            "initialized": await state_manager.is_vault_initialized(),
            "version": "1.0"
        }


    async def encrypt_data(self, plaintext: str, jwt_token: str) -> Dict[str, Any]:
        """Encrypt data: generate DEK, encrypt DEK (Master Key), encrypt data (DEK)."""
        state_manager = self._ensure_state_manager()
        master_key_hex = await state_manager.get_master_key()
        if not master_key_hex:
            raise ValueError("Vault is sealed")
        master_key = bytes.fromhex(master_key_hex)

        # Generate & Encrypt DEK
        dek = secrets.token_bytes(32)
        dek_nonce, encrypted_dek = self.aesgcm_encrypt(master_key, dek)
        
        # Store DEK
        dek_payload = {
            "encrypted_dek": encrypted_dek.hex(),
            "nonce": dek_nonce.hex()
        }
        dek_record = await self.storage_client.create_dek(dek_payload, jwt_token)
        
        # Encrypt Data
        data_nonce, ciphertext = self.aesgcm_encrypt(dek, plaintext.encode("utf-8"))
        
        # Prepend nonce for compatibility
        combined_ciphertext = data_nonce + ciphertext
        
        return {
            "ciphertext_b64": base64.b64encode(combined_ciphertext).decode("utf-8"),
            "dek_id": dek_record["id"],
            "algorithm": "AES-GCM",
            "nonce_b64": base64.b64encode(data_nonce).decode("utf-8"),
            "created_at": datetime.utcnow().isoformat()
        }

    async def decrypt_data(self, ciphertext_b64: str, dek_id: int, nonce_b64: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt data: fetch DEK, decrypt DEK (Master Key), decrypt data (DEK)."""
        state_manager = self._ensure_state_manager()
        master_key_hex = await state_manager.get_master_key()
        if not master_key_hex:
            raise ValueError("Vault is sealed")
        master_key = bytes.fromhex(master_key_hex)

        # Fetch & Decrypt DEK
        dek_record = await self.storage_client.get_dek(str(dek_id))
        dek_nonce = bytes.fromhex(dek_record["nonce"])
        encrypted_dek = bytes.fromhex(dek_record["encrypted_dek"])
        
        dek = self.aesgcm_decrypt(master_key, dek_nonce, encrypted_dek)
        
        # Prepare Ciphertext & Nonce
        ciphertext = base64.b64decode(ciphertext_b64)
        
        if not nonce_b64:
             nonce = ciphertext[:12]
             actual_ciphertext = ciphertext[12:]
        else:
            nonce = base64.b64decode(nonce_b64)
            actual_ciphertext = ciphertext

        # Decrypt Data
        plaintext = self.aesgcm_decrypt(dek, nonce, actual_ciphertext)
        
        return {
            "plaintext": plaintext.decode("utf-8"),
            "dek_id": dek_id,
            "algorithm": "AES-GCM",
            "decrypted_at": datetime.utcnow().isoformat()
        }
