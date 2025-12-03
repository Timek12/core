import os
import json
import logging
import redis.asyncio as redis
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class RedisKeyManager:
    def __init__(self, client: redis.Redis):
        self.client = client
        self.KEY_PREFIX = "vault:keys:"
        
        # Encryption key for sensitive data
        encryption_key = os.getenv('VAULT_ENCRYPTION_KEY') or os.getenv('ENCRYPTION_KEY')
        if not encryption_key:
            logger.warning("No VAULT_ENCRYPTION_KEY provided, generating temporary key")
            encryption_key = Fernet.generate_key().decode()
        
        try:
            self.cipher = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        except Exception as e:
            logger.error(f"Invalid encryption key format: {e}")
            encryption_key = Fernet.generate_key().decode()
            self.cipher = Fernet(encryption_key.encode())

    def _encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data before storing in Redis"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data after retrieving from Redis"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    async def store_master_key(self, master_key_hex: str):
        """Store encrypted master key for security"""
        try:
            key = f"{self.KEY_PREFIX}master"
            logger.info(f"Storing master key at Redis key: {key}, input length: {len(master_key_hex)}")
            
            # Double encrypt the master key
            double_encrypted = self._encrypt_sensitive_data(master_key_hex)
            logger.info(f"Master key encrypted, encrypted length: {len(double_encrypted)}")
            
            # Store master key with 1 hour TTL
            await self.client.set(
                key,
                double_encrypted,
                ex=3600  # 1 hour TTL
            )
            
            logger.info(f"Master key stored successfully at {key}")
            
        except Exception as e:
            logger.error(f"Error storing master key: {e}", exc_info=True)
            raise

    async def get_master_key(self) -> Optional[str]:
        """Retrieve and decrypt master key"""
        try:
            key = f"{self.KEY_PREFIX}master"
            logger.info(f"Attempting to get master key from Redis with key: {key}")
            double_encrypted = await self.client.get(key)
            if not double_encrypted:
                logger.warning(f"Master key not found in Redis at key: {key}")
                return None
            
            logger.info("Master key found in Redis, decrypting...")
            decrypted = self._decrypt_sensitive_data(double_encrypted)
            logger.info(f"Master key successfully decrypted, length: {len(decrypted) if decrypted else 0}")
            return decrypted
            
        except Exception as e:
            logger.error(f"Error retrieving master key: {e}", exc_info=True)
            return None

    async def store_root_key_info(self, root_key_info: Dict[str, Any]):
        """Store root key metadata (not the key itself)"""
        try:
            await self.client.set(
                f"{self.KEY_PREFIX}root_info",
                json.dumps(root_key_info)
            )
            logger.info("Root key info stored")
        except Exception as e:
            logger.error(f"Error storing root key info: {e}")
            raise

    async def get_root_key_info(self) -> Optional[Dict[str, Any]]:
        """Get root key metadata"""
        try:
            info = await self.client.get(f"{self.KEY_PREFIX}root_info")
            return json.loads(info) if info else None
        except Exception as e:
            logger.error(f"Error retrieving root key info: {e}")
            return None

    async def clear_sensitive_keys(self):
        """Clear all sensitive keys from memory (on seal)"""
        try:
            pipe = self.client.pipeline()
            pipe.delete(f"{self.KEY_PREFIX}master")
            await pipe.execute()
            
            logger.info("Sensitive keys cleared from Redis")
            
        except Exception as e:
            logger.error(f"Error clearing sensitive keys: {e}")
