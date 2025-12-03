import logging
import redis.asyncio as redis
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class RedisVaultManager:
    def __init__(self, client: redis.Redis, audit_logger: Any, key_manager: Any):
        self.client = client
        self.audit_logger = audit_logger
        self.key_manager = key_manager
        self.VAULT_PREFIX = "vault:"
        
    async def is_vault_sealed(self) -> bool:
        """Check if vault is sealed"""
        try:
            master_key = await self.key_manager.get_master_key()
            if not master_key:
                await self.set_vault_sealed(True)
                return True
        
            sealed = await self.client.get(f"{self.VAULT_PREFIX}sealed")
            return sealed == "true" if sealed else True  # Default to sealed
        except Exception as e:
            logger.error(f"Error checking vault seal status: {e}")
            return True

    async def set_vault_sealed(self, sealed: bool, user_id: Optional[str] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None):
        """Set vault seal status with audit trail"""
        try:
            # Check if status is actually changing to avoid duplicate logs
            current_sealed = await self.client.get(f"{self.VAULT_PREFIX}sealed")
            new_status = "true" if sealed else "false"
            
            if current_sealed == new_status:
                return

            pipe = self.client.pipeline()
            
            # Set seal status
            pipe.set(f"{self.VAULT_PREFIX}sealed", new_status)
            
            # Set timestamp
            timestamp = datetime.utcnow().isoformat()
            if sealed:
                pipe.set(f"{self.VAULT_PREFIX}last_seal_time", timestamp)
            else:
                pipe.set(f"{self.VAULT_PREFIX}last_unseal_time", timestamp)
            
            await pipe.execute()
            
            # Audit Log
            await self.audit_logger.log_event(
                action="seal_vault" if sealed else "unseal_vault",
                status="success",
                user_id=user_id,
                resource_type="vault",
                ip_address=ip_address,
                user_agent=user_agent,
                details=f"Vault {'sealed' if sealed else 'unsealed'}"
            )
            
            logger.info(f"Vault {'sealed' if sealed else 'unsealed'} by user {user_id}")
            
        except Exception as e:
            logger.error(f"Error setting vault seal status: {e}")
            raise

    async def is_vault_initialized(self) -> bool:
        """Check if vault is initialized"""
        try:
            initialized = await self.client.get(f"{self.VAULT_PREFIX}initialized")
            return initialized == "true" if initialized else False
        except Exception as e:
            logger.error(f"Error checking vault initialization: {e}")
            return False

    async def set_vault_initialized(self, user_id: Optional[str] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None):
        """Mark vault as initialized"""
        try:
            pipe = self.client.pipeline()
            
            pipe.set(f"{self.VAULT_PREFIX}initialized", "true")
            pipe.set(f"{self.VAULT_PREFIX}init_time", datetime.utcnow().isoformat())
            
            await pipe.execute()
            
            # Audit Log
            await self.audit_logger.log_event(
                action="init_vault",
                status="success",
                user_id=user_id,
                resource_type="vault",
                ip_address=ip_address,
                user_agent=user_agent,
                details="Vault initialized"
            )
            
            logger.info(f"Vault initialized by user {user_id}")
            
        except Exception as e:
            logger.error(f"Error setting vault initialization: {e}")
            raise

    async def get_vault_status(self) -> Dict[str, Any]:
        """Get comprehensive vault status"""
        try:
            pipe = self.client.pipeline()
            pipe.get(f"{self.VAULT_PREFIX}sealed")
            pipe.get(f"{self.VAULT_PREFIX}initialized") 
            pipe.get(f"{self.VAULT_PREFIX}last_seal_time")
            pipe.get(f"{self.VAULT_PREFIX}last_unseal_time")
            pipe.get(f"{self.VAULT_PREFIX}init_time")
            
            pipe.exists("vault:keys:master")
            
            results = await pipe.execute()
            
            return {
                "sealed": results[0] == "true" if results[0] else True,
                "initialized": results[1] == "true" if results[1] else False,
                "last_seal_time": results[2],
                "last_unseal_time": results[3], 
                "init_time": results[4],
                "master_key_in_cache": bool(results[5]),
                "redis_connected": True
            }
            
        except Exception as e:
            logger.error(f"Error getting vault status: {e}")
            return {
                "sealed": True,
                "initialized": False,
                "redis_connected": False,
                "error": str(e)
            }
