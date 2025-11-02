import redis.asyncio as redis
import json
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class RedisStateManager:
    """
    Redis state manager with security features:
    - Encrypted sensitive data storage
    - Connection pooling and retry logic
    - TTL management for sensitive keys
    - Atomic operations for consistency
    """
    
    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        self.redis_db = int(os.getenv('REDIS_DB', 0))
        
        # Encryption key for sensitive data
        encryption_key = os.getenv('VAULT_ENCRYPTION_KEY') or os.getenv('ENCRYPTION_KEY')
        if not encryption_key:
            # Generate a key if not provided
            logger.warning("No VAULT_ENCRYPTION_KEY provided, generating temporary key")
            encryption_key = Fernet.generate_key().decode()
        
        # Ensure the key is properly formatted
        try:
            self.cipher = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        except Exception as e:
            logger.error(f"Invalid encryption key format: {e}")
            # Generate a valid key as fallback
            encryption_key = Fernet.generate_key().decode()
            self.cipher = Fernet(encryption_key.encode())
        
        # Redis connection pool
        self.pool = None
        self.redis_client = None
        
        # Key prefixes for organization
        self.VAULT_PREFIX = "vault:"
        self.KEY_PREFIX = "vault:keys:"
        self.SESSION_PREFIX = "vault:sessions:"
        self.AUDIT_PREFIX = "vault:audit:"
        
    async def initialize(self):
        """Initialize Redis connection pool"""
        try:
            # Build connection pool parameters
            pool_kwargs = {
                'host': self.redis_host,
                'port': self.redis_port,
                'password': self.redis_password,
                'db': self.redis_db,
                'decode_responses': True,
                'max_connections': 20,
                'retry_on_timeout': True,
                'socket_keepalive': True
            }
            
            # Add socket keepalive options with proper constants
            try:
                import socket
                pool_kwargs['socket_keepalive_options'] = {
                    socket.TCP_KEEPIDLE: 1,
                    socket.TCP_KEEPINTVL: 3,
                    socket.TCP_KEEPCNT: 5
                }
            except (AttributeError, OSError):
                # Skip keepalive options if not supported on this platform
                logger.warning("TCP keepalive options not supported on this platform")
            
            self.pool = redis.ConnectionPool(**pool_kwargs)
            
            self.redis_client = redis.Redis(connection_pool=self.pool)
            
            # Test connection
            await self.redis_client.ping()
            logger.info(f"Redis connected successfully to {self.redis_host}:{self.redis_port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def close(self):
        """Close Redis connections"""
        if self.redis_client:
            await self.redis_client.close()
        if self.pool:
            await self.pool.disconnect()

    def _encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data before storing in Redis"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data after retrieving from Redis"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    async def is_vault_sealed(self) -> bool:
        """Check if vault is sealed"""
        try:
            master_key = await self.get_master_key()
            if not master_key:
                await self.set_vault_sealed(True)
                return True
        
            sealed = await self.redis_client.get(f"{self.VAULT_PREFIX}sealed")
            return sealed == "true" if sealed else True  # Default to sealed
        except Exception as e:
            logger.error(f"Error checking vault seal status: {e}")
            return True

    async def set_vault_sealed(self, sealed: bool, user_id: Optional[str] = None):
        """Set vault seal status with audit trail"""
        try:
            pipe = self.redis_client.pipeline()
            
            # Set seal status
            pipe.set(f"{self.VAULT_PREFIX}sealed", "true" if sealed else "false")
            
            # Set timestamp
            timestamp = datetime.utcnow().isoformat()
            if sealed:
                pipe.set(f"{self.VAULT_PREFIX}last_seal_time", timestamp)
            else:
                pipe.set(f"{self.VAULT_PREFIX}last_unseal_time", timestamp)
            
            # Audit log
            audit_entry = {
                "action": "seal" if sealed else "unseal",
                "user_id": user_id,
                "timestamp": timestamp,
                "success": True
            }
            pipe.lpush(f"{self.AUDIT_PREFIX}seal_actions", json.dumps(audit_entry))
            pipe.ltrim(f"{self.AUDIT_PREFIX}seal_actions", 0, 99)  # Keep last 100 entries
            
            await pipe.execute()
            
            logger.info(f"Vault {'sealed' if sealed else 'unsealed'} by user {user_id}")
            
        except Exception as e:
            logger.error(f"Error setting vault seal status: {e}")
            raise

    async def is_vault_initialized(self) -> bool:
        """Check if vault is initialized"""
        try:
            initialized = await self.redis_client.get(f"{self.VAULT_PREFIX}initialized")
            return initialized == "true" if initialized else False
        except Exception as e:
            logger.error(f"Error checking vault initialization: {e}")
            return False

    async def set_vault_initialized(self, user_id: Optional[str] = None):
        """Mark vault as initialized"""
        try:
            pipe = self.redis_client.pipeline()
            
            pipe.set(f"{self.VAULT_PREFIX}initialized", "true")
            pipe.set(f"{self.VAULT_PREFIX}init_time", datetime.utcnow().isoformat())
            
            # Audit log
            audit_entry = {
                "action": "initialize",
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "success": True
            }
            pipe.lpush(f"{self.AUDIT_PREFIX}init_actions", json.dumps(audit_entry))
            
            await pipe.execute()
            
            logger.info(f"Vault initialized by user {user_id}")
            
        except Exception as e:
            logger.error(f"Error setting vault initialization: {e}")
            raise
    
    async def store_master_key(self, master_key_hex: str, ttl_hours: int = 1):
        """Store encrypted master key with TTL for security"""
        try:
            key = f"{self.KEY_PREFIX}master"
            logger.info(f"Storing master key at Redis key: {key}, input length: {len(master_key_hex)}")
            
            # Double encrypt the master key
            double_encrypted = self._encrypt_sensitive_data(master_key_hex)
            logger.info(f"Master key encrypted, encrypted length: {len(double_encrypted)}")
            
            # Store with TTL
            ttl_seconds = ttl_hours * 3600
            await self.redis_client.setex(
                key,
                ttl_seconds,
                double_encrypted
            )
            
            logger.info(f"Master key stored successfully at {key} with {ttl_hours}h TTL ({ttl_seconds}s)")
            
        except Exception as e:
            logger.error(f"Error storing master key: {e}", exc_info=True)
            raise

    async def get_master_key(self) -> Optional[str]:
        """Retrieve and decrypt master key"""
        try:
            key = f"{self.KEY_PREFIX}master"
            logger.info(f"Attempting to get master key from Redis with key: {key}")
            double_encrypted = await self.redis_client.get(key)
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
            await self.redis_client.set(
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
            info = await self.redis_client.get(f"{self.KEY_PREFIX}root_info")
            return json.loads(info) if info else None
        except Exception as e:
            logger.error(f"Error retrieving root key info: {e}")
            return None

    async def clear_sensitive_keys(self):
        """Clear all sensitive keys from memory (on seal)"""
        try:
            pipe = self.redis_client.pipeline()
            pipe.delete(f"{self.KEY_PREFIX}master")
            pipe.delete(f"{self.KEY_PREFIX}derived_keys")
            await pipe.execute()
            
            logger.info("Sensitive keys cleared from Redis")
            
        except Exception as e:
            logger.error(f"Error clearing sensitive keys: {e}")
    
    async def get_vault_status(self) -> Dict[str, Any]:
        """Get comprehensive vault status"""
        try:
            pipe = self.redis_client.pipeline()
            pipe.get(f"{self.VAULT_PREFIX}sealed")
            pipe.get(f"{self.VAULT_PREFIX}initialized") 
            pipe.get(f"{self.VAULT_PREFIX}last_seal_time")
            pipe.get(f"{self.VAULT_PREFIX}last_unseal_time")
            pipe.get(f"{self.VAULT_PREFIX}init_time")
            pipe.exists(f"{self.KEY_PREFIX}master")
            
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

    async def health_check(self) -> Dict[str, Any]:
        """Redis health check"""
        try:
            start_time = datetime.utcnow()
            await self.redis_client.ping()
            latency = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            info = await self.redis_client.info()
            
            return {
                "status": "healthy",
                "latency_ms": round(latency, 2),
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "unknown"),
                "uptime_in_seconds": info.get("uptime_in_seconds", 0)
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }

# Global instance
_state_manager = None

async def get_state_manager() -> RedisStateManager:
    """Get or create the global state manager instance"""
    global _state_manager
    if _state_manager is None:
        _state_manager = RedisStateManager()
        await _state_manager.initialize()
    return _state_manager

async def cleanup_state_manager():
    """Cleanup the global state manager"""
    global _state_manager
    if _state_manager:
        await _state_manager.close()
        _state_manager = None