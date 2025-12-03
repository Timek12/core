import redis.asyncio as redis
import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from app.clients.audit_logger import RedisAuditLogger
from app.clients.key_manager import RedisKeyManager
from app.clients.vault_manager import RedisVaultManager

logger = logging.getLogger(__name__)

class RedisStateManager:
    """
    Facade for Redis operations, delegating to specialized managers:
    - RedisAuditLogger: Audit logging
    - RedisKeyManager: Key management (Master/Root)
    - RedisVaultManager: Vault status (Sealed/Init)
    """
    
    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        self.redis_db = int(os.getenv('REDIS_DB', 0))
        
        self.pool = None
        self.redis_client = None
        
        # Sub-managers
        self.audit_logger: Optional[RedisAuditLogger] = None
        self.key_manager: Optional[RedisKeyManager] = None
        self.vault_manager: Optional[RedisVaultManager] = None
        
    async def initialize(self):
        """Initialize Redis connection pool and sub-managers"""
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
            
            # Add socket keepalive options
            try:
                import socket
                pool_kwargs['socket_keepalive_options'] = {
                    socket.TCP_KEEPIDLE: 1,
                    socket.TCP_KEEPINTVL: 3,
                    socket.TCP_KEEPCNT: 5
                }
            except (AttributeError, OSError):
                logger.warning("TCP keepalive options not supported on this platform")
            
            self.pool = redis.ConnectionPool(**pool_kwargs)
            self.redis_client = redis.Redis(connection_pool=self.pool)
            
            # Initialize sub-managers
            self.audit_logger = RedisAuditLogger(self.redis_client)
            self.key_manager = RedisKeyManager(self.redis_client)
            self.vault_manager = RedisVaultManager(self.redis_client, self.audit_logger, self.key_manager)
            
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

    # --- Facade Methods ---

    async def log_audit_event(self, *args, **kwargs):
        return await self.audit_logger.log_event(*args, **kwargs)

    async def is_vault_sealed(self) -> bool:
        return await self.vault_manager.is_vault_sealed()

    async def set_vault_sealed(self, *args, **kwargs):
        return await self.vault_manager.set_vault_sealed(*args, **kwargs)

    async def is_vault_initialized(self) -> bool:
        return await self.vault_manager.is_vault_initialized()

    async def set_vault_initialized(self, *args, **kwargs):
        return await self.vault_manager.set_vault_initialized(*args, **kwargs)

    async def get_vault_status(self) -> Dict[str, Any]:
        return await self.vault_manager.get_vault_status()

    async def store_master_key(self, master_key_hex: str):
        return await self.key_manager.store_master_key(master_key_hex)

    async def get_master_key(self) -> Optional[str]:
        return await self.key_manager.get_master_key()

    async def store_root_key_info(self, root_key_info: Dict[str, Any]):
        return await self.key_manager.store_root_key_info(root_key_info)

    async def get_root_key_info(self) -> Optional[Dict[str, Any]]:
        return await self.key_manager.get_root_key_info()

    async def clear_sensitive_keys(self):
        return await self.key_manager.clear_sensitive_keys()

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