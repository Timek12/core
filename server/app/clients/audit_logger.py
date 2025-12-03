import os
import logging
import redis.asyncio as redis
from typing import Optional

logger = logging.getLogger(__name__)

class RedisAuditLogger:
    def __init__(self, client: Optional[redis.Redis] = None):
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_db = int(os.getenv('REDIS_DB', 0))
        self.redis_password = os.getenv('REDIS_PASSWORD', None)
        self.stream_key = "audit_stream"
        
        if client:
            self.client = client
        else:
            self.client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                decode_responses=True
            )

    async def log_event(self, 
                        action: str, 
                        status: str, 
                        user_id: Optional[str] = None, 
                        resource_id: Optional[str] = None, 
                        resource_type: Optional[str] = None, 
                        ip_address: Optional[str] = None, 
                        user_agent: Optional[str] = None, 
                        details: Optional[str] = None):
        """Send audit log to Redis Stream"""
        try:
            event_data = {
                "action": action,
                "status": status,
                "user_id": str(user_id) if user_id else "",
                "resource_id": str(resource_id) if resource_id else "",
                "resource_type": resource_type or "",
                "ip_address": ip_address or "",
                "user_agent": user_agent or "",
                "details": details or ""
            }
            
            await self.client.xadd(self.stream_key, event_data)
            
        except Exception as e:
            logger.error(f"Failed to log audit event to Redis: {e}")
