import asyncio
import logging
import os
import redis.asyncio as redis
from sqlalchemy.orm import Session
from app.db.db import SessionLocal
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

class AuditConsumer:
    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_db = int(os.getenv('REDIS_DB', 0))
        self.redis_password = os.getenv('REDIS_PASSWORD', None)
        
        self.stream_key = "audit_stream"
        self.group_name = "storage_group"
        self.consumer_name = f"storage_consumer_{os.getpid()}"
        self.redis: redis.Redis = None
        self.running = False

    async def connect(self):
        """Initialize Redis connection and consumer group."""
        self.redis = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            db=self.redis_db,
            password=self.redis_password,
            decode_responses=True
        )
        try:
            await self.redis.xgroup_create(self.stream_key, self.group_name, id="0", mkstream=True)
            logger.info(f"Consumer group {self.group_name} ready")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                logger.error(f"Failed to create consumer group: {e}")
                raise
            logger.info("Consumer group already exists")

    async def start(self):
        """Start consuming messages from Redis Stream."""
        self.running = True
        await self.connect()
        logger.info(f"Starting AuditConsumer for stream {self.stream_key}")
        
        while self.running:
            try:
                # Read new messages ('>')
                streams = await self.redis.xreadgroup(
                    self.group_name,
                    self.consumer_name,
                    {self.stream_key: ">"},
                    count=10,
                    block=2000
                )

                if not streams:
                    continue

                for stream, messages in streams:
                    for message_id, data in messages:
                        await self.process_message(message_id, data)

            except Exception as e:
                logger.error(f"Error in consumer loop: {e}")
                await asyncio.sleep(1)

    async def process_message(self, message_id: str, data: dict):
        """Process a single audit message and save to DB."""
        db: Session = SessionLocal()
        try:
            service = AuditService(db)
            
            service.create_log(
                action=data.get("action", "unknown"),
                status=data.get("status", "unknown"),
                user_id=data.get("user_id"),
                resource_id=data.get("resource_id"),
                resource_type=data.get("resource_type"),
                ip_address=data.get("ip_address"),
                user_agent=data.get("user_agent"),
                details=data.get("details")
            )
            
            # Acknowledge message
            await self.redis.xack(self.stream_key, self.group_name, message_id)
            
        except Exception as e:
            logger.error(f"Failed to process message {message_id}: {e}")
            # ACK even on error to prevent infinite loops
            await self.redis.xack(self.stream_key, self.group_name, message_id)
        finally:
            db.close()

    async def stop(self):
        """Stop the consumer."""
        self.running = False
        if self.redis:
            await self.redis.close()
