import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean,
    TIMESTAMP, Index, inspect
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.sql import text
from sqlalchemy.orm import declarative_base

from app.db.db import create_database_url

Base = declarative_base()

class Secrets(Base):
    """Secrets table (used by server service)"""
    __tablename__ = 'secrets'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    key_id = Column(PGUUID(as_uuid=True), nullable=False)
    encrypted_value = Column(Text, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index('idx_secrets_name', 'name'),
        Index('idx_secrets_key_id', 'key_id'),
    )

class Keys(Base):
    """Keys table (for encryption key management)"""
    __tablename__ = 'keys'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key_type = Column(String(16), nullable=False)
    encrypted_key = Column(Text, nullable=False)  
    nonce = Column(Text, nullable=False) 
    version = Column(Integer, nullable=False, default=1)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    meta = Column(String, nullable=True)

class ServerStatus(Base):
    """Server status table (for server state management)"""
    __tablename__ = 'server_status'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sealed = Column(Boolean, nullable=False)
    last_changed = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))

def schema_exists(engine) -> bool:
    """Check if the schema already exists by inspecting database tables."""

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    # Define required tables for this service
    required_tables = {'secrets', 'keys', 'server_status'}

    # Check if all required tables exist
    return required_tables.issubset(set(existing_tables))

def provision_schema():
    """Provision the database schema using SQLAlchemy with retry logic"""
    import os
    import logging
    import time
    from sqlalchemy.exc import OperationalError
    
    logger = logging.getLogger(__name__)
    
    # Retry configuration
    max_retries = 5
    retry_delay = 2 # seconds
    connection_timeout = 5 # seconds per attempt
    SCHEMA_LOCK_ID = 123456789 # PostgreSQL advisory lock ID (unique number for this schema)

    for attempt in range(max_retries):
        engine = None

        try:
            logger.info(f"Database connection attempt {attempt + 1}/{max_retries}...")

            # Create database engine with connection timeout
            database_url = create_database_url()
            engine = create_engine(
                database_url,
                echo=os.getenv('DEBUG', 'false').lower() == 'true',
                pool_pre_ping=True,
                connect_args={
                    'connect_timeout': connection_timeout,
                    'options': '-c statement_timeout=30000'  # 30 second statement timeout
                }
            )

            # Test connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            logger.info("Database connection successful")

            with engine.connect() as conn:
                logger.info(f"Attempting to acquire advisory lock {SCHEMA_LOCK_ID}")

                # Acquire advisory lock - blocks until lock is available again
                conn.execute(
                    text("SELECT pg_advisory_lock(:lock_id)"),
                    {"lock_id": SCHEMA_LOCK_ID}
                )

                logger.info(f"Advisory lock {SCHEMA_LOCK_ID} acquired")

                try:
                    # Check if schema exists
                    if schema_exists(engine):
                        logger.info("Schema already exists, skipping")
                        return True
                    
                    
                    logger.info("Schema does not exist - creating tables")

                    # Enable UUID extension
                    conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'))
                    conn.commit()

                    # Create all tables
                    Base.metadata.create_all(engine)
                    
                    logger.info("Schema provisioned sucessfully")
                    return True
                
                finally:
                    # Always release the advisory lock
                    try:
                        conn.execute(
                            text("SELECT pg_advisory_unlock(:lock_id)"),
                            {"lock_id": SCHEMA_LOCK_ID}
                        )
                        logger.info(f"Advisory lock {SCHEMA_LOCK_ID} released")
                    except Exception as unlock_error:
                        logger.warning(f"Error releasing lock: {unlock_error}")

        except OperationalError as e:
            logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect after {max_retries} attempts")
                return False
                
        except Exception as e:
            logger.error(f"Unexpected error during schema provisioning: {e}", exc_info=True)
            return False
            
        finally:
            # Clean up engine
            if engine:
                engine.dispose()
                
    return False            
