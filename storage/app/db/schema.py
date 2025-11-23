import uuid
from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean, DateTime,
    TIMESTAMP, Index, inspect
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.sql import text
from sqlalchemy.orm import declarative_base, Session

from app.db.db import create_database_url

Base = declarative_base()

class Data(Base):
    """Data table (used by server service)"""
    __tablename__ = 'data'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    
    # Typed data support
    data_type = Column(String(50), nullable=False, default='text_with_ttl')  # text_with_ttl, kubernetes, credentials, api_key, ssh_key, certificate
    metadata_json = Column(Text, nullable=True)  # Unencrypted metadata for filtering/searching
    
    # Encryption
    dek_id = Column(PGUUID(as_uuid=True), nullable=False)  # Data Encryption Key reference
    encrypted_value = Column(Text, nullable=False)  # JSON structure, encrypted
    
    # TTL support
    ttl_seconds = Column(Integer, nullable=True)  # Time to live in seconds
    expires_at = Column(TIMESTAMP(timezone=True), nullable=True)  # Calculated expiration time
    
    # Standard fields
    version = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True)  # Active/inactive status
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index('idx_data_name', 'name'),
        Index('idx_data_dek_id', 'dek_id'),
        Index('idx_data_user_id', 'user_id'),
        Index('idx_data_is_active', 'is_active'),
        Index('idx_data_type', 'data_type'),
        Index('idx_data_expires_at', 'expires_at'),
    )

class EncryptionKeys(Base):
    __tablename__ = "encryption_keys"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_type = Column(String(50), nullable=False)  # 'root', 'master', 'dek'
    encrypted_key = Column(Text, nullable=False)
    nonce = Column(String(255), nullable=False)
    version = Column(Integer, default=1)
    status = Column(String(20), default='active')  # 'active', 'rotated', 'deactivated'
    meta = Column(Text)  # JSON string for additional metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DataEncryptionKeys(Base):
    """Data Encryption Keys table (DEKs encrypted with master key)"""
    __tablename__ = 'data_encryption_keys'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    encrypted_dek = Column(Text, nullable=False)  # DEK encrypted with master key
    nonce = Column(Text, nullable=False)  # Nonce used for DEK encryption
    version = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    rotated_at = Column(TIMESTAMP(timezone=True), nullable=True)
    
    __table_args__ = (
        Index('idx_dek_is_active', 'is_active'),
    )

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
    required_tables = {'data', 'keys', 'data_encryption_keys', 'server_status'}

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
