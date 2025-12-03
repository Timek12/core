import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean, 
    TIMESTAMP, ForeignKey, UniqueConstraint, Index, inspect, Enum
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, INET as PGINET
from sqlalchemy.sql import text
from sqlalchemy.orm import declarative_base

from app.db.db import create_database_url

Base = declarative_base()

class UserRole(str, enum.Enum):
    """User role enumeration"""
    USER = "user"
    ADMIN = "admin"

class Users(Base):
    """Users table for authentication (used by security service)"""
    __tablename__ = 'users'
    
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    role = Column(Enum(UserRole, name='user_role', native_enum=False), default=UserRole.USER, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index('idx_users_email', 'email'),
        Index('idx_users_role', 'role'),
    )

class JWTRefreshTokens(Base):
    """JWT refresh tokens table"""
    __tablename__ = 'jwt_refresh_tokens'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    token_hash = Column(String(255), nullable=False)  # Hashed refresh token
    jti = Column(PGUUID(as_uuid=True), nullable=False, default=uuid.uuid4)  # JWT ID for token identification
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    device_info = Column(Text, nullable=True)  # JSON stored as text, could be JSONB
    ip_address = Column(PGINET, nullable=True)
    revoked_at = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        UniqueConstraint('token_hash', name='uq_jwt_tokens_hash'),
        UniqueConstraint('jti', name='uq_jwt_tokens_jti'),
        Index('idx_jwt_tokens_user_id', 'user_id'),
        Index('idx_jwt_tokens_jti', 'jti'),
        Index('idx_jwt_tokens_hash', 'token_hash'),
        Index('idx_jwt_tokens_expires', 'expires_at'),
        Index('idx_jwt_tokens_active', 'user_id', 'revoked', 'expires_at'),
    )

def schema_exists(engine) -> bool:
    """Check if the schema already exists by inspecting database tables."""

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    # Define required tables for this service
    required_tables = {'users', 'jwt_refresh_tokens'}

    # Check if all required tables exist
    return required_tables.issubset(set(existing_tables))

def provision_schema():
    """Provision DB schema using SQLAlchemy with retry logic and PostgreSQL advisory locks for replica safety."""
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
                    
                    logger.info("Schema provisioned successfully")
                    
                    # Seed initial data
                    logger.info("Seeding initial users...")
                    from sqlalchemy.orm import Session
                    from app.db.seed import seed_initial_users
                    
                    session = Session(bind=engine)
                    try:
                        seed_success = seed_initial_users(session)
                        if seed_success:
                            logger.info("Initial data seeding completed")
                        else:
                            logger.warning("Initial data seeding had issues, but schema is provisioned")
                    finally:
                        session.close()
                    
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