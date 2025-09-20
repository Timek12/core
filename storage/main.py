import os
from sqlalchemy import create_engine, Integer, String, Float, Column
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def create_database_url():
    """Create PostgreSQL database URL from environment variables."""
    db_host = os.getenv('DB_HOST', 'localhost')
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME', 'lunaguard')
    db_user = os.getenv('DB_USER', 'postgres')
    db_password = os.getenv('DB_PASSWORD', 'password')
    
    return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

def get_engine():
    """Get SQLAlchemy engine with proper configuration."""
    database_url = create_database_url()
    
    # Engine configuration
    engine_config = {
        'echo': os.getenv('DEBUG', 'false').lower() == 'true',
        'pool_pre_ping': True,  # Verify connections before use
        'pool_recycle': 300,    # Recycle connections every 5 minutes
    }
    
    return create_engine(database_url, **engine_config)

def get_session():
    """Get database session."""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()

# Create database engine with connection string built from environment variables
engine = get_engine()

# Create declarative base for ORM models
Base = declarative_base()