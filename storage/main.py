"""
LunaGuard Storage Service - Cloud-Native Database Provisioning

This service automatically provisions database schema on startup and provides
cloud-native, scalable database initialization for the LunaGuard platform.
"""

import os
import logging
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import asyncpg

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global database connection
db_pool = None

async def load_schema() -> str:
    """Load database schema from SQL file"""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    try:
        with open(schema_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise RuntimeError("schema.sql file not found")

async def ensure_database_schema():
    """
    Ensure database schema exists - idempotent operation safe for multiple replicas
    """
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            # Load schema
            schema_sql = await load_schema()
            
            # Execute schema with retry logic
            async with db_pool.acquire() as connection:
                # Use a transaction to ensure atomicity
                async with connection.transaction():
                    await connection.execute(schema_sql)
                    
            logger.info("Database schema ensured successfully")
            return
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Schema initialization attempt {attempt + 1} failed: {e}, retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error(f"Failed to initialize schema after {max_retries} attempts: {e}")
                raise

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with automatic schema provisioning"""
    global db_pool
    
    # Startup
    logger.info("Starting LunaGuard Storage Service...")
    
    try:
        # Create database connection pool with retry logic
        database_url = (
            f"postgresql://{os.getenv('DB_USER', 'postgres')}:"
            f"{os.getenv('DB_PASSWORD', 'password')}@"
            f"{os.getenv('DB_HOST', 'localhost')}:"
            f"{os.getenv('DB_PORT', '5432')}/"
            f"{os.getenv('DB_NAME', 'lunaguard')}"
        )
        
        # Wait for database to be available
        max_retries = 10
        for attempt in range(max_retries):
            try:
                db_pool = await asyncpg.create_pool(
                    database_url, 
                    min_size=1, 
                    max_size=10,
                    command_timeout=30
                )
                # Test connection
                async with db_pool.acquire() as connection:
                    await connection.fetchval("SELECT 1")
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Database connection attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(2)
                else:
                    raise
        
        logger.info("Database connection pool created")
        
        # Automatically provision schema on startup (idempotent)
        if os.getenv("AUTO_PROVISION", "true").lower() == "true":
            logger.info("Auto-provisioning database schema...")
            await ensure_database_schema()
        
        logger.info("Storage service startup complete")
        
    except Exception as e:
        logger.error(f"Failed to start storage service: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down LunaGuard Storage Service...")
    if db_pool:
        await db_pool.close()
    logger.info("Storage service shutdown complete")

# Create FastAPI application
app = FastAPI(
    title="LunaGuard Storage Service",
    description="Database provisioning service for LunaGuard",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "lunaguard-storage",
        "status": "running",
        "version": "1.0.0",
        "description": "Database provisioning service"
    }

@app.get("/health")
async def health_check():
    """
    Kubernetes-ready health check endpoint
    """
    try:
        if db_pool:
            async with db_pool.acquire() as connection:
                await connection.fetchval("SELECT 1")
        return {
            "status": "healthy", 
            "database": "connected",
            "service": "lunaguard-storage",
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Database connection failed")

@app.get("/ready")
async def readiness_check():
    """
    Kubernetes readiness probe - checks if schema is provisioned
    """
    try:
        provisioned = await check_schema_provisioned()
        if provisioned:
            return {
                "status": "ready",
                "schema_provisioned": True,
                "service": "lunaguard-storage"
            }
        else:
            raise HTTPException(
                status_code=503, 
                detail="Database schema not fully provisioned"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail="Readiness check failed")

async def check_schema_provisioned() -> bool:
    """Check if all required tables exist"""
    try:
        async with db_pool.acquire() as connection:
            # Check if main tables exist
            tables = await connection.fetch("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name IN ('users', 'oauth_tokens', 'jwt_refresh_tokens')
            """)
            return len(tables) >= 3
    except Exception:
        return False

@app.post("/provision/database")
async def provision_database():
    """
    Manual database provisioning endpoint (idempotent)
    """
    try:
        await ensure_database_schema()
        return {
            "status": "success", 
            "message": "Database schema provisioned successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Manual provisioning failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Database provisioning failed: {str(e)}"
        )

@app.post("/provision/migrate")
async def run_migrations():
    """Run database migrations (placeholder for future use)"""
    try:
        # Placeholder for migration logic
        logger.info("Migration endpoint called")
        return {"status": "success", "message": "No migrations to run"}
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Migration failed: {str(e)}")

@app.get("/provision/status")
async def get_provision_status():
    """Check database provisioning status"""
    try:
        async with db_pool.acquire() as connection:
            # Check if main tables exist
            users_exists = await connection.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'users'
                );
            """)
            
            oauth_tokens_exists = await connection.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'oauth_tokens'
                );
            """)
            
            jwt_tokens_exists = await connection.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'jwt_refresh_tokens'
                );
            """)
            
        return {
            "status": "success",
            "provisioned": users_exists and oauth_tokens_exists and jwt_tokens_exists,
            "tables": {
                "users": users_exists,
                "oauth_tokens": oauth_tokens_exists,
                "jwt_refresh_tokens": jwt_tokens_exists
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to check provision status: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    # Get configuration from environment
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8002"))
    
    logger.info(f"Starting server on {host}:{port}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=os.getenv("DEBUG", "false").lower() == "true"
    )
