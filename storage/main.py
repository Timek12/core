#!/usr/bin/env python3

from datetime import datetime, timezone
import os
import sys
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi import HTTPException
from sqlalchemy import text

sys.path.append('/app')  # Add the app directory to Python path for Docker

from app.db.schema import provision_schema
from app.internal import data_api, key_api, status_api, dek_api

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting storage service")
    logger.info("Provisioning database schema")

    if provision_schema():
        logger.info("Schema provisioning completed successfully")
    else:
        logger.error("Schema provisioning failed")
        sys.exit(1)

    yield

    # Shutdown
    logger.info("Shutting down storage service")

# Create FastAPI app
app = FastAPI(
    title="Storage Service",
    description="Storage service for microservices architecture",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(data_api.router)
app.include_router(key_api.router)
app.include_router(status_api.router)
app.include_router(dek_api.router)

@app.get("/health")
def health_check():
    from app.db.db import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        
        return {
            "status": "healthy",
            "service": "storage",
            "database": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "service": "storage",
                "database": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv('PORT', '8002'))
    host = os.getenv('HOST', '0.0.0.0')

    logger.info(f"Starting storage service on {host}:{port}")

    config = uvicorn.Config("main:app", host=host, port=port, log_level="debug" if os.getenv('DEBUG', 'info').lower() == 'debug' else "info")
    server = uvicorn.Server(config)
    server.run()
