import os
import sys
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Now import from app
from app.api import auth_api
from app.db.schema import provision_schema

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the application."""

    # Startup
    logger.info("Starting security service")

    if provision_schema():
        logger.info("Schema provisioning completed successfully")
    else:
        logger.error("Schema provisioning failed")
        sys.exit(1)

    yield

    # Shutdown
    logger.info("Shutting down security service")

# Create FastAPI app
app = FastAPI(
    title="Security Service",
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
app.include_router(auth_api.router)


@app.get("/health")
def health_check():
    """Health check endpoint."""
    from app.db.db import engine
    from sqlalchemy import text

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"

    return {
        "status": "healthy" if db_status == "healthy" else "unhealthy",
        "service": "security",
        "database": db_status
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8001"))
    host = os.getenv("HOST", "0.0.0.0")

    logger.info(f"Starting security service on {host}:{port}")

    config = uvicorn.Config("main:app", host=host, port=port, log_level="debug" if os.getenv(
        'DEBUG', 'info').lower() == 'debug' else "info")
    server = uvicorn.Server(config)
    server.run()
