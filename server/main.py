import logging
from pathlib import Path
from contextlib import asynccontextmanager
import httpx
import os
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio

from app.api import data_api, crypto_api, admin_api, audit_api, projects_api, security_api
from app.clients.storage_client import StorageClient
from app.services import notification_service

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting server service")
    app.state.http_client = httpx.AsyncClient()
    
    # Background Task for Rotation Checks
    async def rotation_checker():
        logger.info("Starting rotation checker loop")
        storage_client = StorageClient()
        while True:
            try:
                # Check for due rotations
                due_secrets = await storage_client.get_due_rotations(limit=20)
                if due_secrets:
                    logger.info(f"Found {len(due_secrets)} secrets due for rotation")
                    for secret in due_secrets:
                        msg = f"Secret Rotation Due: '{secret['name']}' (ID: {secret['id']}) needs to be rotated."
                        await notification_service.send_slack_notification(msg, level="warning")
                
                await asyncio.sleep(3600) 
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in rotation checker: {e}")
                await asyncio.sleep(60) # Retry after 1 min on error

    checker_task = asyncio.create_task(rotation_checker())
    
    yield
    # Shutdown
    logger.info("Shutting down server service")
    checker_task.cancel()
    try:
        await checker_task
    except asyncio.CancelledError:
        pass
    await app.state.http_client.aclose()

app = FastAPI(title="Key Management System API", lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(crypto_api.router)
app.include_router(data_api.router)
app.include_router(admin_api.router)
app.include_router(audit_api.router)
app.include_router(projects_api.router)
app.include_router(security_api.router)

@app.get('/health')
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv('PORT', '8000'))
    host = os.getenv('HOST', '0.0.0.0')

    logger.info(f"Server configured to run on {host}:{port}")

    config = uvicorn.Config("main:app", host=host, port=port, log_level="debug" if os.getenv('DEBUG', 'info').lower() == 'debug' else "info", lifespan="on")
    server = uvicorn.Server(config)
    server.run()