import logging
from pathlib import Path
from contextlib import asynccontextmanager
import httpx
import os
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import data_api, crypto_api, admin_api, audit_api

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting server service")
    app.state.http_client = httpx.AsyncClient()
    yield
    # Shutdown
    logger.info("Shutting down server service")
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

@app.get('/health')
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv('PORT', '8000'))
    host = os.getenv('HOST', '0.0.0.0')

    logger.info(f"Starting server service on {host}:{port}")

    config = uvicorn.Config("main:app", host=host, port=port, log_level="debug" if os.getenv('DEBUG', 'info').lower() == 'debug' else "info")
    server = uvicorn.Server(config)
    server.run()