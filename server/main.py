import logging
from pathlib import Path
from fastapi import FastAPI
from datetime import datetime
from dotenv import load_dotenv
import sys
import os

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.api import crypto_api, secrets_api

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI(title="Key Management System API")

# Include routers
app.include_router(crypto_api.router)
app.include_router(secrets_api.router)

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
    