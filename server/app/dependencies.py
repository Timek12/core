from fastapi import Request
from app.clients.storage_client import StorageClient

def get_storage_client(request: Request) -> StorageClient:
    """Dependency to get StorageClient with shared HTTP client"""
    return StorageClient(client=request.app.state.http_client)

def get_client_info(request: Request) -> tuple[str, str]:
    """Extract device info and IP address from request."""
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = request.client.host if request.client else "unknown"
    return user_agent, ip_address
