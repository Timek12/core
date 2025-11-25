from fastapi import Request
from app.clients.storage_client import StorageClient

def get_storage_client(request: Request) -> StorageClient:
    """Dependency to get StorageClient with shared HTTP client"""
    return StorageClient(client=request.app.state.http_client)
