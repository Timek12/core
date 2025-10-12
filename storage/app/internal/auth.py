from fastapi import HTTPException, Header
import os

async def verify_internal_request(x_internal_token: str = Header(None)):
    """Verify request comes from internal service"""
    expected_token = os.getenv("INTERNAL_SERVICE_TOKEN")
    if not x_internal_token or x_internal_token != expected_token:
        raise HTTPException(status_code=403, detail="Internal access only")
    return True