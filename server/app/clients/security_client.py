import os
import httpx
from typing import Dict, Any, Optional

class SecurityClient:
    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self.base_url = os.getenv("SECURITY_SERVICE_URL", "http://security:8001")
        self.client = client

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Internal request helper to handle client lifecycle"""
        if self.client:
            return await self.client.request(method, url, **kwargs)
        
        async with httpx.AsyncClient() as client:
            return await client.request(method, url, **kwargs)

    async def get_user_public(self, user_id: int, jwt_token: str) -> Dict[str, Any]:
        """Get public user info"""
        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = await self._request(
            "GET",
            f"{self.base_url}/auth/{user_id}/public",
            headers=headers
        )
        response.raise_for_status()
        return response.json()
