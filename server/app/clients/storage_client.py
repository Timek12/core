import uuid
import httpx
import os
from typing import Dict, Any, List, Optional


class StorageClient:
    def __init__(self):
        self.base_url = os.getenv("STORAGE_SERVICE_URL", "http://storage:8000")
        self.internal_token = os.getenv("INTERNAL_SERVICE_TOKEN")
        self.headers: Dict[str, str] = {}
        if self.internal_token:
            self.headers["X-Internal-Token"] = self.internal_token
    
    def _get_headers(self, jwt_token: Optional[str] = None) -> Dict[str, str]:
        """Get headers with optional JWT token"""
        headers = self.headers.copy()
        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"
        return headers
    
    def _convert_uuids_to_strings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert UUID objects to strings for JSON serialization"""
        converted = {}
        for key, value in data.items():
            if isinstance(value, uuid.UUID):
                converted[key] = str(value)
            else:
                converted[key] = value
        return converted
        
    async def get_all_data(self, data_type: Optional[str] = None, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all data from storage, optionally filtered by type"""
        params = {"data_type": data_type} if data_type else {}
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/data",
                headers=self._get_headers(jwt_token),
                params=params
            )
            response.raise_for_status()
            return response.json()
    
    async def get_data(self, data_id: str, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific data by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/data/{data_id}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
        
    async def create_data(self, data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Create a new data"""
        serializable_data = self._convert_uuids_to_strings(data)
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/internal/data",
                headers=self._get_headers(jwt_token),
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
        
    async def update_data(self, data_id: str, data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing data"""
        serializable_data = self._convert_uuids_to_strings(data)
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}/internal/data/{data_id}",
                headers=self._get_headers(jwt_token),
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
        
    async def delete_data(self, data_id: str, jwt_token: Optional[str] = None) -> bool:
        """Delete a data by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/internal/data/{data_id}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return True 
        
    async def get_all_keys(self, key_type: Optional[str] = None, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all active keys, optionally filtered by type"""
        params = {"key_type": key_type} if key_type else {}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/keys",
                headers=self._get_headers(jwt_token),
                params=params
            )
            response.raise_for_status()
            return response.json()
    
    async def get_key_by_id(self, key_id: uuid.UUID, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific key by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/keys/{str(key_id)}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
    
    async def get_key_by_type(self, key_type: str, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Get a key by its type"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/keys/type/{key_type}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
    
    async def create_key(self, key_data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Create a new encryption key"""
        serializable_data = self._convert_uuids_to_strings(key_data)
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/internal/keys",
                headers=self._get_headers(jwt_token),
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
    
    async def deactivate_key(self, key_id: uuid.UUID, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Deactivate a key (soft delete)"""
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/internal/keys/{str(key_id)}/deactivate",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
        
    async def get_server_status(self) -> Dict[str, Any]:
        """Get current server status"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/status",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
    
    async def update_server_status(self, status_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update server status"""
        serializable_data = self._convert_uuids_to_strings(status_data)
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}/internal/status",
                headers=self.headers,
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
    
    async def seal_vault(self) -> Dict[str, Any]:
        """Seal the vault"""
        return await self.update_server_status({"sealed": True})
    
    async def unseal_vault(self) -> Dict[str, Any]:
        """Unseal the vault"""
        return await self.update_server_status({"sealed": False})
    
    async def is_vault_sealed(self) -> bool:
        """Check if vault is currently sealed"""
        status = await self.get_server_status()
        return status.get("sealed", True)
    
    
    async def get_data_for_user(self, user_id: str, data_type: Optional[str] = None, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get data for a specific user via admin endpoint"""
        async with httpx.AsyncClient() as client:
            params = {"data_type": data_type} if data_type else {}
            response = await client.get(
                f"{self.base_url}/internal/data/admin/user/{user_id}",
                headers=self._get_headers(jwt_token),
                params=params
            )
            response.raise_for_status()
            return response.json()
    
    async def get_all_data_admin(self, data_type: Optional[str] = None, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all data across all users (admin only)"""
        params = {"data_type": data_type} if data_type else {}
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/data/admin/all",
                headers=self._get_headers(jwt_token),
                params=params
            )
            response.raise_for_status()
            return response.json()
    
    async def delete_data_admin(self, data_id: str, jwt_token: Optional[str] = None) -> bool:
        """Delete any user's data (admin only)"""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/internal/data/admin/{data_id}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return True
    
    async def get_active_encryption_key(self) -> Dict[str, Any]:
        """Get the current active encryption key"""
        try:
            return await self.get_key_by_type("encryption")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise ValueError("No active encryption key found")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if storage service is healthy"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/internal/status",
                    headers=self.headers,
                    timeout=5.0
                )
                response.raise_for_status()
                return {"status": "healthy", "response": response.json()}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    # DEK (Data Encryption Key) operations
    async def create_dek(self, dek_data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Create a new DEK (Data Encryption Key)"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/internal/deks",
                headers=self._get_headers(jwt_token),
                json=self._convert_uuids_to_strings(dek_data)
            )
            response.raise_for_status()
            return response.json()
    
    async def get_dek(self, dek_id: str) -> Dict[str, Any]:
        """Get a Data Encryption Key by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/deks/{dek_id}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()