import uuid
import httpx
import os
from typing import Dict, Any, List, Optional


# TODO: Add proper error handling, logging and request / response models
class StorageClient:
    def __init__(self):
        self.base_url = os.getenv("STORAGE_SERVICE_URL", "http://storage:8000")
        self.internal_token = os.getenv("INTERNAL_SERVICE_TOKEN")
        self.headers = {"X-Internal-Token": self.internal_token}
    
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
        
    async def get_all_secrets(self, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all secrets from storage"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/secrets",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
    
    async def get_secret(self, secret_id: str, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific secret by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/secrets/{secret_id}",
                headers=self._get_headers(jwt_token)
            )
            response.raise_for_status()
            return response.json()
        
    async def create_secret(self, secret_data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Create a new secret"""
        serializable_data = self._convert_uuids_to_strings(secret_data)
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/internal/secrets",
                headers=self._get_headers(jwt_token),
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
        
    async def update_secret(self, secret_id: str, secret_data: Dict[str, Any], jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing secret"""
        serializable_data = self._convert_uuids_to_strings(secret_data)
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}/internal/secrets",
                headers=self._get_headers(jwt_token),
                params={"secret_id": secret_id},
                json=serializable_data
            )
            response.raise_for_status()
            return response.json()
        
    async def delete_secret(self, secret_id: str, jwt_token: Optional[str] = None) -> bool:
        """Delete a secret by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/internal/secrets/{secret_id}",
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
    
    async def get_key_by_id(self, key_id: int, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific key by ID"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/internal/keys/{key_id}",
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
    
    async def deactivate_key(self, key_id: int, jwt_token: Optional[str] = None) -> Dict[str, Any]:
        """Deactivate a key (soft delete)"""
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/internal/keys/{key_id}/deactivate",
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
    
    
    async def get_secrets_for_user(self, user_id: str, jwt_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all secrets and filter by user_id (client-side filtering)"""
        all_secrets = await self.get_all_secrets(jwt_token)
        # Convert user_id to int for comparison since DB stores it as integer
        try:
            user_id_int = int(user_id)
            return [secret for secret in all_secrets if secret.get("user_id") == user_id_int]
        except (ValueError, TypeError):
            # If conversion fails, try string comparison as fallback
            return [secret for secret in all_secrets if str(secret.get("user_id")) == str(user_id)]
    
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