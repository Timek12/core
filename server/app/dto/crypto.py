from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from .common import DataResponse, StatusEnum

class InitRequest(BaseModel):
    """Initialize vault request"""
    external_token: str = Field(..., min_length=1, description="External token for key derivation")
    root_key_name: Optional[str] = Field("root", description="Root key identifier name")
    
    @validator('external_token')
    def validate_token(cls, v):
        if len(v.strip()) < 8:
            raise ValueError('External token must be at least 8 characters')
        return v.strip()

class UnsealRequest(BaseModel):
    """Unseal vault request"""
    external_token: str = Field(..., min_length=1, description="External token for unsealing")
    
    @validator('external_token')
    def validate_token(cls, v):
        if len(v.strip()) < 8:
            raise ValueError('External token must be at least 8 characters')
        return v.strip()

class VaultStatus(BaseModel):
    """Vault status information"""
    sealed: bool = Field(..., description="Whether vault is sealed")
    initialized: bool = Field(default=False, description="Whether vault is initialized")
    version: Optional[str] = Field(None, description="Vault version")
    uptime: Optional[int] = Field(None, description="Uptime in seconds")
    last_seal_time: Optional[datetime] = Field(None, description="Last time vault was sealed")
    last_unseal_time: Optional[datetime] = Field(None, description="Last time vault was unsealed")

class StatusResponse(BaseModel):
    """Vault status response"""
    status: StatusEnum = Field(default=StatusEnum.SUCCESS, description="Response status")
    vault: VaultStatus = Field(..., description="Vault status details")
    message: Optional[str] = Field(None, description="Status message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

class DEKInfo(BaseModel):
    """Data Encryption Key information"""
    dek_id: int = Field(..., description="DEK unique identifier")
    key_type: str = Field(default="dek", description="Key type")
    version: int = Field(default=1, description="Key version")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    purpose: Optional[str] = Field(None, description="Key purpose/usage")

class IssueDEKResponse(DataResponse[DEKInfo]):
    """Issue DEK response with encrypted key"""
    dek_ciphertext_b64: str = Field(..., description="Base64 encoded encrypted DEK")

class EncryptRequest(BaseModel):
    """Encrypt data request"""
    plaintext: str = Field(..., min_length=1, description="Data to encrypt")
    context: Optional[Dict[str, str]] = Field(None, description="Additional context for encryption")
    
    @validator('plaintext')
    def validate_plaintext(cls, v):
        if not v.strip():
            raise ValueError('Plaintext cannot be empty')
        return v

class EncryptionResult(BaseModel):
    """Encryption operation result"""
    ciphertext_b64: str = Field(..., description="Base64 encoded encrypted data")
    dek_id: int = Field(..., description="DEK used for encryption")
    algorithm: str = Field(default="AES-GCM", description="Encryption algorithm used")
    nonce_b64: Optional[str] = Field(None, description="Base64 encoded nonce if separate")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Encryption timestamp")

class EncryptResponse(DataResponse[EncryptionResult]):
    """Encrypt response"""
    pass

class DecryptRequest(BaseModel):
    """Decrypt data request"""
    dek_id: int = Field(..., description="DEK ID for decryption")
    ciphertext_b64: str = Field(..., min_length=1, description="Base64 encoded encrypted data")
    context: Optional[Dict[str, str]] = Field(None, description="Additional context for decryption")
    
    @validator('ciphertext_b64')
    def validate_ciphertext(cls, v):
        if not v.strip():
            raise ValueError('Ciphertext cannot be empty')
        return v.strip()

class DecryptionResult(BaseModel):
    """Decryption operation result"""
    plaintext: str = Field(..., description="Decrypted data")
    dek_id: int = Field(..., description="DEK used for decryption") 
    algorithm: str = Field(default="AES-GCM", description="Decryption algorithm used")
    decrypted_at: datetime = Field(default_factory=datetime.utcnow, description="Decryption timestamp")

class DecryptResponse(DataResponse[DecryptionResult]):
    """Decrypt response"""
    pass

class KeyRotationRequest(BaseModel):
    """Key rotation request"""
    key_type: str = Field(..., description="Type of key to rotate")
    reason: Optional[str] = Field(None, description="Reason for rotation")

class KeyRotationResult(BaseModel):
    """Key rotation result"""
    old_key_id: int = Field(..., description="Previous key ID")
    new_key_id: int = Field(..., description="New key ID")
    key_type: str = Field(..., description="Type of key rotated")
    rotated_at: datetime = Field(default_factory=datetime.utcnow, description="Rotation timestamp")
    reason: Optional[str] = Field(None, description="Rotation reason")

class KeyRotationResponse(DataResponse[KeyRotationResult]):
    """Key rotation response"""
    pass

class CryptoOperationLog(BaseModel):
    """Crypto operation audit log"""
    operation: str = Field(..., description="Operation type (encrypt/decrypt/seal/unseal)")
    user_id: Optional[str] = Field(None, description="User who performed operation")
    success: bool = Field(..., description="Whether operation succeeded")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Operation timestamp")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional operation details")

class CryptoStatsResponse(BaseModel):
    """Crypto operations statistics"""
    total_encryptions: int = Field(default=0, description="Total encryption operations")
    total_decryptions: int = Field(default=0, description="Total decryption operations")
    total_deks_issued: int = Field(default=0, description="Total DEKs issued")
    vault_uptime: Optional[int] = Field(None, description="Vault uptime in seconds")
    last_key_rotation: Optional[datetime] = Field(None, description="Last key rotation time")
    recent_operations: List[CryptoOperationLog] = Field(default=[], description="Recent operations")