from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime
from .common import StatusEnum

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