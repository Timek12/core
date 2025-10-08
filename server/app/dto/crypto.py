from pydantic import BaseModel
from typing import Optional

class InitRequest(BaseModel):
    external_token: str
    master_key_name: Optional[str] = "master-v1"

class UnsealRequest(BaseModel):
    external_token: str

class StatusResponse(BaseModel):
    sealed: bool
    message: Optional[str] = None

class IssueDEKResponse(BaseModel):
    dek_id: int
    dek_ciphertext_b64: str

class EncryptRequest(BaseModel):
    plaintext: str

class EncryptResponse(BaseModel):
    dek_id: int
    ciphertext_b64: str

class DecryptRequest(BaseModel):
    dek_id: int
    ciphertext_b64: str