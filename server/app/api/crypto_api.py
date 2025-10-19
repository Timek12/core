from base64 import b64encode, b64decode
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from app.services.crypto_service import CryptoService
from app.clients.storage_client import StorageClient
from app.utils.jwt_utils import get_current_user, require_role, require_roles, UserInfo, get_token
from app.utils.redis_state import get_state_manager
from dotenv import load_dotenv
import os
import hashlib
import json
from app.dto.crypto import *

load_dotenv()

router = APIRouter(prefix="/api/crypto", tags=["crypto"])

@router.post("/init", response_model=StatusResponse)
async def init(req: InitRequest, current_user: UserInfo = Depends(require_role("admin")), token: str = Depends(get_token)):
    """Initialize the vault with Redis state management"""
    
    state_manager = await get_state_manager()
    storage_client = StorageClient()
    
    # Check if already initialized
    if await state_manager.is_vault_initialized():
        raise HTTPException(status_code=400, detail="Vault already initialized")

    # Initialize crypto service
    service = CryptoService()

    # Generate keys
    root_key = os.urandom(32)
    master_key = os.urandom(32)
    
    # Derive KEK from external token
    salt = os.urandom(16)
    kek = service.hkdf_derive(req.external_token.encode("utf-8"), salt)

    # Encrypt root key with KEK
    root_nonce, root_ct = service.aesgcm_encrypt(kek, root_key)
    master_nonce, master_ct = service.aesgcm_encrypt(root_key, master_key)

    # Store keys in storage service
    root_key_data = {
        'key_type': 'root',
        'encrypted_key': root_ct.hex(),
        'nonce': root_nonce.hex(),
        'version': 1,
        'status': 'active',
        'meta': json.dumps({"salt": salt.hex(), "kek_derived": True})
    }
    
    master_key_data = {
        'key_type': 'master', 
        'encrypted_key': master_ct.hex(),
        'nonce': master_nonce.hex(),
        'version': 1,
        'status': 'active',
        'meta': json.dumps({"derived_from": "root"})
    }

    root_response = await storage_client.create_key(root_key_data, token)
    master_response = await storage_client.create_key(master_key_data, token)

    # Store root key metadata in Redis
    await state_manager.store_root_key_info({
        "storage_id": root_response['id'],
        "salt": salt.hex(),
        "created_by": current_user.user_id,
        "created_at": datetime.utcnow().isoformat()
    })

    # Mark vault as initialized and sealed
    await state_manager.set_vault_initialized(current_user.user_id)
    await state_manager.set_vault_sealed(True, current_user.user_id)

    # Clear sensitive data from memory
    del root_key, master_key, kek

    return StatusResponse(
        vault=VaultStatus(
            sealed=True, 
            initialized=True,
            version="1.0"
        ),
        message=f"Vault initialized successfully. Root ID: {root_response['id']}, Master ID: {master_response['id']}"
    )


@router.post("/unseal", response_model=StatusResponse)
async def unseal(req: UnsealRequest, current_user: UserInfo = Depends(require_role("admin")), token: str = Depends(get_token)):
    """Unseal the vault using Redis for session management"""
    
    state_manager = await get_state_manager()
    storage_client = StorageClient()
    
    # Check if initialized
    if not await state_manager.is_vault_initialized():
        raise HTTPException(status_code=400, detail="Vault not initialized")

    # Get root key info from Redis
    root_key_info = await state_manager.get_root_key_info()
    if not root_key_info:
        raise HTTPException(status_code=500, detail="Root key metadata not found")

    # Fetch encrypted root key from storage
    root_key_data = await storage_client.get_key_by_id(root_key_info["storage_id"], token)
    
    # Find and fetch master key
    master_keys = await storage_client.get_all_keys(key_type="master", jwt_token=token)
    if not master_keys:
        raise HTTPException(status_code=500, detail="Master key not found")
    master_key_data = master_keys[0]

    # Initialize crypto service
    service = CryptoService()

    # Decrypt root key using external token
    salt = bytes.fromhex(root_key_info["salt"])
    kek = service.hkdf_derive(req.external_token.encode("utf-8"), salt)
    
    root_ct = bytes.fromhex(root_key_data["encrypted_key"])
    root_nonce = bytes.fromhex(root_key_data["nonce"])

    try:
        root_key = service.aesgcm_decrypt(kek, root_nonce, root_ct)
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid external token")

    # Decrypt master key with root key
    master_ct = bytes.fromhex(master_key_data["encrypted_key"])
    master_nonce = bytes.fromhex(master_key_data["nonce"])

    try:
        master_key = service.aesgcm_decrypt(root_key, master_nonce, master_ct)
    except Exception:
        raise HTTPException(status_code=500, detail="Master key decryption failed")

    # Store decrypted master key in Redis with TTL for security (as hex string)
    await state_manager.store_master_key(master_key.hex(), ttl_hours=1)

    # Mark vault as unsealed
    await state_manager.set_vault_sealed(False, current_user.user_id)

    # Clear sensitive data from memory immediately
    del root_key, master_key, kek

    return StatusResponse(
        vault=VaultStatus(
            sealed=False,
            initialized=True,
            version="1.0"
        ),
        message=f"Vault unsealed successfully"
    )


@router.post("/seal", response_model=StatusResponse)
async def seal(current_user: UserInfo = Depends(require_role("admin"))):
    """Seal the vault by clearing Redis session data"""
    
    state_manager = await get_state_manager()
    
    # Clear sensitive keys (master key, etc.)
    await state_manager.clear_sensitive_keys()
    
    # Mark vault as sealed
    await state_manager.set_vault_sealed(True, current_user.user_id)

    return StatusResponse(
        vault=VaultStatus(
            sealed=True,
            initialized=await state_manager.is_vault_initialized(),
            version="1.0"
        ),
        message="Vault sealed successfully - all sessions cleared"
    )


@router.get("/status", response_model=StatusResponse)
async def status(current_user: UserInfo = Depends(get_current_user)):
    """Get vault status from Redis state"""
    
    state_manager = await get_state_manager()
    
    is_initialized = await state_manager.is_vault_initialized()
    is_sealed = await state_manager.is_vault_sealed()
    
    return StatusResponse(
        vault=VaultStatus(
            sealed=is_sealed,
            initialized=is_initialized,
            version="1.0"
        ),
        message="Vault status retrieved"
    )


@router.post("/issue-dek", response_model=IssueDEKResponse)
async def issue_dek(current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Issue a new Data Encryption Key (DEK) using Redis session"""
    
    state_manager = await get_state_manager()
    storage_client = StorageClient()
    
    # Check vault status
    if await state_manager.is_vault_sealed():
        raise HTTPException(status_code=400, detail="Vault is sealed")

    # Get active crypto session
    session_data = await state_manager.get_active_crypto_session()
    if not session_data:
        raise HTTPException(status_code=400, detail="No active crypto session - vault may be sealed")

    # Initialize crypto service
    service = CryptoService()

    # Generate DEK
    dek = os.urandom(32)
    master_key = session_data["master_key"]

    dek_nonce, dek_ct = service.aesgcm_encrypt(master_key, dek)

    # Store DEK in storage service
    dek_data = {
        'key_type': 'dek',
        'encrypted_key': dek_ct.hex(),
        'nonce': dek_nonce.hex(),
        'version': 1,
        'status': 'active',
        'meta': json.dumps({
            "purpose": "issued_dek",
            "issued_by": current_user.user_id,
            "issued_at": datetime.utcnow().isoformat()
        })
    }

    dek_response = await storage_client.create_key(dek_data)

    # Clear sensitive data
    del dek, master_key

    return IssueDEKResponse(
        dek_id=dek_response['id'],
        dek_ciphertext_b64=b64encode(dek_ct).decode(),
        message="DEK issued successfully"
    )


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_secret(req: EncryptRequest, current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Encrypt data with ephemeral DEK using Redis session"""
    
    state_manager = await get_state_manager()
    storage_client = StorageClient()
    
    # Check vault status
    if await state_manager.is_vault_sealed():
        raise HTTPException(status_code=400, detail="Vault is sealed")

    # Get active crypto session
    session_data = await state_manager.get_active_crypto_session()
    if not session_data:
        raise HTTPException(status_code=400, detail="No active crypto session")

    # Initialize crypto service
    service = CryptoService()

    # Generate ephemeral DEK
    dek = os.urandom(32)
    master_key = session_data["master_key"]
    dek_nonce, dek_ct = service.aesgcm_encrypt(master_key, dek)

    # Store ephemeral DEK
    dek_data = {
        'key_type': 'dek',
        'encrypted_key': dek_ct.hex(),
        'nonce': dek_nonce.hex(),
        'version': 1,
        'status': 'active',
        'meta': json.dumps({
            "purpose": "ephemeral_dek",
            "created_by": current_user.user_id,
            "created_at": datetime.utcnow().isoformat()
        })
    }

    dek_response = await storage_client.create_key(dek_data)

    # Encrypt plaintext with DEK
    encryption_nonce, ciphertext = service.aesgcm_encrypt(dek, req.plaintext.encode() if isinstance(req.plaintext, str) else req.plaintext)

    # Create payload
    payload = {
        'ciphertext': b64encode(ciphertext).decode(),
        'enc_nonce': b64encode(encryption_nonce).decode()
    }

    # Clear sensitive data
    del dek, master_key

    return EncryptResponse(
        ciphertext_b64=b64encode(json.dumps(payload).encode()).decode(),
        dek_id=dek_response['id'],
        message="Data encrypted successfully"
    )


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_secret(req: DecryptRequest, current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Decrypt data using stored DEK and Redis session"""
    
    state_manager = await get_state_manager()
    storage_client = StorageClient()
    
    # Check vault status
    if await state_manager.is_vault_sealed():
        raise HTTPException(status_code=400, detail="Vault is sealed")

    # Get active crypto session
    session_data = await state_manager.get_active_crypto_session()
    if not session_data:
        raise HTTPException(status_code=400, detail="No active crypto session")

    # Initialize crypto service
    service = CryptoService()

    # Fetch DEK from storage
    try:
        dek_data = await storage_client.get_key_by_id(req.dek_id)
    except Exception:
        raise HTTPException(status_code=404, detail="DEK not found")

    # Decrypt DEK with master key
    dek_ct = bytes.fromhex(dek_data['encrypted_key'])
    dek_nonce = bytes.fromhex(dek_data['nonce'])
    master_key = session_data["master_key"]

    try:
        dek = service.aesgcm_decrypt(master_key, dek_nonce, dek_ct)
    except Exception:
        raise HTTPException(status_code=500, detail="DEK decryption failed")

    # Decrypt payload
    try:
        payload_bytes = b64decode(req.ciphertext_b64)
        payload = json.loads(payload_bytes.decode())
        ciphertext = b64decode(payload['ciphertext'])
        enc_nonce = b64decode(payload['enc_nonce'])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ciphertext format")

    try:
        plaintext = service.aesgcm_decrypt(dek, enc_nonce, ciphertext)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")

    # Clear sensitive data
    del dek, master_key

    return DecryptResponse(
        plaintext=plaintext.decode() if isinstance(plaintext, bytes) else plaintext,
        message="Data decrypted successfully"
    )