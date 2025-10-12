from base64 import b64encode
from fastapi import APIRouter, HTTPException, Depends
from app.services.crypto_service import CryptoService
from app.utils.jwt_utils import get_current_user, require_role, require_roles, UserInfo
from dotenv import load_dotenv
import os
import requests
import json
from app.dto.crypto import *

load_dotenv()

# Configuration
STORAGE_SERVICE_URL = os.getenv('STORAGE_SERVICE_URL', 'http://localhost:8002')

_runtime = {
    "sealed": True,
    "root_key": None,  
    "master_key": None,
}  

router = APIRouter(prefix="/api/crypto", tags=["crypto"])

@router.post("/init", response_model=StatusResponse)
def init(req: InitRequest, current_user: UserInfo = Depends(require_role("admin"))):
    """Initialize the server with root and master keys. Requires admin role."""

    # Check if already initialized
    response = requests.get(f"{STORAGE_SERVICE_URL}/api/keys/type/root")
    if response.status_code == 200:
        raise HTTPException(status_code=400, detail="Already initialized")

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

    # Encrypt master key with root key
    master_nonce, master_ct = service.aesgcm_encrypt(root_key, master_key)

    # Store root key
    root_response = requests.post(
        f"{STORAGE_SERVICE_URL}/api/keys",
        json={
            'key_type': 'root',
            'encrypted_key': root_ct.hex(),
            'nonce': root_nonce.hex(),
            'version': 1,
            'active': True,
            'meta': json.dumps({"salt": salt.hex()})
        }
    )
    root_response.raise_for_status()
    root_id = root_response.json()['id']

    # Store master key
    master_response = requests.post(
        f"{STORAGE_SERVICE_URL}/api/keys",
        json={
            'key_type': 'master',
            'encrypted_key': master_ct.hex(),
            'nonce': master_nonce.hex(),
            'version': 1,
            'active': True,
            'meta': json.dumps({"salt": salt.hex()})
        }
    )
    master_response.raise_for_status()
    master_id = master_response.json()['id']

    requests.put(
        f"{STORAGE_SERVICE_URL}/api/status",
        json={'sealed': True}
    )

    _runtime["sealed"] = True

    return StatusResponse(
        sealed=True,
        message=f"Initialized: root_id={root_id} master_id={master_id}"
    )

@router.post("/unseal", response_model=StatusResponse)
def unseal(req: UnsealRequest, current_user: UserInfo = Depends(require_role("admin"))):
    """Unseal the server by decrypting root and master key. Requires admin role."""
    root_response = requests.get(f"{STORAGE_SERVICE_URL}/api/keys/type/root")
    if root_response.status_code == 404:
        raise HTTPException(status_code=400, detail="Not initialized")

    # Initialize crypto service
    service = CryptoService()

    root_data = root_response.json()

    master_response = requests.get(f"{STORAGE_SERVICE_URL}/api/keys/type/master")
    if master_response.status_code == 404:
        raise HTTPException(status_code=400, detail="Not initialized")

    master_data = master_response.json()

    root_meta = json.loads(root_data.get("meta", "{}"))
    salt = bytes.fromhex(root_meta.get("salt", ""))

    root_ct = bytes.fromhex(root_data["encrypted_key"])
    root_nonce = bytes.fromhex(root_data["nonce"])



    kek = service.hkdf_derive(req.external_token.encode("utf-8"), salt)

    try:
        root_key = service.aesgcm_decrypt(kek, root_nonce, root_ct)
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    master_ct = bytes.fromhex(master_data["encrypted_key"])
    master_nonce = bytes.fromhex(master_data["nonce"])

    try:
        master_key = service.aesgcm_decrypt(root_key, master_nonce, master_ct)
    except Exception:
        raise HTTPException(status_code=500, detail="Master key decrypt failed")

    _runtime["root_key"] = root_key
    _runtime["master_key"] = master_key
    _runtime["sealed"] = False

    requests.put(
        f"{STORAGE_SERVICE_URL}/api/status",
        json={'sealed': False}
    )

    return StatusResponse(sealed=False, message="Unsealed successfully")

@router.post("/seal", response_model=StatusResponse)
def seal(current_user: UserInfo = Depends(require_role("admin"))):
    """Seal the server by wiping keys from memory. Requires admin role."""
    _runtime["root_key"] = None
    _runtime["master_key"] = None
    _runtime["sealed"] = True

    requests.put(
        f"{STORAGE_SERVICE_URL}/api/status",
        json={'sealed': True}
    )

    return StatusResponse(sealed=True, message="Sealed successfully")

@router.get("/status", response_model=StatusResponse)
def status(current_user: UserInfo = Depends(get_current_user)):
    """Get server seal status. Requires authentication."""
    response = requests.get(f"{STORAGE_SERVICE_URL}/api/status")
    if response.status_code == 404:
        raise HTTPException(status_code=500, detail="Status not found")

    status_data = response.json()
    return StatusResponse(sealed=status_data['sealed'])

@router.post("/issue-dek", response_model=IssueDEKResponse)
def issue_dek(current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Issue a new Data Encryption Key (DEK). Requires admin or crypto role."""
    if _runtime["sealed"]:
        raise HTTPException(status_code=400, detail="Server is sealed")
    
    # Initialize crypto service
    service = CryptoService()

    # Generate DEK
    dek = os.urandom(32)
    master_key = _runtime["master_key"]

    dek_nonce, dek_ct = service.aesgcm_encrypt(master_key, dek)

    # Store DEK
    response = requests.post(
        f"{STORAGE_SERVICE_URL}/api/keys",
        json={
            'key_type': 'dek',
            'encrypted_key': dek_ct.hex(),
            'nonce': dek_nonce.hex(),
            'version': 1,
            'active': True,
            'meta': json.dumps({"purpose": "issued_dek"})
        }
    )

    response.raise_for_status()
    dek_id = response.json()['id']

    return IssueDEKResponse(
        dek_id=dek_id,
        dek_ciphertext_b64=b64encode(dek_ct).decode()
    )

@router.post("/encrypt", response_model=EncryptResponse)
def encrypt_secret(req: EncryptRequest, current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Encrypt data with a new ephemeral DEK. Requires admin or crypto role."""
    if _runtime['sealed']:
        raise HTTPException(status_code=400, detail="Server is sealed")

    # Initialize crypto service
    service = CryptoService()

    # Generate empheral DEK
    dek = os.urandom(32)
    master_key = _runtime['master_key']
    dek_nonce, dek_ct = service.aesgcm_encrypt(master_key, dek)

    # Store DEK
    response = requests.post(
        f"{STORAGE_SERVICE_URL}/api/keys",
        json={
            'key_type': 'dek',
            'encrypted_key': dek_ct.hex(),
            'nonce': dek_nonce.hex(),
            'version': 1,
            'active': True,
            'meta': json.dumps({"purpose": "ephemeral_dek"})
        }
    )

    response.raise_for_status()
    dek_id = response.json()['id']

    # Encrypt plaintext with DEK
    encryption_nonce, ciphertext = service.aesgcm_encrypt(dek, req.plaintext)

    payload = {
        'ciphertext': b64encode(ciphertext).decode(),
        "enc_nonce": b64encode(encryption_nonce).decode()
    }

    return EncryptResponse(
        ciphertext_b64=b64encode(json.dumps(payload).encode()).decode(),
        dek_id=dek_id
    )

@router.post("/decrypt", response_model=StatusResponse)
def decrypt_secret(req: DecryptRequest, current_user: UserInfo = Depends(require_roles(["admin", "crypto"]))):
    """Decrypt data using stored DEK. Requires admin or crypto role."""
    if _runtime["sealed"]:
        raise HTTPException(status_code=400, detail="Server is sealed")

    # Initialize crypto service
    service = CryptoService()

    # Fetch DEK from storage
    response = requests.get(f"{STORAGE_SERVICE_URL}/api/keys/{req.dek_id}")
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="DEK not found")

    key_data = response.json()

    # Decrypt DEK with master key
    dek_ct = bytes.fromhex(key_data['encrypted_key'])
    dek_nonce = bytes.fromhex(key_data['nonce'])
    master_key = _runtime["master_key"]

    try:
        dek = service.aesgcm_decrypt(master_key, dek_nonce, dek_ct)
    except:
        raise HTTPException(status_code=500, detail="DEK decrypt failed")

    # Decrypt payload
    outer = json.loads(b64encode(req.ciphertext_b64).decode())
    ciphertext = b64encode(outer['ciphertext'])
    enc_nonce = b64encode(outer['enc_nonce'])

    try:
        plaintext = service.aesgcm_decrypt(dek, enc_nonce, ciphertext)
    except:
        raise HTTPException(status_code=400, detail="Decryption failed")
    
    return StatusResponse(sealed=False, message=f"decrypted: {plaintext}")
