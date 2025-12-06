from typing import Dict, Any


def format_dek_response(dek, include_encrypted: bool = True) -> Dict[str, Any]:
    """Format DEK object to response dict"""
    response = {
        "id": str(dek.id),
        "version": dek.version,
        "is_active": dek.status == 'active',
        "created_at": dek.created_at.isoformat()
    }
    
    if include_encrypted:
        response.update({
            "encrypted_dek": dek.encrypted_key,
            "nonce": dek.nonce
        })
    
    return response
