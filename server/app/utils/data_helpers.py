import json
from typing import Optional, Dict, Any


def parse_metadata_json(metadata_json: Optional[str]) -> Dict[str, Any]:
    """Parse metadata JSON string, return empty dict on error"""
    if not metadata_json:
        return {}
    try:
        return json.loads(metadata_json)
    except (json.JSONDecodeError, TypeError):
        return {}


def format_dek_response(dek) -> Dict[str, Any]:
    """Format DEK object to response dict"""
    return {
        "id": str(dek.id),
        "encrypted_dek": dek.encrypted_dek,
        "nonce": dek.nonce,
        "version": dek.version,
        "is_active": dek.is_active,
        "created_at": dek.created_at.isoformat(),
        "rotated_at": dek.rotated_at.isoformat() if dek.rotated_at else None
    }
