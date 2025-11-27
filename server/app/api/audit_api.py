from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import Optional
import logging

from app.dto.audit import AuditLogListResponse
from app.clients.storage_client import StorageClient
from app.utils.jwt_utils import get_current_user
from app.dto.token import UserInfo
from app.dependencies import get_storage_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit"])

def get_token_from_request(request: Request) -> str:
    """Extract JWT token from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""

@router.get("", response_model=AuditLogListResponse)
async def get_audit_logs(
    request: Request,
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get audit logs. Admins can see all, users only their own."""
    try:
        token = get_token_from_request(request)
        
        # Access Control
        if "admin" not in current_user.roles:
            # Regular user can only see their own logs
            if user_id and user_id != str(current_user.user_id):
                 raise HTTPException(status_code=403, detail="Cannot view other users' logs")
            # Force user_id filter for non-admins
            user_id = str(current_user.user_id)
            
        result = await storage_client.get_audit_logs(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            limit=limit,
            offset=offset,
            jwt_token=token
        )
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
