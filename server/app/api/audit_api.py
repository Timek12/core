from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
import logging

from app.dto.audit import AuditLogListResponse
from app.clients.storage_client import StorageClient
from app.dto.token import UserInfo
from app.dependencies import get_storage_client, get_token_from_request, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit"])

@router.get("", response_model=AuditLogListResponse)
async def get_audit_logs(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    token: str = Depends(get_token_from_request),
    current_user: UserInfo = Depends(get_current_user),
    storage_client: StorageClient = Depends(get_storage_client)
):
    """Get audit logs. Admins can see all, users only their own."""
    try:
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
