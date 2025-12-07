from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.db.db import get_db
from app.services.audit_service import AuditService
from app.dto.audit import AuditLogCreate, AuditLogResponse, AuditLogListResponse
from app.utils.jwt_utils import get_current_user, UserInfo

router = APIRouter(prefix="/internal/audit", tags=["audit"])

def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    return AuditService(db)

@router.get("", response_model=AuditLogListResponse)
def get_audit_logs(
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: AuditService = Depends(get_audit_service),
    _: UserInfo = Depends(get_current_user)
):
    """Retrieve audit logs with filtering"""
    try:
        logs = service.get_logs(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            limit=limit,
            offset=offset
        )
        return AuditLogListResponse(logs=logs, count=len(logs))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
