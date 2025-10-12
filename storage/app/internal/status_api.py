from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.db import get_db
from app.services.status_service import ServerStatusService
from app.dto.server_status import ServerStatusUpdate, ServerStatusResponse
from app.utils.jwt_utils import get_current_user, UserInfo, require_role

router = APIRouter(prefix="/internal/status", tags=["status"])

@router.get("", response_model=ServerStatusResponse)
def get_server_status(
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(get_current_user)
):
    """Get server status - requires authentication"""
    service = ServerStatusService(db)
    status_response = service.get_current_status()

    if not status_response:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Status not found"
        )
    
    return status_response

@router.put("", response_model=ServerStatusResponse)
def update_server_status(
    status_data: ServerStatusUpdate,
    db: Session = Depends(get_db),
    current_user: UserInfo = Depends(require_role("admin"))
):
    """Update server status - requires admin role"""
    service = ServerStatusService(db)
    return service.update_status(status_data)
