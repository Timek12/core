from __future__ import annotations

from typing import Optional, List
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.services.data_service import DataService
from app.repositories.data_repository import DataRepository
from app.db.db import get_db
from app.dto.data import DataInternalCreate, DataInternalUpdate
from app.utils.jwt_utils import get_current_user, require_role
from app.dto.token import UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/data", tags=["data"])


def get_data_service(db: Session = Depends(get_db)) -> DataService:
    """Provide a DataService instance for request scope."""
    repository = DataRepository(db)
    return DataService(repository)


def _parse_data_id(data_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(data_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid data id") from exc


def _parse_user_id(user_info: UserInfo) -> int:
    try:
        return int(user_info.user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id") from exc


@router.post("", status_code=status.HTTP_201_CREATED)
def create_data(
    request: DataInternalCreate,
    current_user: UserInfo = Depends(get_current_user),
    service: DataService = Depends(get_data_service),
):
    """Create a new typed data for the authenticated user."""
    user_id = _parse_user_id(current_user)
    try:
        return service.create_data(user_id, request)
    except Exception as exc:
        logger.error("Failed to create data: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/{data_id}")
def get_data(
    data_id: str,
    current_user: UserInfo = Depends(get_current_user),
    service: DataService = Depends(get_data_service),
):
    """Retrieve a data (encrypted payload) for the authenticated user."""
    user_id = _parse_user_id(current_user)
    data_uuid = _parse_data_id(data_id)

    data_item = service.get_data(data_uuid, user_id)
    if not data_item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data not found")
    return data_item


@router.get("")
def list_data(
    request: Request,
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    current_user: UserInfo = Depends(get_current_user),
    service: DataService = Depends(get_data_service),
):
    """List data belonging to the authenticated user."""
    user_id = _parse_user_id(current_user)
    return service.list_data(user_id, data_type)


@router.put("/{data_id}")
def update_data(
    data_id: str,
    request: DataInternalUpdate,
    current_user: UserInfo = Depends(get_current_user),
    service: DataService = Depends(get_data_service),
):
    """Update an existing data owned by the authenticated user."""
    user_id = _parse_user_id(current_user)
    data_uuid = _parse_data_id(data_id)

    updated = service.update_data(data_uuid, user_id, request)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data not found")
    return updated


@router.delete("/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_data(
    data_id: str,
    current_user: UserInfo = Depends(get_current_user),
    service: DataService = Depends(get_data_service),
):
    """Delete a data belonging to the authenticated user."""
    user_id = _parse_user_id(current_user)
    data_uuid = _parse_data_id(data_id)

    deleted = service.delete_data(data_uuid, user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data not found")
    return None


# ------------------------------ Admin endpoints ------------------------------


def _ensure_admin(user: UserInfo = Depends(require_role("admin"))) -> UserInfo:
    return user


@router.get("/admin/all")
def get_all_data_admin(
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    _: UserInfo = Depends(_ensure_admin),
    service: DataService = Depends(get_data_service),
):
    """Admin: list all data across users."""
    return service.get_all_data_admin(data_type)


@router.get("/admin/user/{user_id}")
def get_data_for_user_admin(
    user_id: int,
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    _: UserInfo = Depends(_ensure_admin),
    service: DataService = Depends(get_data_service),
):
    """Admin: list data for a specific user."""
    return service.get_data_for_user_admin(user_id, data_type)


@router.delete("/admin/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_data_admin(
    data_id: str,
    _: UserInfo = Depends(_ensure_admin),
    service: DataService = Depends(get_data_service),
):
    """Admin: delete any data by ID."""
    data_uuid = _parse_data_id(data_id)
    deleted = service.delete_data_admin(data_uuid)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data not found")
    return None
