import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.db.db import get_db
from app.services.dek_service import DEKService
from app.utils.dek_helpers import format_dek_response


router = APIRouter(prefix="/internal/deks", tags=["deks"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_dek(dek_data: Dict[str, Any], db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Create a new Data Encryption Key (already encrypted with KEK)"""
    try:
        service = DEKService(db)
        
        dek = service.create_dek(
            encrypted_dek=dek_data["encrypted_dek"],
            nonce=dek_data["nonce"]
        )
        
        return format_dek_response(dek)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create DEK: {str(e)}"
        )


@router.get("/{dek_id}")
def get_dek(dek_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get a Data Encryption Key by ID"""
    try:
        service = DEKService(db)
        dek = service.get_dek(uuid.UUID(dek_id))
        
        if not dek:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="DEK not found"
            )
        
        return format_dek_response(dek)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid DEK ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get DEK: {str(e)}"
        )



