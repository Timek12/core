import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.db.db import get_db
from app.services.dek_service import DEKService


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
        
        # TODO: Proper DTO response model
        return {
            "id": str(dek.id),
            "encrypted_dek": dek.encrypted_dek,
            "nonce": dek.nonce,
            "version": dek.version,
            "is_active": dek.is_active,
            "created_at": dek.created_at.isoformat()
        }
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
        
        # TODO: Proper DTO response model
        return {
            "id": str(dek.id),
            "encrypted_dek": dek.encrypted_dek,
            "nonce": dek.nonce,
            "version": dek.version,
            "is_active": dek.is_active,
            "created_at": dek.created_at.isoformat(),
            "rotated_at": dek.rotated_at.isoformat() if dek.rotated_at else None
        }
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


@router.get("")
def list_active_deks(db: Session = Depends(get_db)):
    """List all active DEKs"""
    try:
        service = DEKService(db)
        deks = service.get_all_active_deks()
        
        # TODO: Proper DTO response model
        return [ 
            {
                "id": str(dek.id),
                "version": dek.version,
                "is_active": dek.is_active,
                "created_at": dek.created_at.isoformat()
            }
            for dek in deks
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list DEKs: {str(e)}"
        )
