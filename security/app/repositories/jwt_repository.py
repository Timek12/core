from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid

from app.db.schema import JWTRefreshTokens

class JWTTokenRepository:
    """Repository for JWTRefreshTokens entity data access operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_by_id(self, token_id: int) -> Optional[JWTRefreshTokens]:
        """Find JWT token by ID."""
        return self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.id == token_id
        ).first()
    
    def find_by_jti(self, jti: uuid.UUID) -> Optional[JWTRefreshTokens]:
        """Find JWT token by JTI (JWT ID)."""
        return self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.jti == jti
        ).first()
    
    def find_by_token_hash(self, token_hash: str) -> Optional[JWTRefreshTokens]:
        """Find JWT token by token hash."""
        return self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.token_hash == token_hash
        ).first()
    
    def find_by_user_id(self, user_id: int) -> List[JWTRefreshTokens]:
        """Find all JWT tokens for a user."""
        return self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.user_id == user_id
        ).order_by(JWTRefreshTokens.created_at.desc()).all()
    
    def find_active_by_user_id(self, user_id: int) -> List[JWTRefreshTokens]:
        """Find all active (non-revoked, non-expired) JWT tokens for a user."""
        now = datetime.now(timezone.utc)
        return self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.user_id == user_id,
            JWTRefreshTokens.revoked == False,
            JWTRefreshTokens.expires_at > now
        ).order_by(JWTRefreshTokens.created_at.desc()).all()
    
    def is_token_valid(self, jti: uuid.UUID) -> bool:
        """Check if token is valid (exists, not revoked, not expired)."""
        now = datetime.now(timezone.utc)
        token = self.db.query(JWTRefreshTokens).filter(
            JWTRefreshTokens.jti == jti,
            JWTRefreshTokens.revoked == False,
            JWTRefreshTokens.expires_at > now
        ).first()
        return token is not None
    
    def save(self, token: JWTRefreshTokens) -> JWTRefreshTokens:
        """Save a new JWT token."""
        self.db.add(token)
        self.db.commit()
        self.db.refresh(token)
        return token
    
    def update(self, token: JWTRefreshTokens) -> JWTRefreshTokens:
        """Update existing JWT token."""
        self.db.commit()
        self.db.refresh(token)
        return token
    
    def delete(self, token: JWTRefreshTokens) -> None:
        """Delete a JWT token."""
        self.db.delete(token)
        self.db.commit()

    def revoke_token(self, jti: uuid.UUID) -> bool:
        """Revoke a token by JTI."""
        token = self.find_by_jti(jti)
        if not token:
            return False
        token.revoked = True
        self.save(token)
        return True