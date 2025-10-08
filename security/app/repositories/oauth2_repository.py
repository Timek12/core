from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.schema import OAuthRefreshTokens

class OAuth2TokenRepository:
    """Repository for OAuthRefreshTokens entity data access operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_by_id(self, token_id: int) -> Optional[OAuthRefreshTokens]:
        """Find OAuth token by ID."""
        return self.db.query(OAuthRefreshTokens).filter(
            OAuthRefreshTokens.id == token_id
        ).first()
    
    def find_by_user_and_provider(self, user_id: int, provider: str) -> Optional[OAuthRefreshTokens]:
        """Find OAuth token by user ID and provider."""
        return self.db.query(OAuthRefreshTokens).filter(
            OAuthRefreshTokens.user_id == user_id,
            OAuthRefreshTokens.provider == provider
        ).first()
    
    def find_by_user_id(self, user_id: int) -> List[OAuthRefreshTokens]:
        """Find all OAuth tokens for a user."""
        return self.db.query(OAuthRefreshTokens).filter(
            OAuthRefreshTokens.user_id == user_id
        ).all()
    
    def find_by_provider(self, provider: str) -> List[OAuthRefreshTokens]:
        """Find all OAuth tokens for a provider."""
        return self.db.query(OAuthRefreshTokens).filter(
            OAuthRefreshTokens.provider == provider
        ).all()
    
    def find_expired_tokens(self) -> List[OAuthRefreshTokens]:
        """Find all expired OAuth tokens."""
        now = datetime.now(timezone.utc)
        return self.db.query(OAuthRefreshTokens).filter(
            OAuthRefreshTokens.token_expires_at < now
        ).all()
    
    def save(self, token: OAuthRefreshTokens) -> OAuthRefreshTokens:
        """Save a new OAuth token."""
        self.db.add(token)
        self.db.commit()
        self.db.refresh(token)
        return token
    
    def update(self, token: OAuthRefreshTokens) -> OAuthRefreshTokens:
        """Update existing OAuth token."""
        self.db.commit()
        self.db.refresh(token)
        return token
    
    def delete(self, token: OAuthRefreshTokens) -> None:
        """Delete an OAuth token."""
        self.db.delete(token)
        self.db.commit()
    
    def delete_by_user_and_provider(self, user_id: int, provider: str) -> bool:
        """Delete OAuth token by user ID and provider."""
        token = self.find_by_user_and_provider(user_id, provider)
        if token:
            self.delete(token)
            return True
        return False