from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.schema import Keys

class KeyRepository:
    """Repository for Keys entity data access operations."""

    def __init__(self, db: Session):
        self.db = db

    def find_by_id(self, key_id: int) -> Optional[Keys]:
        """Find key by ID."""
        return self.db.query(Keys).filter(Keys.id == key_id).first()
    
    def find_by_type(self, key_type: str) -> Optional[Keys]:
        """Find the most recent active key by type."""
        return self.db.query(Keys).filter(
            Keys.key_type == key_type,
            Keys.active == True
        ).order_by(Keys.id.desc()).first()
    
    def find_all_active(self, key_type: Optional[str] = None) -> List[Keys]:
        """Find all active keys, optionally filtered by type."""
        query = self.db.query(Keys).filter(Keys.active == True)
        if key_type:
            query = query.filter(Keys.key_type == key_type)
        return query.order_by(Keys.created_at.desc()).all()
    
    def save(self, key: Keys) -> Keys:
        """Save a new key."""
        self.db.add(key)
        self.db.commit()
        self.db.refresh(key)
        return key
    
    def update(self, key: Keys) -> Keys:
        """Update existing key."""
        self.db.commit()
        self.db.refresh(key)
        return key
    