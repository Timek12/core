from typing import Optional
from sqlalchemy.orm import Session
from app.db.schema import ServerStatus

class ServerStatusRepository:
    """Repository for ServerStatus entity data access operations."""

    def __init__(self, db: Session):
        self.db = db

    def find_current(self) -> Optional[ServerStatus]:
        """Get current server status."""
        return self.db.query(ServerStatus).order_by(ServerStatus.id.desc()).first()
    
    def save(self, status: ServerStatus) -> ServerStatus:
        """Save a new status."""
        self.db.add(status)
        self.db.commit()
        self.db.refresh(status)
        return status
    
    def update(self, status: ServerStatus) -> ServerStatus:
        """Update existing status."""
        self.db.commit()
        self.db.refresh(status)
        return status
    