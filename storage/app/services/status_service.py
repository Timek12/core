from doctest import REPORT_CDIFF
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.repositories.server_status_repository import ServerStatusRepository
from app.dto.server_status import ServerStatusUpdate, ServerStatusResponse
from app.db.schema import ServerStatus

class ServerStatusService:
    """"Service for server status business logic."""

    def __init__(self, db: Session):
        self.repository = ServerStatusRepository(db)

    def get_current_status(self) -> Optional[ServerStatusResponse]:
        status = self.repository.find_current()
        return ServerStatusResponse.from_orm(status) if status else None
    
    def update_status(self, status_data: ServerStatusUpdate) -> ServerStatusResponse:
        status = self.repository.find_current()

        if status:
            status.sealed = status_data.sealed
            status.last_changed = datetime.now(timezone.utc)
            updated_status = self.repository.update(status)
        else:
            status = ServerStatus(
                sealed=status_data.sealed,
                last_changed=datetime.now(timezone.utc)
            )    

            updated_status = self.repository.save(status)
        
        return ServerStatusResponse.from_orm(updated_status)
    
    