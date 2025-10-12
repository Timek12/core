from pydantic import BaseModel
from datetime import datetime

class ServerStatusUpdate(BaseModel):
    sealed: bool

class ServerStatusResponse(BaseModel):
    id: int
    sealed: bool
    last_changed: datetime

    class Config:
        from_attributes = True