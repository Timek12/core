from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid

class ProjectInternalCreate(BaseModel):
    name: str

class ProjectMemberAdd(BaseModel):
    user_id: int
    role: str = 'member'

class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_by: int
    created_at: datetime

    class Config:
        from_attributes = True

class ProjectMemberResponse(BaseModel):
    project_id: uuid.UUID
    user_id: int
    role: str
    joined_at: datetime

    class Config:
        from_attributes = True
