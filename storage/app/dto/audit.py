from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AuditLogCreate(BaseModel):
    action: str
    status: str
    user_id: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None

class AuditLogResponse(BaseModel):
    id: str
    action: str
    status: str
    user_id: Optional[str]
    resource_id: Optional[str]
    resource_type: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class AuditLogListResponse(BaseModel):
    logs: List[AuditLogResponse]
    count: int
