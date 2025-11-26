import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.schema import AuditLog

logger = logging.getLogger(__name__)

class AuditService:
    """Service for managing audit logs"""
    
    def __init__(self, db: Session):
        self.db = db
        
    def create_log(self, 
                   action: str, 
                   status: str, 
                   user_id: Optional[str] = None, 
                   resource_id: Optional[str] = None, 
                   resource_type: Optional[str] = None, 
                   ip_address: Optional[str] = None, 
                   user_agent: Optional[str] = None, 
                   details: Optional[str] = None) -> AuditLog:
        """Create a new audit log entry"""
        try:
            log_entry = AuditLog(
                action=action,
                status=status,
                user_id=user_id,
                resource_id=resource_id,
                resource_type=resource_type,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                created_at=datetime.now(timezone.utc)
            )
            
            self.db.add(log_entry)
            self.db.commit()
            self.db.refresh(log_entry)
            
            logger.info(f"Audit log created: {action} - {status} by {user_id or 'system'}")
            return log_entry
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}", exc_info=True)
            self.db.rollback()
            raise
            
    def get_logs(self, 
                 user_id: Optional[str] = None, 
                 action: Optional[str] = None, 
                 resource_type: Optional[str] = None, 
                 limit: int = 100, 
                 offset: int = 0) -> List[AuditLog]:
        """Retrieve audit logs with filtering"""
        query = self.db.query(AuditLog)
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        if action:
            query = query.filter(AuditLog.action == action)
            
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
            
        # Always order by newest first
        query = query.order_by(desc(AuditLog.created_at))
        
        return query.offset(offset).limit(limit).all()
