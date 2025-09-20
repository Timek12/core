from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, DateTime, UUID
import uuid
from datetime import datetime

Base = declarative_base()

class SecretDAO(Base):
    __tablename__ = 'secrets'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(256), nullable=False)
    description = Column(String, nullable=False)
    key_id = Column(UUID(as_uuid=True), nullable=False)
    encrypted_value = Column(String, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=datetime.timezone.utc)
    updated_at = Column(DateTime, nullable=False, default=datetime.timezone.utc, onupdate=datetime.timezone.utc)
