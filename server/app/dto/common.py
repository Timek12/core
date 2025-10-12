"""
Common DTOs used across all APIs for consistent response formatting
"""
from pydantic import BaseModel, Field
from typing import Optional, Generic, TypeVar, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

# Generic type for pagination
T = TypeVar('T')

class StatusEnum(str, Enum):
    """Standard status values"""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class ErrorType(str, Enum):
    """Error type classification"""
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error" 
    NOT_FOUND_ERROR = "not_found_error"
    CONFLICT_ERROR = "conflict_error"
    INTERNAL_ERROR = "internal_error"
    EXTERNAL_SERVICE_ERROR = "external_service_error"
    BUSINESS_LOGIC_ERROR = "business_logic_error"

class ErrorDetail(BaseModel):
    """Detailed error information"""
    field: Optional[str] = Field(None, description="Field name that caused the error")
    message: str = Field(..., description="Human-readable error message")
    code: Optional[str] = Field(None, description="Error code for programmatic handling")

class ErrorResponse(BaseModel):
    """Standardized error response format"""
    status: StatusEnum = StatusEnum.ERROR
    error_type: ErrorType = Field(..., description="Type of error")
    message: str = Field(..., description="Main error message")
    details: Optional[List[ErrorDetail]] = Field(None, description="Detailed error information")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request ID for tracking")
    
class SuccessResponse(BaseModel):
    """Standardized success response format"""
    status: StatusEnum = StatusEnum.SUCCESS
    message: str = Field(..., description="Success message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request ID for tracking")

class PaginationMeta(BaseModel):
    """Pagination metadata"""
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, le=100, description="Number of items per page")
    total_items: int = Field(..., ge=0, description="Total number of items")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_previous: bool = Field(..., description="Whether there is a previous page")

class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response"""
    status: StatusEnum = StatusEnum.SUCCESS
    data: List[T] = Field(..., description="List of items")
    meta: PaginationMeta = Field(..., description="Pagination metadata")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class DataResponse(BaseModel, Generic[T]):
    """Generic data response wrapper"""
    status: StatusEnum = StatusEnum.SUCCESS
    data: T = Field(..., description="Response data")
    message: Optional[str] = Field(None, description="Optional message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class HealthCheck(BaseModel):
    """Health check response"""
    status: StatusEnum = Field(..., description="Service health status")
    service: str = Field(..., description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    uptime: Optional[int] = Field(None, description="Uptime in seconds")
    dependencies: Optional[Dict[str, str]] = Field(None, description="Dependency health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AuditInfo(BaseModel):
    """Audit information for tracking changes"""
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp") 
    created_by: Optional[str] = Field(None, description="User who created the record")
    updated_by: Optional[str] = Field(None, description="User who last updated the record")

class BaseEntity(BaseModel):
    """Base entity with common fields"""
    id: uuid.UUID = Field(..., description="Unique identifier")
    audit: AuditInfo = Field(..., description="Audit information")
    
    class Config:
        from_attributes = True

# Request/Response patterns
class IdRequest(BaseModel):
    """Request with just an ID"""
    id: uuid.UUID = Field(..., description="Resource identifier")

class BulkRequest(BaseModel, Generic[T]):
    """Bulk operation request"""
    items: List[T] = Field(..., min_length=1, max_length=100, description="Items to process")

class BulkResponse(BaseModel):
    """Bulk operation response"""
    status: StatusEnum = StatusEnum.SUCCESS
    processed: int = Field(..., description="Number of successfully processed items")
    failed: int = Field(..., description="Number of failed items")
    errors: Optional[List[ErrorDetail]] = Field(None, description="Errors for failed items")
    timestamp: datetime = Field(default_factory=datetime.utcnow)