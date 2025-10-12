"""
Custom exception classes and error handling utilities
"""
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
import logging
import uuid
from datetime import datetime

from app.dto.common import ErrorResponse, ErrorDetail, ErrorType, StatusEnum

logger = logging.getLogger(__name__)

class LunaGuardException(Exception):
    """Base exception for LunaGuard application"""
    def __init__(
        self, 
        message: str, 
        error_type: ErrorType = ErrorType.INTERNAL_ERROR,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[List[ErrorDetail]] = None
    ):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        self.details = details or []
        super().__init__(self.message)

class ValidationException(LunaGuardException):
    """Validation error exception"""
    def __init__(self, message: str, details: Optional[List[ErrorDetail]] = None):
        super().__init__(
            message=message,
            error_type=ErrorType.VALIDATION_ERROR,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )

class AuthenticationException(LunaGuardException):
    """Authentication error exception"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            error_type=ErrorType.AUTHENTICATION_ERROR,
            status_code=status.HTTP_401_UNAUTHORIZED
        )

class AuthorizationException(LunaGuardException):
    """Authorization error exception"""
    def __init__(self, message: str = "Access denied"):
        super().__init__(
            message=message,
            error_type=ErrorType.AUTHORIZATION_ERROR,
            status_code=status.HTTP_403_FORBIDDEN
        )

class NotFoundException(LunaGuardException):
    """Resource not found exception"""
    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with ID '{resource_id}' not found"
        super().__init__(
            message=message,
            error_type=ErrorType.NOT_FOUND_ERROR,
            status_code=status.HTTP_404_NOT_FOUND
        )

class ConflictException(LunaGuardException):
    """Resource conflict exception"""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_type=ErrorType.CONFLICT_ERROR,
            status_code=status.HTTP_409_CONFLICT
        )

class ExternalServiceException(LunaGuardException):
    """External service error exception"""
    def __init__(self, service_name: str, message: str = "External service error"):
        full_message = f"{service_name}: {message}"
        super().__init__(
            message=full_message,
            error_type=ErrorType.EXTERNAL_SERVICE_ERROR,
            status_code=status.HTTP_502_BAD_GATEWAY
        )

class BusinessLogicException(LunaGuardException):
    """Business logic error exception"""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_type=ErrorType.BUSINESS_LOGIC_ERROR,
            status_code=status.HTTP_400_BAD_REQUEST
        )

class VaultSealedException(BusinessLogicException):
    """Vault is sealed exception"""
    def __init__(self):
        super().__init__("Vault is sealed. Please unseal the vault first.")

class CryptoOperationException(LunaGuardException):
    """Cryptographic operation error"""
    def __init__(self, operation: str, reason: str):
        message = f"Cryptographic operation '{operation}' failed: {reason}"
        super().__init__(
            message=message,
            error_type=ErrorType.BUSINESS_LOGIC_ERROR,
            status_code=status.HTTP_400_BAD_REQUEST
        )

def create_error_response(
    error_type: ErrorType,
    message: str,
    details: Optional[List[ErrorDetail]] = None,
    request_id: Optional[str] = None
) -> ErrorResponse:
    """Create standardized error response"""
    return ErrorResponse(
        error_type=error_type,
        message=message,
        details=details or [],
        request_id=request_id,
        timestamp=datetime.utcnow()
    )

def validation_error_handler(validation_error: ValidationError) -> List[ErrorDetail]:
    """Convert Pydantic validation errors to ErrorDetail list"""
    details = []
    for error in validation_error.errors():
        field = ".".join([str(loc) for loc in error["loc"]])
        details.append(ErrorDetail(
            field=field,
            message=error["msg"],
            code=error["type"]
        ))
    return details

async def lunaguard_exception_handler(request: Request, exc: LunaGuardException) -> JSONResponse:
    """Global exception handler for LunaGuard exceptions"""
    request_id = str(uuid.uuid4())
    
    # Log the error
    logger.error(
        f"LunaGuard Exception: {exc.message}",
        extra={
            "request_id": request_id,
            "error_type": exc.error_type,
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    error_response = create_error_response(
        error_type=exc.error_type,
        message=exc.message,
        details=exc.details,
        request_id=request_id
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.dict()
    )

async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """Global exception handler for Pydantic validation errors"""
    request_id = str(uuid.uuid4())
    
    details = validation_error_handler(exc)
    
    error_response = create_error_response(
        error_type=ErrorType.VALIDATION_ERROR,
        message="Validation failed",
        details=details,
        request_id=request_id
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.dict()
    )

async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Global exception handler for HTTPException"""
    request_id = str(uuid.uuid4())
    
    # Map HTTP status codes to error types
    error_type_mapping = {
        400: ErrorType.VALIDATION_ERROR,
        401: ErrorType.AUTHENTICATION_ERROR,
        403: ErrorType.AUTHORIZATION_ERROR,
        404: ErrorType.NOT_FOUND_ERROR,
        409: ErrorType.CONFLICT_ERROR,
        422: ErrorType.VALIDATION_ERROR,
        500: ErrorType.INTERNAL_ERROR,
        502: ErrorType.EXTERNAL_SERVICE_ERROR,
        503: ErrorType.EXTERNAL_SERVICE_ERROR,
    }
    
    error_type = error_type_mapping.get(exc.status_code, ErrorType.INTERNAL_ERROR)
    
    error_response = create_error_response(
        error_type=error_type,
        message=exc.detail,
        request_id=request_id
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.dict()
    )

async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for unhandled exceptions"""
    request_id = str(uuid.uuid4())
    
    # Log the error with full traceback
    logger.exception(
        "Unhandled exception occurred",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    error_response = create_error_response(
        error_type=ErrorType.INTERNAL_ERROR,
        message="An internal server error occurred",
        request_id=request_id
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.dict()
    )