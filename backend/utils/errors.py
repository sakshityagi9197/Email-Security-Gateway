"""
Standardized Error Responses

Provides consistent error format across all API endpoints.

LOW-03 fix: Standardized Error Messages
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException


class APIError(HTTPException):
    """
    Standardized API error with consistent format (LOW-03 fix)

    All errors returned in format:
    {
        "error_code": "DESCRIPTIVE_ERROR_CODE",
        "message": "Human-readable error message",
        "details": {...}  # Optional additional context
    }
    """

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status_code,
            detail={
                "error_code": error_code,
                "message": message,
                "details": details or {}
            }
        )


# Predefined error types for common scenarios

class AuthenticationError(APIError):
    """401 Authentication errors"""

    def __init__(self, message: str = "Authentication failed", details: Optional[Dict] = None):
        super().__init__(
            status_code=401,
            error_code="AUTHENTICATION_FAILED",
            message=message,
            details=details
        )


class AuthorizationError(APIError):
    """403 Authorization errors"""

    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict] = None):
        super().__init__(
            status_code=403,
            error_code="INSUFFICIENT_PERMISSIONS",
            message=message,
            details=details
        )


class NotFoundError(APIError):
    """404 Not found errors"""

    def __init__(self, resource: str, resource_id: Optional[str] = None):
        message = f"{resource} not found"
        if resource_id:
            message += f": {resource_id}"

        super().__init__(
            status_code=404,
            error_code="RESOURCE_NOT_FOUND",
            message=message,
            details={"resource": resource, "id": resource_id}
        )


class ValidationError(APIError):
    """400 Validation errors"""

    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict] = None):
        super().__init__(
            status_code=400,
            error_code="VALIDATION_ERROR",
            message=message,
            details={"field": field, **(details or {})}
        )


class ConflictError(APIError):
    """409 Conflict errors"""

    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(
            status_code=409,
            error_code="RESOURCE_CONFLICT",
            message=message,
            details=details
        )


class RateLimitError(APIError):
    """429 Rate limit errors"""

    def __init__(self, message: str = "Too many requests", retry_after: Optional[int] = None):
        super().__init__(
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            message=message,
            details={"retry_after_seconds": retry_after}
        )


class ServerError(APIError):
    """500 Internal server errors"""

    def __init__(self, message: str = "Internal server error", details: Optional[Dict] = None):
        super().__init__(
            status_code=500,
            error_code="INTERNAL_SERVER_ERROR",
            message=message,
            details=details
        )


class ExternalServiceError(APIError):
    """502/503 External service errors"""

    def __init__(
        self,
        service: str,
        message: str = "External service unavailable",
        status_code: int = 503
    ):
        super().__init__(
            status_code=status_code,
            error_code="EXTERNAL_SERVICE_ERROR",
            message=f"{service}: {message}",
            details={"service": service}
        )


# Convenience functions for common error scenarios

def file_not_found(path: str) -> NotFoundError:
    """Standardized file not found error"""
    return NotFoundError("File", path)


def analysis_not_found(analysis_id: str) -> NotFoundError:
    """Standardized analysis not found error"""
    return NotFoundError("Analysis", analysis_id)


def invalid_file_type(filename: str, allowed_types: list) -> ValidationError:
    """Standardized invalid file type error"""
    return ValidationError(
        f"Invalid file type for '{filename}'",
        field="file",
        details={"allowed_types": allowed_types}
    )


def file_too_large(filename: str, max_size_mb: int, actual_size_mb: float) -> ValidationError:
    """Standardized file too large error"""
    return ValidationError(
        f"File '{filename}' exceeds maximum size of {max_size_mb}MB",
        field="file",
        details={"max_size_mb": max_size_mb, "actual_size_mb": actual_size_mb}
    )


def path_traversal_detected(path: str) -> AuthorizationError:
    """Standardized path traversal error"""
    return AuthorizationError(
        "Access denied: Path outside allowed directories",
        details={"attempted_path": path}
    )
