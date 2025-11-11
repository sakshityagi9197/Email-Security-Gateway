"""
Security Audit Logger

Logs security-relevant events for forensics, compliance, and incident detection.

HIGH-07 fix: Security Event Logging
"""

import logging
import os
from datetime import datetime
from typing import Optional


# Configure audit logger
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
logs_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(logs_dir, exist_ok=True)

# File handler for audit log
audit_log_path = os.path.join(logs_dir, "audit.log")
audit_handler = logging.FileHandler(audit_log_path)
audit_handler.setFormatter(
    logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
)
audit_logger.addHandler(audit_handler)

# Also log to console in development
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter('%(asctime)s - AUDIT - %(message)s', datefmt='%H:%M:%S')
)
audit_logger.addHandler(console_handler)


def log_security_event(
    event_type: str,
    username: Optional[str],
    ip_address: Optional[str],
    details: str,
    success: bool = True,
    severity: str = "INFO"
):
    """
    Log security-relevant events for audit trail.

    Events logged:
    - Authentication (login, logout, failed attempts)
    - Authorization failures (insufficient permissions)
    - File access (uploads, downloads, deletions)
    - Configuration changes
    - API access
    - Security violations (CSRF, path traversal, etc.)

    Args:
        event_type: Type of event (LOGIN, LOGOUT, AUTH_FAILURE, FILE_ACCESS, etc.)
        username: Username associated with the event (or None if not applicable)
        ip_address: IP address of the client (or None if not applicable)
        details: Detailed description of the event
        success: Whether the operation succeeded
        severity: Log level (INFO, WARNING, ERROR)

    Example:
        log_security_event(
            "LOGIN",
            "admin",
            "192.168.1.10",
            "User logged in successfully",
            success=True
        )
    """
    status = "SUCCESS" if success else "FAILURE"

    log_message = (
        f"{event_type} | {status} | "
        f"user={username or 'N/A'} | "
        f"ip={ip_address or 'N/A'} | "
        f"{details}"
    )

    # Log at appropriate level
    if severity == "ERROR" or not success:
        audit_logger.error(log_message)
    elif severity == "WARNING":
        audit_logger.warning(log_message)
    else:
        audit_logger.info(log_message)


def log_auth_event(event_type: str, username: str, ip_address: str, details: str, success: bool):
    """Log authentication event (login, logout, etc.)"""
    log_security_event(
        event_type=event_type,
        username=username,
        ip_address=ip_address,
        details=details,
        success=success,
        severity="WARNING" if not success else "INFO"
    )


def log_authorization_failure(username: str, ip_address: str, required_roles: list, user_roles: list):
    """Log authorization failure (insufficient permissions)"""
    log_security_event(
        event_type="AUTHORIZATION_FAILURE",
        username=username,
        ip_address=ip_address,
        details=f"Insufficient roles. Required: {required_roles}, Has: {user_roles}",
        success=False,
        severity="WARNING"
    )


def log_file_operation(operation: str, username: str, ip_address: str, file_path: str, success: bool):
    """Log file operation (upload, download, delete, etc.)"""
    log_security_event(
        event_type=f"FILE_{operation.upper()}",
        username=username,
        ip_address=ip_address,
        details=f"File: {file_path}",
        success=success,
        severity="INFO" if success else "WARNING"
    )


def log_security_violation(violation_type: str, ip_address: str, details: str):
    """Log security violation (CSRF, path traversal, etc.)"""
    log_security_event(
        event_type=f"SECURITY_VIOLATION_{violation_type.upper()}",
        username=None,
        ip_address=ip_address,
        details=details,
        success=False,
        severity="ERROR"
    )


def log_api_access(endpoint: str, method: str, username: Optional[str], ip_address: str, status_code: int):
    """Log API access for audit trail"""
    success = 200 <= status_code < 300

    log_security_event(
        event_type="API_ACCESS",
        username=username,
        ip_address=ip_address,
        details=f"{method} {endpoint} - Status {status_code}",
        success=success,
        severity="INFO" if success else "WARNING"
    )
