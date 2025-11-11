"""
Path Validation Utility

Protects against path traversal vulnerabilities by validating that
requested paths are within allowed directories.

HIGH-01 fix: Path Traversal Protection
"""

import os
from pathlib import Path
from typing import List


class PathTraversalError(ValueError):
    """Raised when path traversal attack is detected"""
    pass


def validate_safe_path(requested_path: str, allowed_base_dirs: List[str]) -> str:
    """
    Validate that a file path is within allowed directories.

    This prevents path traversal attacks like:
    - ../../../etc/passwd
    - /etc/shadow
    - C:\\Windows\\System32\\config\\SAM

    Args:
        requested_path: The path to validate
        allowed_base_dirs: List of allowed base directory paths

    Returns:
        Absolute, resolved path if safe

    Raises:
        PathTraversalError: If path is outside allowed directories

    Example:
        >>> allowed = ["/app/data/uploads", "/app/data/quarantine"]
        >>> validate_safe_path("/app/data/uploads/email.eml", allowed)
        '/app/data/uploads/email.eml'
        >>> validate_safe_path("../../../etc/passwd", allowed)
        PathTraversalError: Path outside allowed directories
    """
    if not requested_path:
        raise PathTraversalError("Empty path provided")

    # Resolve to absolute path (resolves symlinks and .. references)
    try:
        requested_abs = os.path.abspath(requested_path)
        requested_real = os.path.realpath(requested_abs)
    except Exception as e:
        raise PathTraversalError(f"Invalid path: {str(e)}")

    # Check if within any allowed base directory
    for base_dir in allowed_base_dirs:
        try:
            base_real = os.path.realpath(os.path.abspath(base_dir))

            # Check if requested path is under base directory
            # Using Path.relative_to() which raises ValueError if not relative
            Path(requested_real).relative_to(base_real)

            # Path is safe
            return requested_real

        except ValueError:
            # Not under this base directory, try next
            continue

    # Path is outside all allowed directories
    raise PathTraversalError(
        f"Access denied: Path '{requested_path}' is outside allowed directories"
    )


def get_allowed_email_dirs() -> List[str]:
    """
    Get list of allowed directories for email file operations.

    Returns directories relative to backend module.
    """
    backend_dir = os.path.dirname(os.path.dirname(__file__))  # backend/

    return [
        os.path.join(backend_dir, "logs", "uploads"),
        os.path.join(backend_dir, "logs", "analyses"),
        os.path.join(backend_dir, "routing", "quarantine"),
        os.path.join(backend_dir, "routing", "blocked"),
    ]


def validate_email_path(eml_path: str) -> str:
    """
    Validate email file path is in allowed directories.

    Convenience function for common email validation use case.

    Args:
        eml_path: Path to email file

    Returns:
        Validated absolute path

    Raises:
        PathTraversalError: If path is unsafe
    """
    return validate_safe_path(eml_path, get_allowed_email_dirs())
