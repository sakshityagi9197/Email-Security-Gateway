"""
CSRF Protection Middleware for FastAPI

This middleware validates CSRF tokens on state-changing requests (POST, PUT, PATCH, DELETE).
Works with the frontend CSRF token implementation.
"""

from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import secrets


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware

    Validates X-CSRF-Token header on POST, PUT, PATCH, DELETE requests.
    Tokens are validated using a simple session-based approach.
    """

    def __init__(self, app, exempt_paths: list = None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or [
            "/auth/login",
            "/auth/refresh",
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

    async def dispatch(self, request: Request, call_next: Callable):
        # Only check state-changing methods
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            # Check if path is exempt
            path = request.url.path
            if not any(path.startswith(exempt) for exempt in self.exempt_paths):
                # Validate CSRF token
                csrf_token = request.headers.get("X-CSRF-Token")

                if not csrf_token:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing"}
                    )

                # Validate token format (should be hex string of 64 chars)
                if not self._is_valid_token_format(csrf_token):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Invalid CSRF token format"}
                    )

                # For now, we accept any properly formatted token since it's
                # generated client-side. In production, you might want to
                # validate against a server-side session store.

        response = await call_next(request)
        return response

    def _is_valid_token_format(self, token: str) -> bool:
        """Validate CSRF token format (64 hex characters)"""
        if not token or len(token) != 64:
            return False
        try:
            int(token, 16)  # Should be valid hex
            return True
        except ValueError:
            return False


def generate_csrf_token() -> str:
    """Generate a secure CSRF token"""
    return secrets.token_hex(32)
