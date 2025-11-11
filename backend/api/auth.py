from __future__ import annotations

from typing import Any, Dict, List, Optional, Callable

import hashlib
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError  # CRITICAL-06 fix: Use python-jose for JWT

from backend.utils.load_config import load_config
from backend.utils.audit_logger import log_auth_event, log_authorization_failure  # HIGH-07 fix


router = APIRouter(prefix="/auth", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=False)

# LOW-02 fix: Extract magic numbers to constants
DEFAULT_ACCESS_EXPIRES_MINUTES = 60
DEFAULT_REFRESH_EXPIRES_DAYS = 7
SECONDS_PER_MINUTE = 60
SECONDS_PER_DAY = 86400
MAX_INACTIVITY_SECONDS = 15 * 60  # 15 minutes
TOKEN_BLACKLIST_FORMAT_VERSION = 2  # For future migrations


def _users_from_config() -> List[Dict[str, Any]]:
    cfg = load_config() or {}
    users = (cfg.get("security") or {}).get("users") or []
    return users if isinstance(users, list) else []


def _get_secret_and_exp() -> Dict[str, Any]:
    """
    Get JWT secret and expiration times from config (LOW-02 fix: uses constants)
    """
    cfg = load_config() or {}
    sec = (cfg.get("security") or {})

    # Use constants instead of magic numbers
    access_minutes = sec.get("access_expires_minutes") or DEFAULT_ACCESS_EXPIRES_MINUTES
    refresh_days = sec.get("refresh_expires_days") or DEFAULT_REFRESH_EXPIRES_DAYS

    return {
        "secret": sec.get("jwt_secret") or "change-me",
        "access_exp": int(access_minutes * SECONDS_PER_MINUTE),
        "refresh_exp": int(refresh_days * SECONDS_PER_DAY),
    }


def _sha256(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    username = (username or "").strip().lower()
    for u in _users_from_config():
        if (u.get("username") or "").strip().lower() == username:
            stored = (u.get("password_sha256") or "").lower()
            if stored and stored == _sha256(password or ""):
                return {"username": username, "roles": u.get("roles") or []}
    return None


def _encode_token(payload: Dict[str, Any], secret: str) -> str:
    """
    Encode JWT using python-jose library (CRITICAL-06 fix)

    Benefits over custom implementation:
    - Industry-standard implementation
    - Protection against known JWT vulnerabilities
    - Automatic algorithm validation
    - Better error handling
    """
    try:
        return jwt.encode(payload, secret, algorithm="HS256")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token encoding failed: {str(e)}")


def _decode_token(token: str, secret: str) -> Dict[str, Any]:
    """
    Decode and validate JWT using python-jose library (CRITICAL-06 fix)

    Validates:
    - Signature integrity
    - Token expiration
    - Algorithm (prevents algorithm confusion attacks)
    """
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# --- Refresh token blacklist with expiration tracking (CRITICAL-08 fix) ---
import os
import json
from typing import List, Tuple

_BLACKLIST_FILE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs", "token_blacklist.json"))


def _load_blacklist() -> List[Tuple[str, int]]:
    """
    Load blacklist with expiration times.

    Returns: List of (token, expiration_timestamp) tuples
    """
    try:
        if os.path.exists(_BLACKLIST_FILE):
            with open(_BLACKLIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Support both old format (list of strings) and new format (list of [token, exp])
                if data and isinstance(data, list):
                    if isinstance(data[0], str):
                        # OLD format - migrate to new format
                        # LOW-02 fix: Use constant for default expiration
                        default_exp = int(time.time()) + (DEFAULT_REFRESH_EXPIRES_DAYS * SECONDS_PER_DAY)
                        return [(token, default_exp) for token in data]
                    return data
    except Exception:
        return []
    return []


def _save_blacklist(items: List[Tuple[str, int]]) -> None:
    """
    Save blacklist, automatically removing expired tokens (CRITICAL-08 fix)

    This prevents infinite growth by cleaning up expired entries on each save.
    """
    current_time = int(time.time())

    # Keep only non-expired tokens
    active_items = [(token, exp) for token, exp in items if exp > current_time]

    os.makedirs(os.path.dirname(_BLACKLIST_FILE), exist_ok=True)
    with open(_BLACKLIST_FILE, "w", encoding="utf-8") as f:
        json.dump(active_items, f, ensure_ascii=False, indent=2)


def _is_refresh_revoked(token: str) -> bool:
    """
    Check if token is revoked, automatically cleaning expired entries.
    """
    items = _load_blacklist()
    current_time = int(time.time())

    # Check if token is in blacklist and not expired
    for stored_token, exp_time in items:
        if stored_token == token:
            return exp_time > current_time

    return False


def _revoke_refresh(token: str) -> None:
    """
    Revoke refresh token with expiration tracking (CRITICAL-08 fix)

    Stores token with its expiration time so it can be automatically
    cleaned up after it would have expired anyway.
    """
    items = _load_blacklist()

    # Decode token to get expiration time
    try:
        cfg = _get_secret_and_exp()
        payload = _decode_token(token, cfg["secret"])
        exp_time = payload.get("exp", int(time.time()) + cfg["refresh_exp"])
    except Exception:
        # If decode fails, use default refresh duration
        cfg = _get_secret_and_exp()
        exp_time = int(time.time()) + cfg["refresh_exp"]

    # Add to blacklist if not already present
    if not any(stored_token == token for stored_token, _ in items):
        items.append((token, exp_time))
        _save_blacklist(items)


def require_roles(*roles: str) -> Callable[[HTTPAuthorizationCredentials], Dict[str, Any]]:
    def _dep(
        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
        request: Request = None
    ) -> Dict[str, Any]:
        if not credentials or not credentials.credentials:
            raise HTTPException(status_code=401, detail="Missing bearer token")
        cfg = _get_secret_and_exp()
        payload = _decode_token(credentials.credentials, cfg["secret"])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        # Check for session timeout (frontend handles 15min inactivity)
        # Backend validates token hasn't been idle too long
        last_activity = payload.get("last_activity", payload.get("iat", 0))
        now = int(time.time())

        # LOW-02 fix: Use constant instead of magic number
        if now - last_activity > MAX_INACTIVITY_SECONDS:
            raise HTTPException(status_code=401, detail="Session expired due to inactivity")

        user_roles = set(payload.get("roles") or [])

        # HIGH-07 fix: Log authorization failures
        if roles and user_roles.isdisjoint(set(roles)):
            client_ip = request.client.host if request and request.client else "unknown"
            log_authorization_failure(
                payload.get("sub"),
                client_ip,
                list(roles),
                list(user_roles)
            )
            raise HTTPException(status_code=403, detail="Insufficient role")

        return {
            "sub": payload.get("sub"),
            "roles": list(user_roles),
            "last_activity": last_activity
        }
    return _dep


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login")
def login(request: Request, payload: LoginRequest) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    username = payload.username.strip().lower()

    user = _verify_user(username, payload.password)

    if not user:
        # HIGH-07 fix: Log failed login attempt
        log_auth_event(
            "LOGIN",
            username,
            client_ip,
            "Invalid credentials",
            success=False
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # HIGH-07 fix: Log successful login
    log_auth_event(
        "LOGIN",
        user["username"],
        client_ip,
        f"User logged in with roles: {user.get('roles')}",
        success=True
    )

    cfg = _get_secret_and_exp()
    now = int(time.time())
    access = _encode_token({
        "sub": user["username"],
        "roles": user.get("roles") or [],
        "type": "access",
        "iat": now,
        "exp": now + cfg["access_exp"],
        "last_activity": now,  # Track activity for session timeout
    }, cfg["secret"])
    refresh = _encode_token({
        "sub": user["username"],
        "roles": user.get("roles") or [],
        "type": "refresh",
        "iat": now,
        "exp": now + cfg["refresh_exp"],
    }, cfg["secret"])
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": {"username": user["username"], "roles": user.get("roles") or []},
        "roles": user.get("roles") or [],
        "expires_in": cfg["access_exp"],
    }


@router.post("/refresh")
def refresh(payload: RefreshRequest) -> Dict[str, Any]:
    cfg = _get_secret_and_exp()
    if _is_refresh_revoked(payload.refresh_token):
        raise HTTPException(status_code=401, detail="Refresh token revoked")
    data = _decode_token(payload.refresh_token, cfg["secret"])
    if data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    now = int(time.time())
    new_access = _encode_token({
        "sub": data.get("sub"),
        "roles": data.get("roles") or [],
        "type": "access",
        "iat": now,
        "exp": now + cfg["access_exp"],
        "last_activity": now,  # Reset activity on refresh
    }, cfg["secret"])
    return {"access_token": new_access, "token_type": "bearer", "expires_in": cfg["access_exp"]}


@router.get("/me")
def me(info = Depends(require_roles())) -> Dict[str, Any]:
    return {"user": info}


class LogoutRequest(BaseModel):
    refresh_token: str


@router.post("/logout")
def logout(request: Request, payload: LogoutRequest) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"

    # Try to extract username from token for audit log
    username = None
    try:
        cfg = _get_secret_and_exp()
        token_payload = _decode_token(payload.refresh_token, cfg["secret"])
        username = token_payload.get("sub")
    except:
        pass

    # HIGH-07 fix: Log logout event
    log_auth_event(
        "LOGOUT",
        username or "unknown",
        client_ip,
        "User logged out",
        success=True
    )

    # Optional server-side blacklist of refresh tokens
    try:
        _revoke_refresh(payload.refresh_token)
    except Exception:
        pass

    return {"status": "ok"}
