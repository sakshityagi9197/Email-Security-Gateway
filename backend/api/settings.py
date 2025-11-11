from __future__ import annotations

import os
import json
import hashlib
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.auth import require_roles, _sha256

SETTINGS_FILE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs", "settings.json"))
CONFIG_FILE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".config", "config.yaml"))

router = APIRouter(prefix="/settings", tags=["settings"])


def _load_settings() -> Dict[str, Any]:
    if not os.path.exists(SETTINGS_FILE):
        return {"alerts_blocked": False, "notifications_quarantine": True}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return {**{"alerts_blocked": False, "notifications_quarantine": True}, **data}
    except Exception:
        pass
    return {"alerts_blocked": False, "notifications_quarantine": True}


def _save_settings(d: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


@router.get("")
def get_settings(_=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    return _load_settings()


class ToggleBody(BaseModel):
    value: bool


@router.put("/alerts/blocked")
def set_alerts_blocked(body: ToggleBody, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    s = _load_settings()
    s["alerts_blocked"] = bool(body.value)
    _save_settings(s)
    return s


@router.put("/notifications/quarantine")
def set_notifications_quarantine(body: ToggleBody, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    s = _load_settings()
    s["notifications_quarantine"] = bool(body.value)
    _save_settings(s)
    return s


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str


def _load_yaml(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _save_yaml(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


@router.post("/change-password")
def change_password(body: ChangePasswordBody, user=Depends(require_roles())) -> Dict[str, Any]:
    if body.new_password != body.confirm_new_password:
        raise HTTPException(400, detail="Passwords do not match")

    # Naive YAML manipulation for config.security.users (simple and safe here)
    try:
        import yaml  # type: ignore
    except Exception:
        raise HTTPException(500, detail="YAML support not available")

    if not os.path.exists(CONFIG_FILE):
        raise HTTPException(500, detail="Config not found")

    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        raise HTTPException(500, detail="Failed to read config")

    username = (user.get("sub") or "").strip().lower()
    users = (((cfg.get("security") or {}).get("users")) or [])
    match = None
    for u in users:
        if (u.get("username") or "").strip().lower() == username:
            match = u
            break
    if not match:
        raise HTTPException(404, detail="User not found in config")

    # Verify current password
    if (match.get("password_sha256") or "").lower() != _sha256(body.current_password):
        raise HTTPException(401, detail="Invalid current password")

    # Update
    match["password_sha256"] = _sha256(body.new_password)

    # Save back
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, sort_keys=False)
    except Exception:
        raise HTTPException(500, detail="Failed to update config")

    return {"status": "ok"}


@router.get("/spam-detection-level")
def spam_detection_level(_=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    return {"status": "Coming Soon"}

