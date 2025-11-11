from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.auth import require_roles
from backend.api.storage import get_analysis


router = APIRouter(tags=["actions"])


class ForwardBody(BaseModel):
    id: str


@router.post("/forward")
def forward_email(body: ForwardBody, _=Depends(require_roles("analyst","admin"))) -> Dict[str, Any]:
    if not get_analysis(body.id):
        raise HTTPException(404, detail="Not found")
    # Placeholder implementation
    return {"id": body.id, "status": "forwarded"}

