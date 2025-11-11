from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from backend.api.auth import require_roles
from backend.api.storage import list_analyses
from backend.api.policies import _list_policy_files, POLICY_DIR, get_active_policy_path
import os
import time


router = APIRouter(tags=["sync"])


@router.post("/sync")
def sync(_=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    # Build a compact payload used by UI badges
    items = list_analyses()
    metrics = {
        "total": len(items),
        "quarantined": sum(1 for i in items if (i.get("final_decision") or "").upper() == "QUARANTINE"),
        "blocked": sum(1 for i in items if (i.get("final_decision") or "").upper() == "BLOCK"),
        "passed": sum(1 for i in items if (i.get("final_decision") or "").upper() == "FORWARD"),
    }
    # Policies
    pols = []
    for f in _list_policy_files():
        p = os.path.join(POLICY_DIR, f)
        active_path = get_active_policy_path()
        pols.append({
            "name": f,
            "active": os.path.normpath(p) == os.path.normpath(active_path) if active_path else False,
            "last_modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(p)))
        })
    # Emails recent
    recent = [
        {
            "id": i.get("id"),
            "from": i.get("from"),
            "subject": i.get("subject"),
            "final_decision": i.get("final_decision"),
            "created_at": i.get("created_at"),
        }
        for i in items[:5]
    ]
    return {"metrics": metrics, "policies": pols[:5], "recent": recent}

