from __future__ import annotations

from typing import Any, Dict, List
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query

from backend.api.auth import require_roles
from backend.api.storage import list_analyses


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics")
def metrics(_=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, int]:
    items = list_analyses()
    total = len(items)
    quarantined = sum(1 for i in items if (i.get("final_decision") or "").upper() == "QUARANTINE")
    blocked = sum(1 for i in items if (i.get("final_decision") or "").upper() == "BLOCK")
    passed = sum(1 for i in items if (i.get("final_decision") or "").upper() == "FORWARD")
    # Include both keys for compatibility (spec expects total_emails)
    return {"total": total, "total_emails": total, "quarantined": quarantined, "blocked": blocked, "passed": passed}


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@router.get("/graph")
def graph(
    series: str = Query("total", pattern="^(total|malicious|both)$"),
    date_from: str | None = None,
    date_to: str | None = None,
    _=Depends(require_roles("viewer","analyst","admin")),
) -> Dict[str, Any]:
    items = list_analyses()
    # Date window
    if date_from:
        df = _parse_dt(date_from)
        items = [i for i in items if i.get("created_at") and _parse_dt(i["created_at"]) >= df]
    if date_to:
        dt = _parse_dt(date_to)
        items = [i for i in items if i.get("created_at") and _parse_dt(i["created_at"]) <= dt]

    # Bucket by day
    buckets: Dict[str, Dict[str, int]] = {}
    for i in items:
        ts = i.get("created_at")
        if not ts:
            continue
        d = _parse_dt(ts).date().isoformat()
        b = buckets.setdefault(d, {"total": 0, "malicious": 0})
        b["total"] += 1
        if (i.get("final_decision") or "").upper() == "BLOCK":
            b["malicious"] += 1

    # Fill missing days if range provided
    if date_from and date_to:
        df = _parse_dt(date_from).date()
        dt = _parse_dt(date_to).date()
        cur = df
        while cur <= dt:
            iso = cur.isoformat()
            buckets.setdefault(iso, {"total": 0, "malicious": 0})
            cur += timedelta(days=1)

    labels = sorted(buckets.keys())
    total_series = [buckets[d]["total"] for d in labels]
    mal_series = [buckets[d]["malicious"] for d in labels]
    resp: Dict[str, Any] = {"labels": labels}
    if series in ("total","both"):
        resp["total"] = total_series
    if series in ("malicious","both"):
        resp["malicious"] = mal_series
    return resp


@router.get("/recent")
def recent(_=Depends(require_roles("viewer","analyst","admin"))) -> List[Dict[str, Any]]:
    items = list_analyses()
    items = items[:5]
    # sender, subject, status, time
    out: List[Dict[str, Any]] = []
    for i in items:
        out.append({
            "id": i.get("id"),
            "sender": i.get("from"),
            "subject": i.get("subject"),
            "status": i.get("final_decision"),
            "time": i.get("created_at"),
        })
    return out
