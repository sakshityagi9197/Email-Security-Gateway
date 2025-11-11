from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel

from backend.api.auth import require_roles
from backend.api.storage import list_analyses, get_analysis, delete_analysis
from backend.routing.email_routing import BLOCK_DIR, QUARANTINE_DIR
import os
from backend.ingestion.ingestion import load_email
from backend.parser.parser import parse_eml
import html
import re


router = APIRouter(prefix="/emails", tags=["emails"])


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


@router.get("")
def emails_list(
    folder: str = Query("all", pattern="^(quarantine|blocked|all)$"),
    page: int = 1,
    page_size: int = 20,
    sort: str = Query("-created_at"),
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    _=Depends(require_roles("viewer","analyst","admin")),
) -> Dict[str, Any]:
    items = list_analyses()
    # Filter by folder -> final_decision
    if folder == "quarantine":
        items = [i for i in items if (i.get("final_decision") or "").upper() == "QUARANTINE"]
    elif folder == "blocked":
        items = [i for i in items if (i.get("final_decision") or "").upper() == "BLOCK"]

    # Search
    if q:
        ql = q.lower()
        items = [i for i in items if (str(i.get("subject") or "").lower().find(ql) >= 0) or (str(i.get("from") or "").lower().find(ql) >= 0)]

    # Date range
    df = _parse_dt(date_from)
    dt = _parse_dt(date_to)
    if df:
        items = [i for i in items if (t:=_parse_dt(i.get("created_at"))) and t >= df]
    if dt:
        items = [i for i in items if (t:=_parse_dt(i.get("created_at"))) and t <= dt]

    # Sort
    reverse = sort.startswith("-")
    key = sort[1:] if reverse else sort
    valid = {"created_at","subject","from","final_decision","threat_score"}
    if key not in valid:
        key = "created_at"
        reverse = True
    items.sort(key=lambda d: (d.get(key) or ""), reverse=reverse)

    total = len(items)
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    page_items = items[start:end]
    return {"total": total, "page": page, "page_size": page_size, "items": page_items}


@router.get("/{email_id}")
def email_detail(email_id: str, _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    doc = get_analysis(email_id)
    if not doc:
        raise HTTPException(404, detail="Not found")
    # Enrich with headers (collapsed) and safe-render body
    headers_collapsed: Dict[str, Any] = {}
    body_text: Optional[str] = None
    body_html_safe: Optional[str] = None
    atts_meta: List[Dict[str, Any]] = doc.get("attachments") or []
    try:
        path = ((doc.get("email") or {}).get("path"))
        if path:
            raw = load_email(path)
            eml_json = parse_eml(raw)
            # Headers collapse
            header = (eml_json or {}).get("header") or {}
            if isinstance(header, dict) and isinstance(header.get("header"), dict):
                header = header.get("header")
            if isinstance(header, dict):
                for k, v in header.items():
                    if isinstance(v, list):
                        headers_collapsed[k] = v[0] if v else None
                    else:
                        headers_collapsed[k] = v
            # Body extraction
            bodies = (eml_json or {}).get("body") or []
            # Prefer text/html for html_safe, text/plain for text
            text_part = next((b for b in bodies if (b.get("content_type") or "").lower().startswith("text/plain")), None)
            html_part = next((b for b in bodies if (b.get("content_type") or "").lower().startswith("text/html")), None)
            def _get_content(part: Dict[str, Any]) -> Optional[str]:
                if not isinstance(part, dict):
                    return None
                return part.get("content") or part.get("body") or part.get("text")
            if text_part:
                body_text = _get_content(text_part)
            if html_part:
                raw_html = _get_content(html_part)
                if raw_html is not None:
                    # Render safely: use minimal scrub of risky constructs; the UI will also sandbox.
                    s = str(raw_html)
                    # Remove script/style blocks
                    s = re.sub(r"<\s*(script|style)[^>]*?>[\s\S]*?<\s*/\s*\1\s*>", "", s, flags=re.IGNORECASE)
                    # Drop event handler attributes like onclick=... on*=
                    s = re.sub(r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", s, flags=re.IGNORECASE)
                    # Neutralize javascript: URLs in href/src
                    s = re.sub(r"(href|src)\s*=\s*(\"|')\s*javascript:[^\2]*\2", r"\1=\2#\2", s, flags=re.IGNORECASE)
                    body_html_safe = s
            # Attachment sizes from original message
            msg_atts = (eml_json or {}).get("attachment") or []
            if isinstance(msg_atts, list):
                sizes: Dict[str, Any] = {}
                for a in msg_atts:
                    fname = a.get("filename")
                    sz = a.get("size")
                    if not sz:
                        # Fallback: derive from raw attachment data length when available
                        data = (
                            a.get("raw_content") or a.get("raw") or a.get("payload") or a.get("data") or a.get("content")
                        )
                        try:
                            import base64
                            if isinstance(data, (bytes, bytearray)):
                                sz = len(data)
                            elif isinstance(data, str):
                                # approximate decoded size; exact decode is fine for small parts
                                sz = len(base64.b64decode(data, validate=False))
                        except Exception:
                            pass
                    sizes[fname] = sz
                for a in atts_meta:
                    fn = a.get("filename")
                    if fn in sizes:
                        a["size"] = sizes.get(fn)
    except Exception:
        pass
    # Provide a compact detail + reasons + enrichments
    return {
        "id": email_id,
        "email": doc.get("email"),
        "auth": doc.get("auth"),
        "attachments": atts_meta,
        "final_decision": doc.get("final_decision"),
        "reasons": doc.get("reasons") or [],
        "created_at": doc.get("created_at"),
        "headers": headers_collapsed,
        "body": {"text": body_text, "html_safe": body_html_safe},
    }


@router.delete("/{email_id}")
def email_delete(email_id: str, _=Depends(require_roles("analyst","admin"))) -> Dict[str, str]:
    ok = delete_analysis(email_id)
    if not ok:
        raise HTTPException(404, detail="Not found")
    return {"deleted": email_id}


@router.post("/{email_id}/forward")
def email_forward(email_id: str, _=Depends(require_roles("analyst","admin"))) -> Dict[str, Any]:
    # Placeholder: In a real system, this would re-route the email.
    if not get_analysis(email_id):
        raise HTTPException(404, detail="Not found")
    return {"id": email_id, "status": "forwarded"}


@router.get("/{email_id}/attachments")
def email_attachments(email_id: str, _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    doc = get_analysis(email_id)
    if not doc:
        raise HTTPException(404, detail="Not found")
    atts = doc.get("attachments") or []
    # Try to supplement size from original message
    try:
        path = ((doc.get("email") or {}).get("path"))
        if path:
            raw = load_email(path)
            eml_json = parse_eml(raw)
            msg_atts = (eml_json or {}).get("attachment") or []
            sizes: Dict[str, Any] = {}
            for a in msg_atts:
                sz = a.get("size")
                if not sz:
                    data = (a.get("raw_content") or a.get("raw") or a.get("payload") or a.get("data") or a.get("content"))
                    try:
                        import base64
                        if isinstance(data, (bytes, bytearray)):
                            sz = len(data)
                        elif isinstance(data, str):
                            sz = len(base64.b64decode(data, validate=False))
                    except Exception:
                        pass
                sizes[a.get("filename")] = sz
            for a in atts:
                fn = (a or {}).get("filename")
                if fn in sizes:
                    a["size"] = sizes.get(fn)
    except Exception:
        pass
    # Only metadata is persisted; no file content to download
    return {"items": [
        {
            "id": str(idx),
            "filename": (a or {}).get("filename") or f"attachment-{idx}",
            "size": (a or {}).get("size"),
            "is_malicious": bool((a or {}).get("is_malicious")),
        }
        for idx, a in enumerate(atts)
    ]}


@router.get("/{email_id}/attachments/{att_id}")
def email_attachment_download(email_id: str, att_id: str, _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    # Not implemented: original attachment content isn't stored
    if not get_analysis(email_id):
        raise HTTPException(404, detail="Not found")
    raise HTTPException(404, detail="Attachment content not stored")


class ClearBody(BaseModel):
    folder: str


@router.post("/clear")
def emails_clear(body: ClearBody, folder: Optional[str] = None, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    folder = (folder or body.folder or "").lower()
    if folder not in ("quarantine","blocked","all"):
        raise HTTPException(400, detail="folder must be 'quarantine', 'blocked', or 'all'")
    # Delete matching analyses
    items = list_analyses()
    targets = ["QUARANTINE", "BLOCK"] if folder == "all" else (["QUARANTINE"] if folder == "quarantine" else ["BLOCK"])
    to_delete = [i.get("id") for i in items if (i.get("final_decision") or "").upper() in targets]
    deleted = 0
    for _id in to_delete:
        if _id and delete_analysis(_id):
            deleted += 1
    # Also clear routed EML copies for selected folders
    files_deleted = 0
    def _clear_dir(path: str) -> int:
        count = 0
        try:
            if os.path.isdir(path):
                for name in os.listdir(path):
                    if name.lower().endswith(('.eml', '.json')):
                        try:
                            os.remove(os.path.join(path, name))
                            count += 1
                        except Exception:
                            pass
        except Exception:
            pass
        return count
    if folder in ("quarantine","all"):
        files_deleted += _clear_dir(QUARANTINE_DIR)
    if folder in ("blocked","all"):
        files_deleted += _clear_dir(BLOCK_DIR)
    return {"deleted": deleted, "files_deleted": files_deleted}


@router.get("/clear")
def emails_clear_get(folder: str, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    # Delegate to POST handler logic
    return emails_clear(ClearBody(folder=folder))
