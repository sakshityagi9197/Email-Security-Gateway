from __future__ import annotations

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

BASE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs", "analyses"))


def _ensure_dir() -> None:
    os.makedirs(BASE_DIR, exist_ok=True)


def save_analysis(result: Dict[str, Any]) -> str:
    _ensure_dir()
    analysis_id = uuid4().hex
    doc = dict(result)
    doc["id"] = analysis_id
    doc["created_at"] = datetime.utcnow().isoformat() + "Z"
    path = os.path.join(BASE_DIR, f"{analysis_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return analysis_id


def list_analyses(
    limit: Optional[int] = None,
    offset: int = 0,
    sort_by: str = "created_at",
    reverse: bool = True
) -> List[Dict[str, Any]]:
    """
    List analyses with pagination and efficient sorting (MEDIUM-01 fix)

    Args:
        limit: Maximum number of items to return (None = all)
        offset: Number of items to skip
        sort_by: Field to sort by (created_at, threat_score)
        reverse: Sort in reverse order (True = newest first)

    Returns:
        List of analysis summaries

    Optimization:
    - Uses file stats for sorting when possible (avoids loading files)
    - Only loads files needed for the requested page
    - Reduces memory usage for large datasets
    """
    _ensure_dir()

    # Get file list with metadata (avoids loading full JSON)
    file_metadata = []
    for name in os.listdir(BASE_DIR):
        if not name.endswith(".json"):
            continue
        path = os.path.join(BASE_DIR, name)
        try:
            stat = os.stat(path)
            file_metadata.append({
                "path": path,
                "name": name,
                "mtime": stat.st_mtime,  # Modification time
                "size": stat.st_size
            })
        except Exception:
            continue

    # Sort by modification time (proxy for created_at) for efficiency
    # This avoids loading all files just to sort
    if sort_by == "created_at":
        file_metadata.sort(key=lambda f: f["mtime"], reverse=reverse)
    else:
        # For other sort fields, we need to load files
        # Sort after loading in this case
        pass

    # Apply pagination at file level
    start = offset
    end = start + limit if limit else len(file_metadata)
    selected_files = file_metadata[start:end]

    # Load only selected files
    items = []
    for file_info in selected_files:
        try:
            with open(file_info["path"], "r", encoding="utf-8") as f:
                data = json.load(f)

            items.append({
                "id": data.get("id"),
                "created_at": data.get("created_at"),
                "from": ((data.get("email") or {}).get("from")),
                "subject": ((data.get("email") or {}).get("subject")),
                "final_decision": data.get("final_decision"),
                "threat_score": ((data.get("policy") or {}).get("threat_score")),
            })
        except Exception:
            continue

    # If sorting by non-time field, sort after loading
    if sort_by == "threat_score":
        items.sort(key=lambda d: d.get("threat_score") or 0, reverse=reverse)

    return items


def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(BASE_DIR, f"{analysis_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def delete_analysis(analysis_id: str) -> bool:
    path = os.path.join(BASE_DIR, f"{analysis_id}.json")
    if not os.path.exists(path):
        return False
    try:
        os.remove(path)
        return True
    except Exception:
        return False

