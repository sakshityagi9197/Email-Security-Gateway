from __future__ import annotations

import os
from typing import Dict

try:
    from backend.utils.load_config import load_config
except Exception:
    load_config = None  # type: ignore


def _from_config(path: str, default: str | None = None) -> str | None:
    try:
        if load_config is None:
            return default
        cfg = load_config() or {}
        cur = cfg
        for part in path.split('.'):
            if not isinstance(cur, dict):
                return default
            cur = cur.get(part)  # type: ignore[index]
        if isinstance(cur, str):
            return cur
    except Exception:
        return default
    return default


# Hybrid Analysis base URL (public default)
HYBRID_ANALYSIS_BASE_URL: str = os.getenv("HA_BASE_URL", _from_config("threat_detection.hybrid_analysis_base_url", "https://www.hybrid-analysis.com/api/v2") or "https://www.hybrid-analysis.com/api/v2")

# API keys: prefer config, then environment, else empty (requests may 401, which the callers already handle)
_VT_KEY = _from_config("threat_detection.virustotal_api_key") or os.getenv("VIRUSTOTAL_API_KEY", "")
_HA_KEY = _from_config("threat_detection.hybrid_analysis_api_key") or os.getenv("HYBRID_ANALYSIS_API_KEY", "")


HEADERS_VT: Dict[str, str] = {
    "x-apikey": _VT_KEY,
}

HEADERS_HA: Dict[str, str] = {
    "accept": "application/json",
    "api-key": _HA_KEY,
}

