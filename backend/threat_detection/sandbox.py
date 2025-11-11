# threat_detection/sandbox.py

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import time
from backend.threat_detection.constants import HYBRID_ANALYSIS_BASE_URL, HEADERS_HA

# HIGH-03 fix: Add timeouts to prevent hung connections
HA_UPLOAD_TIMEOUT = 30  # seconds - file uploads can be slow
HA_API_TIMEOUT = 15     # seconds - API calls

# MEDIUM-02 fix: Connection pooling for better performance
_ha_session = None


def get_ha_session() -> requests.Session:
    """
    Get or create Hybrid Analysis session with connection pooling (MEDIUM-02 fix)
    """
    global _ha_session

    if _ha_session is None:
        _ha_session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )

        # Configure connection pool
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )

        _ha_session.mount("https://", adapter)
        _ha_session.mount("http://", adapter)

    return _ha_session


def submit_to_hybrid_analysis(file_path: str) -> dict:
    """
    Submit file to Hybrid Analysis for sandbox analysis.

    HIGH-03 fix: Added timeout to prevent indefinite hangs.
    MEDIUM-02 fix: Uses connection pooling for better performance.
    """
    session = get_ha_session()  # MEDIUM-02 fix

    try:
        url = f"{HYBRID_ANALYSIS_BASE_URL}/submit/file"
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            data = {"environment_id": 300}  # 300 = Windows 10

            response = session.post(  # Use session
                url,
                headers=HEADERS_HA,
                files=files,
                data=data,
                timeout=HA_UPLOAD_TIMEOUT  # HIGH-03 fix
            )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HA submission failed: {response.status_code}", "details": response.text}

    except requests.exceptions.Timeout:
        return {"error": "Hybrid Analysis API timeout - request took too long"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Hybrid Analysis API error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


def get_hybrid_analysis_report(sha256_hash: str) -> dict:
    """
    Get Hybrid Analysis report for file hash.

    HIGH-03 fix: Added timeout to prevent indefinite hangs.
    MEDIUM-02 fix: Uses connection pooling for better performance.
    """
    session = get_ha_session()  # MEDIUM-02 fix
    url = f"{HYBRID_ANALYSIS_BASE_URL}/report/{sha256_hash}"

    try:
        response = session.get(  # Use session
            url,
            headers=HEADERS_HA,
            timeout=HA_API_TIMEOUT  # HIGH-03 fix
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "File not found in Hybrid Analysis database"}
        else:
            return {"error": f"HA report fetch failed: {response.status_code}", "details": response.text}

    except requests.exceptions.Timeout:
        return {"error": "Hybrid Analysis API timeout - request took too long"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Hybrid Analysis API error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}
