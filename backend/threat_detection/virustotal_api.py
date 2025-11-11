# threat_detection/virustotal_api.py

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
from backend.threat_detection.constants import HEADERS_VT

# HIGH-03 fix: Add timeouts to prevent hung connections
VT_UPLOAD_TIMEOUT = 30  # seconds - file uploads can be slow
VT_API_TIMEOUT = 15     # seconds - API calls

# MEDIUM-02 fix: Connection pooling for better performance
_vt_session = None


def get_vt_session() -> requests.Session:
    """
    Get or create VirusTotal session with connection pooling (MEDIUM-02 fix)

    Benefits:
    - Reuses TCP connections
    - Automatic retry on transient failures
    - Better performance for multiple requests
    - Reduced server load
    """
    global _vt_session

    if _vt_session is None:
        _vt_session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,  # Wait 1, 2, 4 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=["GET", "POST"]
        )

        # Configure connection pool
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Number of connection pools
            pool_maxsize=20       # Connections per pool
        )

        _vt_session.mount("https://", adapter)
        _vt_session.mount("http://", adapter)

    return _vt_session


def scan_file_virustotal(file_path: str) -> dict:
    """
    Upload file to VirusTotal for scanning.

    HIGH-03 fix: Added timeout to prevent indefinite hangs.
    MEDIUM-02 fix: Uses connection pooling for better performance.
    """
    url = "https://www.virustotal.com/api/v3/files"
    session = get_vt_session()  # MEDIUM-02 fix: Use pooled connection

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = session.post(  # Use session instead of requests
                url,
                headers=HEADERS_VT,
                files=files,
                timeout=VT_UPLOAD_TIMEOUT  # HIGH-03 fix
            )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal scan failed: {response.status_code}", "details": response.text}

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API timeout - request took too long"}
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


def get_report_virustotal(file_hash: str) -> dict:
    """
    Get VirusTotal report for file hash.

    HIGH-03 fix: Added timeout to prevent indefinite hangs.
    MEDIUM-02 fix: Uses connection pooling for better performance.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    session = get_vt_session()  # MEDIUM-02 fix: Use pooled connection

    try:
        response = session.get(  # Use session instead of requests
            url,
            headers=HEADERS_VT,
            timeout=VT_API_TIMEOUT  # HIGH-03 fix
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "File not found in VirusTotal database"}
        else:
            return {
                "error": f"VT report fetch failed: {response.status_code}",
                "details": response.text
            }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API timeout - request took too long"}
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}