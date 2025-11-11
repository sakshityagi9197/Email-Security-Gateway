import subprocess
from pathlib import Path
import shutil
import tempfile
from email import policy
from email.parser import BytesParser
import os
import sys

# Default ClamAV clamscan path. On Windows we default to the common
# installation path for convenience; on other platforms we prefer to
# discover clamscan/clamdscan from PATH.
if sys.platform.startswith("win"):
    CLAMSCAN_PATH = r"C:\Program Files\ClamAV\clamscan.exe"
else:
    CLAMSCAN_PATH = None


def _is_executable_file(p: Path) -> bool:
    try:
        return p.is_file() and os.access(str(p), os.X_OK)
    except Exception:
        return p.is_file()


def _find_clamscan(clamscan_path: str | None = None) -> tuple[str | None, list[str]]:
    """Return a tuple (path_to_exe_or_None, attempted_candidates).

    The function tries multiple sensible candidate binaries on both
    Unix-like systems and Windows (clamscan, clamdscan, with and without
    .exe). It also accepts a directory or explicit path and will try
    to add common suffixes. Returns a list of attempted candidate
    strings to help diagnostics.
    """
    candidates_tried: list[str] = []

    def try_path(p: str) -> str | None:
        candidates_tried.append(p)
        path = Path(p)
        if _is_executable_file(path):
            return str(path)
        return None

    # If user supplied an explicit path or directory
    if clamscan_path:
        p = Path(clamscan_path)
        # If it's a directory, try common names inside it
        if p.is_dir():
            for name in ("clamscan", "clamscan.exe", "clamdscan", "clamdscan.exe"):
                found = try_path(str(p / name))
                if found:
                    return found, candidates_tried
        else:
            # If exact file, accept; else try adding .exe on Windows
            found = try_path(str(p))
            if found:
                return found, candidates_tried
            if sys.platform.startswith("win"):
                found = try_path(str(p) + ".exe")
                if found:
                    return found, candidates_tried

    # Try to find common binaries in PATH
    for name in ("clamscan", "clamscan.exe", "clamdscan", "clamdscan.exe"):
        candidates_tried.append(name)
        which = shutil.which(name)
        if which:
            return which, candidates_tried

    # On Windows, check common install locations
    if sys.platform.startswith("win"):
        common_dirs = [
            r"C:\Program Files\ClamAV",
            r"C:\Program Files (x86)\ClamAV",
        ]
        for d in common_dirs:
            for name in ("clamscan.exe", "clamdscan.exe"):
                candidate = str(Path(d) / name)
                found = try_path(candidate)
                if found:
                    return found, candidates_tried

    return None, candidates_tried


def scan_with_clamav(file_path: str, clamscan_path: str | None = None) -> dict:
    """
    Scan a file using ClamAV (clamscan).
    Returns a dictionary with scan result.
    Keys: status: 'clean'|'infected'|'unknown', details: raw output or error
    """
    try:
        # Ensure file exists
        if not Path(file_path).is_file():
            return {"error": f"File not found: {file_path}"}

        exe, attempted = _find_clamscan(clamscan_path or CLAMSCAN_PATH)
        if not exe:
            # Provide a helpful error with suggestions the operator can follow
            return {
                "error": "clamscan not found",
                "details": "clamscan (ClamAV) executable was not found on PATH and CLAMSCAN_PATH is not valid.",
                "suggestions": [
                    "Install ClamAV and ensure 'clamscan' or 'clamdscan' is on the system PATH.",
                    "On Windows, set CLAMSCAN_PATH to the full path to clamscan.exe or add its folder to PATH.",
                    "If you prefer the daemon, install clamd and ensure 'clamdscan' is available.",
                ],
                "attempted_candidates": attempted,
            }

        # Run clamscan; use explicit exe path and --no-summary for concise output
        result = subprocess.run(
            [exe, "--no-summary", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = (result.stdout or "") + (result.stderr or "")
        output = output.strip()

        # clamscan prints either "<file>: OK" or "<file>: <name> FOUND"
        if output.endswith('OK') or ' OK' in output:
            return {"status": "clean", "details": output}
        elif 'FOUND' in output:
            return {"status": "infected", "details": output}
        else:
            return {"status": "unknown", "details": output}

    except Exception as e:
        return {"error": str(e)}


def scan_attachments_in_eml(eml_path: str, clamscan_path: str | None = None) -> dict:
    """
    Extract attachments from an .eml file and scan each with clamscan.

    Returns dict:
      {
        'malicious': bool,  # True if any attachment is infected
        'attachments': [ { 'filename': str, 'status': 'infected'|'clean'|'unknown'|'error', 'details': str }, ... ]
      }

    Use clamscan_path to override default binary location.
    """
    eml_file = Path(eml_path)
    if not eml_file.is_file():
        return {"error": f"EML file not found: {eml_path}"}

    attachments = []
    malicious_found = False

    try:
        raw = eml_file.read_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(raw)

        # Walk message parts and find attachments
        idx = 0
        for part in msg.iter_attachments():
            filename = part.get_filename() or f'attachment-{idx}'
            payload = part.get_payload(decode=True)
            if not payload:
                attachments.append({
                    'filename': filename,
                    'status': 'unknown',
                    'details': 'empty payload'
                })
                idx += 1
                continue

            # Write to temp file and scan (ensure we write bytes)
            if isinstance(payload, str):
                payload_bytes = payload.encode('utf-8', errors='replace')
            elif isinstance(payload, (bytes, bytearray)):
                payload_bytes = bytes(payload)
            else:
                # Fallback: try to coerce to bytes (may work for memoryview, bytearray-like)
                try:
                    payload_bytes = bytes(payload)
                except Exception:
                    # As a last resort, represent the payload as utf-8 text
                    payload_bytes = str(payload).encode('utf-8', errors='replace')

            with tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix='eml_attach_', suffix='_' + os.path.basename(filename)) as tf:
                tf.write(payload_bytes)
                tf_path = tf.name

            try:
                res = scan_with_clamav(tf_path, clamscan_path=clamscan_path)
                if res.get('status') == 'infected':
                    malicious_found = True
                attachments.append({
                    'filename': filename,
                    'status': res.get('status') if 'status' in res else 'error',
                    'details': res.get('details') or res.get('error')
                })
            finally:
                try:
                    os.remove(tf_path)
                except Exception:
                    pass

            idx += 1

        return {
            'malicious': malicious_found,
            'attachments': attachments
        }

    except Exception as e:
        return {"error": str(e)}
