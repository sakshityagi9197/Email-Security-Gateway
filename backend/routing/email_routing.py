import os
import shutil
import json
import logging
import smtplib
from email import policy
from email.parser import BytesParser
from datetime import datetime
from typing import Optional, Dict, Any, List

from backend.utils.load_config import load_config

# Setup logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Routing base directories
BASE_DIR = os.path.dirname(__file__)
BLOCK_DIR = os.path.join(BASE_DIR, "blocked")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")


def _forward_email(eml_path: str, mail_from: str, rcpt_to: List[str]) -> bool:
    """
    Forwards the email to the downstream MTA (e.g., Postfix).
    """
    try:
        cfg = load_config()
        downstream_cfg = cfg.get("downstream_mta", {})
        host = downstream_cfg.get("host")
        port = downstream_cfg.get("port")

        if not host or not port:
            log.error("Downstream MTA host or port not configured. Cannot forward email.")
            return False

        with open(eml_path, 'rb') as f:
            eml_content = f.read()

        # Try to parse and send as an EmailMessage (better control over serialization)
        msg = None
        try:
            msg = BytesParser(policy=policy.SMTP).parsebytes(eml_content)
        except Exception:
            # parsing failed: we'll fall back to raw bytes
            msg = None

        with smtplib.SMTP(host, port) as server:
            try:
                if msg is not None:
                    server.send_message(msg, from_addr=mail_from, to_addrs=rcpt_to)
                else:
                    server.sendmail(mail_from, rcpt_to, eml_content)
                log.info(f"Successfully forwarded email from {mail_from} to {rcpt_to} via {host}:{port}")
                return True
            except smtplib.SMTPDataError as e:
                # downstream MTA sometimes rejects very long lines per RFC5321
                err_bytes = getattr(e, 'smtp_error', None)
                err_text = ''
                try:
                    if isinstance(err_bytes, (bytes, bytearray)):
                        err_text = err_bytes.decode('utf-8', errors='ignore')
                    else:
                        err_text = str(err_bytes)
                except Exception:
                    err_text = str(e)

                log.error(f"SMTP DATA error when forwarding email: {e} ({err_text})")
                if 'line too long' in err_text.lower() or 'line too long' in str(e).lower():
                    log.info("Detected 'line too long' from downstream; attempting to wrap long lines and retry")

                    # Helper: naive long-line breaker (best-effort)
                    def break_long_lines(b: bytes, limit: int = 998) -> bytes:
                        out_parts = []
                        # Ensure we operate on CRLF-separated lines
                        normalized = b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                        for line in normalized.split(b"\n"):
                            if len(line) <= limit:
                                out_parts.append(line + b"\r\n")
                            else:
                                # break into chunks of 'limit' bytes; append CRLF after each
                                i = 0
                                while i < len(line):
                                    chunk = line[i:i+limit]
                                    out_parts.append(chunk + b"\r\n")
                                    i += limit
                        return b''.join(out_parts)

                    try:
                        if msg is not None:
                            # Re-serialize with a conservative max_line_length
                            try:
                                safe_policy = policy.default.clone(max_line_length=998)
                                bytes_out = msg.as_bytes(policy=safe_policy)
                            except Exception:
                                # as_bytes may still produce long lines for some parts; fallback to naive breaker
                                bytes_out = msg.as_bytes()
                                bytes_out = break_long_lines(bytes_out)
                        else:
                            bytes_out = break_long_lines(eml_content)

                        server.sendmail(mail_from, rcpt_to, bytes_out)
                        log.info(f"Successfully forwarded email on retry (wrapped lines) to {rcpt_to} via {host}:{port}")
                        return True
                    except Exception as retry_e:
                        log.error(f"Retry after wrapping long lines failed: {retry_e}")
                        return False
                # other SMTPDataError reasons -> log and fail
                return False
            except Exception as e:
                log.error(f"Failed to forward email: {e}")
                return False
    except Exception as e:
        log.error(f"Failed to forward email: {e}")
        return False


# Routing base directories
BASE_DIR = os.path.dirname(__file__)
BLOCK_DIR = os.path.join(BASE_DIR, "blocked")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")


def _ensure_dirs():
    os.makedirs(BLOCK_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)


def _decide_action(result: Dict[str, Any]) -> Optional[str]:
    """
    Decide routing action based on analysis result dict produced by main pipeline.

    Priority:
    - If result.final_decision is one of {block, quarantine, forward} -> honor it
    - Else if policy.final_action in {block, quarantine} -> use it
    - Else if attachments contain any is_malicious=True -> "quarantine"
    - Else if final_decision == FAIL -> "quarantine"
    - Otherwise None
    """
    try:
        # First, honor explicit final decision if provided
        fd = (result.get("final_decision") or "").strip().lower()
        if fd in {"block", "quarantine", "forward"}:
            return None if fd == "forward" else fd

        policy = result.get("policy") or {}
        final_action = policy.get("final_action") if isinstance(policy, dict) else None
        if final_action in {"block", "quarantine"}:
            return final_action

        # Fallbacks
        attachments = result.get("attachments") or []
        if any(att.get("is_malicious") for att in attachments if isinstance(att, dict)):
            return "quarantine"

        if str(result.get("final_decision")).upper() == "FAIL":
            return "quarantine"
    except Exception:
        pass
    return None


def _unique_dest_path(folder: str, filename: str) -> str:
    base = os.path.splitext(os.path.basename(filename))[0]
    ext = os.path.splitext(filename)[1] or ".eml"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = os.path.join(folder, f"{base}_{ts}{ext}")
    if not os.path.exists(candidate):
        return candidate
    # Add incremental suffix if needed
    i = 1
    while True:
        cand = os.path.join(folder, f"{base}_{ts}_{i}{ext}")
        if not os.path.exists(cand):
            return cand
        i += 1


def route_email(eml_path: str, result: Dict[str, Any]) -> Optional[str]:
    """
    Route the EML to blocked/quarantine based on analysis result, or forward to downstream MTA.

    Returns destination path if routed (block/quarantine), otherwise None for forward.
    Also writes a sidecar metadata JSON next to the copied EML.
    """
    action = _decide_action(result)

    if not action:
        # This means the action is FORWARD
        try:
            email_meta = result.get("email", {})
            mail_from = email_meta.get("from")
            # Assuming 'to' might be a list or a single string, ensure it's a list
            rcpt_to = email_meta.get("to", [])
            if isinstance(rcpt_to, str):
                rcpt_to = [rcpt_to]

            if not mail_from or not rcpt_to:
                log.error(f"Cannot forward email, missing 'from' or 'to' in result: {email_meta}")
                return None

            _forward_email(eml_path, mail_from, rcpt_to)
        except Exception as e:
            log.error(f"Error during email forwarding process: {e}")
        return None

    _ensure_dirs()

    dest_folder = BLOCK_DIR if action == "block" else QUARANTINE_DIR
    dest_path = _unique_dest_path(dest_folder, eml_path)

    shutil.copy2(eml_path, dest_path)

    # Write sidecar metadata
    meta = {
        "routed_at": datetime.now().isoformat(),
        "action": action,
        "source_path": os.path.abspath(eml_path),
        "email": result.get("email"),
        "final_decision": result.get("final_decision"),
        "reasons": result.get("reasons"),
        "policy": {
            "final_action": (result.get("policy") or {}).get("final_action") if isinstance(result.get("policy"), dict) else None,
            "threat_score": (result.get("policy") or {}).get("threat_score") if isinstance(result.get("policy"), dict) else None,
        },
    }
    try:
        with open(dest_path + ".json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass

    return dest_path
