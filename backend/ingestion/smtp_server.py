from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any, Dict, Optional

from email import policy
from email.parser import BytesParser

try:
    from aiosmtpd.controller import Controller
except Exception:  # pragma: no cover - aiosmtpd may not be installed in some environments
    Controller = None  # type: ignore

from backend.api.service import analyze_eml
from backend.api.storage import save_analysis


class ESGSMTPHandler:
    """SMTP handler that saves incoming mail, adds X-Cyveon-ESG header, and triggers analysis.

    The handler returns quickly (accepts mail) and processes analysis asynchronously.
    """

    def __init__(self, save_dir: str, *, max_size_bytes: int = 25 * 1024 * 1024, allowed_ips: Optional[list[str]] = None) -> None:
        self.save_dir = os.path.normpath(save_dir)
        self.max_size = int(max_size_bytes)
        self.allowed_ips = set(allowed_ips or [])
        os.makedirs(self.save_dir, exist_ok=True)

    async def handle_DATA(self, server, session, envelope):  # type: ignore[no-untyped-def]
        # Log the connection attempt
        try:
            peer = session.peer
            src_ip = peer[0] if isinstance(peer, (list, tuple)) and len(peer) >= 1 else None
            print(f"[smtp] Handling DATA from {src_ip or 'unknown'}")
        except Exception as e:
            print(f"[smtp] Error getting peer info: {e}")
            src_ip = None
            
        # Optionally filter by source IP
        if self.allowed_ips and src_ip and src_ip not in self.allowed_ips:
            return "550 5.7.1 Access denied"

        try:
            content: bytes = envelope.content or b""
            if self.max_size and len(content) > self.max_size:
                print(f"[smtp] Message exceeds size limit ({len(content)} > {self.max_size})")
                return "552 5.3.4 Message size exceeds fixed maximum message size"
        except Exception as e:
            print(f"[smtp] Error reading message content: {e}")
            return "451 4.3.0 Temporary processing error"

        # Parse, add header, and persist
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
        except Exception:
            # If parsing fails, still store raw with token header prepended
            msg = None

        token = uuid.uuid4().hex
        filename = f"{uuid.uuid4().hex}.eml"
        path = os.path.join(self.save_dir, filename)
        try:
            if msg is not None:
                msg.add_header("X-Cyveon-ESG", token)
                data = msg.as_bytes()
            else:
                # Prepend header manually
                data = (f"X-Cyveon-ESG: {token}\r\n").encode("utf-8") + content
            with open(path, "wb") as f:
                f.write(data)
        except Exception:
            return "451 4.3.0 Temporary processing error"

        # Fire-and-forget analysis to avoid blocking SMTP
        async def _analyze() -> None:
            try:
                result: Dict[str, Any] = analyze_eml(path, policy_yaml_path=None, verbose=False)
                # Persist for dashboard
                save_analysis(result)
            except Exception:
                # Best-effort; avoid crashing the loop
                pass

        try:
            asyncio.create_task(_analyze())
        except RuntimeError:
            # If no running loop, run synchronously as last resort
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(_analyze())
                loop.close()
            except Exception:
                pass

        return "250 2.0.0 Message accepted for delivery"


class ESGSMTPController:
    """Wrapper to encapsulate the aiosmtpd Controller lifecycle."""

    def __init__(self, host: str, port: int, handler: ESGSMTPHandler) -> None:
        if Controller is None:
            raise RuntimeError("aiosmtpd is not installed; please add aiosmtpd to requirements and install it")
        self._controller = Controller(handler, hostname=host, port=int(port))

    def start(self) -> None:
        self._controller.start()

    def stop(self) -> None:
        try:
            self._controller.stop()
        except Exception:
            pass

