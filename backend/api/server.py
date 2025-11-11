from typing import Optional, List, Dict, Any
import os
import tempfile
import uuid

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from pydantic import BaseModel

from backend.api.service import analyze_eml
from backend.api.auth import router as auth_router, require_roles
from backend.api.emails import router as emails_router
from backend.api.dashboard import router as dashboard_router
from backend.api.policies import router as policies_router
from backend.api.settings import router as settings_router
from backend.api.sync import router as sync_router
from backend.api.actions import router as actions_router
from backend.api.websocket_notifications import router as websocket_router
from backend.api.csrf_middleware import CSRFMiddleware
from backend.validation_layer.dkim import verify_existing_dkim
from backend.validation_layer.spf import verify_spf
from backend.validation_layer.dmarc import validate_dmarc
from backend.ingestion.ingestion import load_email
from backend.routing.email_routing import BLOCK_DIR, QUARANTINE_DIR
from backend.validation_layer.domain_checking import analyze_domain
from backend.api.storage import (
    save_analysis,
    list_analyses,
    get_analysis,
    delete_analysis,
)
from backend.utils.path_validator import validate_email_path, PathTraversalError


from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from backend.utils.load_config import load_config
from backend.ingestion.smtp_server import ESGSMTPHandler, ESGSMTPController

app = FastAPI(title="EmailSecurity API", version="1.1")
cfg = load_config() or {}

# Add CORS middleware first (CRITICAL-05 fix: restrict origins)
def get_cors_origins():
    """Get CORS origins from config with secure defaults"""
    api_cfg = cfg.get("api", {})

    # Check environment variable first
    cors_origins_env = os.getenv("CORS_ORIGINS")
    if cors_origins_env:
        return [origin.strip() for origin in cors_origins_env.split(",")]

    # Check config
    origins = api_cfg.get("cors_origins", [])

    # If wildcard or empty, use environment-specific defaults
    if not origins or origins == ["*"]:
        env = os.getenv("ENVIRONMENT", "production")

        if env == "development":
            # Development: allow localhost
            return [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:8000",
                "http://127.0.0.1:8000",
            ]
        else:
            # Production: require explicit configuration
            print("[SECURITY WARNING] CORS origins not configured. Using restrictive defaults.")
            print("[SECURITY WARNING] Set CORS_ORIGINS environment variable or api.cors_origins in config.yaml")
            # Same origin only
            return [f"http://{api_cfg.get('host', '127.0.0.1')}:{api_cfg.get('port', 8000)}"]

    return origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    max_age=3600,
)

# Add CSRF protection middleware (after CORS)
app.add_middleware(CSRFMiddleware, exempt_paths=[
    "/auth/login",
    "/auth/refresh",
    "/auth/logout",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
])

# Include routers
app.include_router(auth_router)
app.include_router(websocket_router)
app.include_router(sync_router)
app.include_router(dashboard_router)
app.include_router(emails_router)
app.include_router(policies_router)
app.include_router(settings_router)
app.include_router(actions_router)

# --- Serve the frontend SPA under /app ---
FRONTEND_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "webapp", "dist"))
if os.path.isdir(FRONTEND_DIR):
    print(f"[webapp] Serving static UI from: {FRONTEND_DIR}")
    app.mount("/app", StaticFiles(directory=FRONTEND_DIR, html=True), name="webapp")
else:
    print(f"[webapp] Frontend directory not found: {FRONTEND_DIR}")


@app.get("/")
def root() -> RedirectResponse:
    # Redirect to the SPA when available, otherwise to health
    if os.path.isdir(FRONTEND_DIR):
        return RedirectResponse(url="/app/")
    return RedirectResponse(url="/health")
app.include_router(actions_router)


# --- SMTP Listener (optional) ---
@app.on_event("startup")
def _start_smtp_listener() -> None:
    try:
        c = cfg.get("smtp_listener") or {}
        if not c or not bool(c.get("enabled", False)):
            return
        host = str(c.get("host") or "127.0.0.1")
        port = int(c.get("port") or 2525)
        max_mb = int(c.get("max_size_mb") or 25)
        allowed_ips = c.get("allowed_ips") or []

        # Save directory (reuse uploads log dir)
        uploads_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs", "uploads"))
        os.makedirs(uploads_dir, exist_ok=True)

        handler = ESGSMTPHandler(uploads_dir, max_size_bytes=max_mb * 1024 * 1024, allowed_ips=allowed_ips)
        controller = ESGSMTPController(host, port, handler)
        controller.start()
        app.state.smtp_controller = controller
        print(f"[smtp] Listening on {host}:{port}; save_dir={uploads_dir}")
    except Exception as e:
        print(f"[smtp] Failed to start SMTP listener: {e}")


@app.on_event("shutdown")
def _stop_smtp_listener() -> None:
    try:
        ctl = getattr(app.state, "smtp_controller", None)
        if ctl:
            ctl.stop()
            print("[smtp] Listener stopped")
    except Exception:
        pass


class AnalyzePathRequest(BaseModel):
    eml_path: str
    policy_yaml_path: Optional[str] = None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze/path")
def analyze_path(req: AnalyzePathRequest, _=Depends(require_roles("analyst","admin"))) -> Dict[str, Any]:
    # HIGH-01 fix: Validate path to prevent traversal attacks
    try:
        safe_path = validate_email_path(req.eml_path)
    except PathTraversalError as e:
        raise HTTPException(403, detail=str(e))

    if not os.path.exists(safe_path):
        raise HTTPException(404, detail="EML file not found")

    result = analyze_eml(safe_path, policy_yaml_path=req.policy_yaml_path, verbose=False)
    analysis_id = save_analysis(result)
    result["id"] = analysis_id
    return result


def validate_upload_file(file: UploadFile, max_size_mb: int = 25) -> None:
    """
    Validate uploaded file before processing (HIGH-02 fix)

    Checks:
    - Content type
    - File extension
    - Filename for path traversal attempts

    Args:
        file: The uploaded file
        max_size_mb: Maximum file size in megabytes

    Raises:
        HTTPException: If validation fails
    """
    # Check content type
    allowed_types = ['message/rfc822', 'application/octet-stream', 'text/plain', 'application/x-mime']
    if file.content_type and file.content_type not in allowed_types:
        raise HTTPException(
            400,
            detail=f"Invalid content type: {file.content_type}. Expected email file (message/rfc822)."
        )

    # Check file extension
    if not file.filename or not file.filename.lower().endswith('.eml'):
        raise HTTPException(
            400,
            detail="Invalid file extension. Only .eml files are accepted."
        )

    # Check filename for path traversal
    if '..' in file.filename or '/' in file.filename or '\\' in file.filename:
        raise HTTPException(400, detail="Invalid filename: path traversal detected")

    # Filename length check
    if len(file.filename) > 255:
        raise HTTPException(400, detail="Filename too long (max 255 characters)")


@app.post("/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    policy_yaml_path: Optional[str] = Form(None),
    _roles=Depends(require_roles("analyst","admin")),
) -> Dict[str, Any]:
    # HIGH-02 fix: Validate file before processing
    validate_upload_file(file, max_size_mb=25)

    # Persist uploaded EML so detail view can re-parse headers/body later
    uploads_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs", "uploads"))
    os.makedirs(uploads_dir, exist_ok=True)
    fname = f"{uuid.uuid4().hex}.eml"
    dst_path = os.path.join(uploads_dir, fname)

    # HIGH-02 fix: Read in chunks with size limit to prevent memory exhaustion
    MAX_SIZE = 25 * 1024 * 1024  # 25MB
    total_size = 0

    try:
        with open(dst_path, "wb") as f:
            while chunk := file.file.read(8192):  # 8KB chunks
                total_size += len(chunk)
                if total_size > MAX_SIZE:
                    # Remove partial file
                    if os.path.exists(dst_path):
                        os.remove(dst_path)
                    raise HTTPException(
                        413,
                        detail=f"File too large. Maximum size: {MAX_SIZE // 1024 // 1024}MB"
                    )
                f.write(chunk)

        # HIGH-02 fix: Validate it's actually an email file
        with open(dst_path, 'rb') as f:
            sample = f.read(1024)
            # Check for common email headers
            if not (b'From:' in sample or b'Subject:' in sample or
                    b'Date:' in sample or b'Return-Path:' in sample or
                    b'Received:' in sample):
                os.remove(dst_path)
                raise HTTPException(
                    400,
                    detail="File does not appear to be a valid email (missing email headers)"
                )

    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(dst_path):
            os.remove(dst_path)
        raise HTTPException(400, detail=f"File upload failed: {str(e)}")

    # Analyze using the persistent path
    result = analyze_eml(dst_path, policy_yaml_path=policy_yaml_path, verbose=False)
    analysis_id = save_analysis(result)
    result["id"] = analysis_id

    # Notify via WebSocket about new email
    try:
        from backend.api.websocket_notifications import notify_new_email
        email_data = {
            "subject": result.get("email", {}).get("subject", ""),
            "sender": result.get("email", {}).get("from", ""),
            "created_at": result.get("created_at", ""),
            "id": analysis_id,
            "final_decision": result.get("final_decision", ""),
        }
        # Run async notification in background
        import asyncio
        asyncio.create_task(notify_new_email(email_data))
    except Exception as e:
        print(f"[websocket] Failed to send notification: {e}")

    return result


class SPFRequest(BaseModel):
    eml_path: str
    ip: str


@app.post("/auth/dkim/path")
def dkim_for_path(req: AnalyzePathRequest, _=Depends(require_roles("analyst","admin"))) -> Dict[str, Any]:
    if not os.path.exists(req.eml_path):
        raise HTTPException(404, detail="EML file not found")
    raw = load_email(req.eml_path)
    ok, msg = verify_existing_dkim(raw)
    return {"passed": bool(ok), "message": msg}


@app.post("/auth/spf")
def spf_for_path(req: SPFRequest, _=Depends(require_roles("analyst","admin"))) -> Dict[str, Any]:
    if not os.path.exists(req.eml_path):
        raise HTTPException(404, detail="EML file not found")
    raw = load_email(req.eml_path)
    ok, code, msg = verify_spf(raw, req.ip)
    return {"passed": bool(ok and code == "pass"), "code": code, "message": msg}


@app.get("/routing/list")
def routing_list(_=Depends(require_roles("analyst","admin"))) -> Dict[str, List[str]]:
    blocked = []
    quarantined = []
    if os.path.isdir(BLOCK_DIR):
        blocked = [f for f in os.listdir(BLOCK_DIR) if f.lower().endswith(".eml")]
    if os.path.isdir(QUARANTINE_DIR):
        quarantined = [f for f in os.listdir(QUARANTINE_DIR) if f.lower().endswith(".eml")]
    return {"blocked": blocked, "quarantine": quarantined}


class DomainCheckRequest(BaseModel):
    domain: str
    allowlist: Optional[List[str]] = None
    blocklist: Optional[List[str]] = None


@app.post("/domains/check")
def domain_check(req: DomainCheckRequest, _=Depends(require_roles("analyst","admin","viewer"))) -> Dict[str, Any]:
    return analyze_domain(req.domain, allowlist=req.allowlist, blocklist=req.blocklist)


@app.get("/analysis")
def analysis_list(_=Depends(require_roles("viewer","analyst","admin"))) -> List[Dict[str, Any]]:
    return list_analyses()


@app.get("/analysis/{analysis_id}")
def analysis_get(analysis_id: str, _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(404, detail="Not found")
    return data


@app.delete("/analysis/{analysis_id}")
def analysis_delete(analysis_id: str, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    ok = delete_analysis(analysis_id)
    if not ok:
        raise HTTPException(404, detail="Not found")
    return {"deleted": analysis_id}
