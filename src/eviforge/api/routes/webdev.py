from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import os

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt

from eviforge.core.auth import ALGORITHM, SECRET_KEY
from eviforge.config import ACK_TEXT, load_settings
from eviforge.core.db import create_session_factory, get_setting
from eviforge.core.models import AuditLog, User

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _web_user_from_cookie(request: Request) -> User | None:
    raw = request.cookies.get("access_token")
    if not raw:
        return None
    token = raw[7:] if raw.startswith("Bearer ") else raw
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
    except JWTError:
        return None

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        return session.query(User).filter(User.username == username).first()


@router.get("/login", response_class=HTMLResponse)
async def web_login(request: Request):
    next_url = request.query_params.get("next")
    return templates.TemplateResponse("admin/login.html", {"request": request, "next": next_url})


@router.get("", response_class=HTMLResponse)
async def web_index(request: Request):
    """
    Serve the main case dashboard.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/cases/{case_id}", response_class=HTMLResponse)
async def web_case_detail(request: Request, case_id: str):
    """
    Serve the case details page.
    """
    return templates.TemplateResponse("case.html", {"request": request, "case_id": case_id})


@router.get("/ack", response_class=HTMLResponse)
async def web_ack(request: Request):
    next_url = request.query_params.get("next")
    return templates.TemplateResponse("ack.html", {"request": request, "next": next_url})


@router.get("/osint", response_class=HTMLResponse)
async def web_osint(request: Request):
    return templates.TemplateResponse("osint.html", {"request": request})


def _redact_url(url: str) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" not in rest:
        return url
    creds, host = rest.split("@", 1)
    if ":" in creds:
        user, _pw = creds.split(":", 1)
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://***@{host}"


def _tool_status(name: str, version_args: list[str] | None = None) -> dict:
    path = shutil.which(name)
    if not path:
        return {"name": name, "enabled": False, "path": None, "version": None}
    version = None
    if version_args:
        try:
            p = subprocess.run([path, *version_args], capture_output=True, text=True, timeout=2)
            out = (p.stdout or p.stderr or "").strip().splitlines()
            version = out[0] if out else None
        except Exception:
            version = None
    return {"name": name, "enabled": True, "path": path, "version": version}


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def web_job_detail(request: Request, job_id: str):
    return templates.TemplateResponse("job.html", {"request": request, "job_id": job_id})


@router.get("/admin", response_class=HTMLResponse)
async def web_admin(request: Request):
    user = _web_user_from_cookie(request)
    if not user:
        next_url = request.url.path
        return RedirectResponse(url=f"/web/login?next={next_url}", status_code=302)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        ack = get_setting(session, "authorization_ack")
        audit_log = session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()

    tools = [
        _tool_status("exiftool", ["-ver"]),
        _tool_status("tshark", ["--version"]),
        _tool_status("zeek", ["--version"]),
        _tool_status("suricata", ["--build-info"]),
        _tool_status("bulk_extractor", ["-h"]),
        _tool_status("yara", ["--version"]),
    ]

    try:
        import importlib
        v3 = importlib.util.find_spec("volatility3") is not None
    except Exception:
        v3 = False

    tools.append({"name": "volatility3 (python)", "enabled": v3, "path": None, "version": None})

    ctx = {
        "request": request,
        "ack_required": ACK_TEXT,
        "acknowledged": ack is not None,
        "user": user,
        "data_dir": str(settings.data_dir),
        "vault_dir": str(settings.vault_dir),
        "database_url": _redact_url(settings.database_url),
        "redis_url": _redact_url(settings.redis_url),
        "tools": tools,
        "audit_log": audit_log,
    }
    return templates.TemplateResponse("admin.html", ctx)
