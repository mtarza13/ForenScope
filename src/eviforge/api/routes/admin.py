from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from eviforge.config import load_settings
from eviforge.core.audit import audit_from_user
from eviforge.core.auth import ack_dependency, get_password_hash, require_roles, User
from eviforge.core.db import create_session_factory, get_setting, set_setting
from eviforge.core.models import User as DbUser

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(ack_dependency), Depends(require_roles("admin"))],
)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,48}[a-zA-Z0-9]$")


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    is_active: bool = True


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    password: str


@router.get("/users")
def list_users():
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        users = session.query(DbUser).order_by(DbUser.created_at.desc()).all()
        return [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "is_active": bool(u.is_active),
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ]


@router.post("/users")
def create_user(request: Request, req: UserCreate, current_user: User = Depends(require_roles("admin"))):
    username = req.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Invalid username (use 3-50 chars: letters, digits, . _ -)")
    if len(req.password) < 12:
        raise HTTPException(status_code=400, detail="Password too short (min 12 chars)")
    if req.role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Invalid role")

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        exists = session.query(DbUser).filter(DbUser.username == username).first()
        if exists:
            raise HTTPException(status_code=409, detail="Username already exists")

        u = DbUser(
            username=username,
            hashed_password=get_password_hash(req.password),
            role=req.role,
            is_active=req.is_active,
        )
        session.add(u)
        session.commit()

        try:
            audit_from_user(
                session,
                action="admin.user.create",
                user=current_user,
                request=request,
                details={"username": username, "role": req.role, "is_active": req.is_active},
            )
            session.commit()
        except Exception:
            pass

        return {"id": u.id, "username": u.username, "role": u.role, "is_active": bool(u.is_active)}


@router.patch("/users/{user_id}")
def update_user(request: Request, user_id: str, req: UserUpdate, current_user: User = Depends(require_roles("admin"))):
    if req.role is not None and req.role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Invalid role")

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        u = session.get(DbUser, user_id)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        changed: dict[str, Any] = {}
        if req.role is not None and req.role != u.role:
            changed["role"] = {"from": u.role, "to": req.role}
            u.role = req.role
        if req.is_active is not None and bool(req.is_active) != bool(u.is_active):
            changed["is_active"] = {"from": bool(u.is_active), "to": bool(req.is_active)}
            u.is_active = bool(req.is_active)

        session.add(u)
        session.commit()

        if changed:
            try:
                audit_from_user(
                    session,
                    action="admin.user.update",
                    user=current_user,
                    request=request,
                    details={"user_id": user_id, "changes": changed},
                )
                session.commit()
            except Exception:
                pass

        return {"id": u.id, "username": u.username, "role": u.role, "is_active": bool(u.is_active)}


@router.post("/users/{user_id}/reset-password")
def reset_password(request: Request, user_id: str, req: PasswordReset, current_user: User = Depends(require_roles("admin"))):
    if len(req.password) < 12:
        raise HTTPException(status_code=400, detail="Password too short (min 12 chars)")

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        u = session.get(DbUser, user_id)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        u.hashed_password = get_password_hash(req.password)
        session.add(u)
        session.commit()

        try:
            audit_from_user(
                session,
                action="admin.user.reset_password",
                user=current_user,
                request=request,
                details={"user_id": user_id},
            )
            session.commit()
        except Exception:
            pass

        return {"ok": True}


ALLOWED_SETTINGS = {
    "max_upload_bytes": "Max evidence upload size (bytes). Use /import for large evidence.",
    "max_artifact_preview_bytes": "Max artifact preview size (bytes).",
}


class SettingsUpdate(BaseModel):
    values: dict[str, Any]


@router.get("/settings")
def get_admin_settings():
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        out: dict[str, Any] = {}
        for k in ALLOWED_SETTINGS:
            out[k] = get_setting(session, k)
        return {"values": out, "help": ALLOWED_SETTINGS}


@router.patch("/settings")
def update_admin_settings(request: Request, req: SettingsUpdate, current_user: User = Depends(require_roles("admin"))):
    values = req.values or {}
    unknown = sorted([k for k in values.keys() if k not in ALLOWED_SETTINGS])
    if unknown:
        raise HTTPException(status_code=400, detail={"error": "unknown_settings", "keys": unknown})

    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        for k, v in values.items():
            set_setting(session, k, v)

        try:
            audit_from_user(
                session,
                action="admin.settings.update",
                user=current_user,
                request=request,
                details={"keys": sorted(values.keys())},
            )
            session.commit()
        except Exception:
            pass

    return {"ok": True}
