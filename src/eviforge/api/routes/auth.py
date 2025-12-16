from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from eviforge.config import ACK_TEXT, load_settings
from eviforge.core.db import create_session_factory, get_setting, set_setting

router = APIRouter()


class AckRequest(BaseModel):
    text: str
    actor: str = "local"


def require_ack():
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        if get_setting(session, "authorization_ack") is None:
            raise HTTPException(status_code=428, detail={"error": "authorization_required", "ack_text": ACK_TEXT})


@router.get("/status")
def ack_status():
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    with SessionLocal() as session:
        ack = get_setting(session, "authorization_ack")
        return {"acknowledged": ack is not None, "required_text": ACK_TEXT}


@router.post("/ack")
def ack(req: AckRequest):
    if req.text.strip() != ACK_TEXT:
        raise HTTPException(status_code=400, detail={"error": "ack_text_mismatch", "required_text": ACK_TEXT})

    settings = load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    SessionLocal = create_session_factory(settings.database_url)

    with SessionLocal() as session:
        set_setting(session, "authorization_ack", {"text": req.text, "actor": req.actor})

    auth_file = settings.data_dir / "authorization.txt"
    auth_file.write_text(req.text + "\n", encoding="utf-8")

    return {"acknowledged": True}


def ack_dependency():
    require_ack()
    return True
