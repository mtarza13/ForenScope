from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi import Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from eviforge.core.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    Token,
    create_access_token,
    get_current_active_user,
    verify_password,
    get_password_hash
)
from eviforge.core.db import create_session_factory, get_setting, set_setting
from eviforge.core.models import User
from eviforge.core.audit import audit_from_user
from eviforge.config import ACK_TEXT, load_settings

router = APIRouter(prefix="/auth", tags=["auth"])


class AckRequest(BaseModel):
    text: str
    actor: str = "local"


@router.get("/ack/status")
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
        set_setting(session, "authorization_ack", {"text": req.text, "actor": req.actor, "ts": datetime.utcnow().isoformat()})

    (settings.data_dir / "authorization.txt").write_text(req.text + "\n", encoding="utf-8")
    return {"acknowledged": True}

@router.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        user = session.query(User).filter(User.username == form_data.username).first()
        
        # Determine if we should create a default admin if NO users exist
        # This is a "First Run" convenience for Step 5
        if not user:
            count = session.query(User).count()
            if count == 0 and form_data.username == "admin":
                # Create default admin
                print("Creating default admin user...")
                hashed = get_password_hash(form_data.password)
                admin = User(
                    username="admin",
                    hashed_password=hashed,
                    role="admin",
                    is_active=True
                )
                session.add(admin)
                session.commit()
                # Retry login logic
                user = admin
        
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            audit_from_user(
                session,
                action="auth.login",
                user=user,
                request=request,
                details={},
            )
            session.commit()
        except Exception:
            pass
            
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        # Also set cookie for Admin UI access
        from fastapi.responses import JSONResponse
        response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
        response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
        return response

@router.get("/me", response_model=dict)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return {
        "username": current_user.username,
        "role": current_user.role,
        "active": current_user.is_active
    }
