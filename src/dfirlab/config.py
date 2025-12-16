from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

AUTH_STATEMENT = "I confirm I have legal authorization to process this evidence."


def _xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def config_dir() -> Path:
    return _xdg_config_home() / "dfirlab"


def authorization_path() -> Path:
    return config_dir() / "authorization.json"


@dataclass(frozen=True)
class AuthorizationState:
    acknowledged: bool
    acknowledged_at: str | None = None
    statement: str | None = None


def load_authorization() -> AuthorizationState:
    path = authorization_path()
    if not path.exists():
        return AuthorizationState(acknowledged=False)
    data = json.loads(path.read_text(encoding="utf-8"))
    return AuthorizationState(
        acknowledged=bool(data.get("acknowledged")),
        acknowledged_at=data.get("acknowledged_at"),
        statement=data.get("statement"),
    )


def acknowledge_authorization(*, statement: str) -> AuthorizationState:
    if statement.strip() != AUTH_STATEMENT:
        raise ValueError("Authorization statement did not match required acknowledgement text.")
    path = authorization_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    payload = {"acknowledged": True, "acknowledged_at": now, "statement": AUTH_STATEMENT}
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return AuthorizationState(acknowledged=True, acknowledged_at=now, statement=AUTH_STATEMENT)
