from __future__ import annotations

import json
import mailbox
from email import policy
from email.message import Message
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


def _body_snippet(msg: Message, *, max_chars: int = 2000) -> str:
    body = msg.get_body(preferencelist=("plain", "html"))
    if not body:
        return ""
    try:
        content = body.get_content()
    except Exception:
        return "(decoding error)"
    if not content:
        return ""
    return content[:max_chars]


def _attachments(msg: Message) -> list[str]:
    names: list[str] = []
    try:
        for part in msg.iter_attachments():
            fn = part.get_filename()
            if fn:
                names.append(fn)
    except Exception:
        return names
    return names


def _msg_summary(msg: Message) -> dict[str, Any]:
    return {
        "subject": msg.get("subject"),
        "from": msg.get("from"),
        "to": msg.get("to"),
        "cc": msg.get("cc"),
        "date": msg.get("date"),
        "message_id": msg.get("message-id"),
        "body_snippet": _body_snippet(msg),
        "attachments": _attachments(msg),
    }


class EmailModule(ForensicModule):
    @property
    def name(self) -> str:
        return "email"

    @property
    def description(self) -> str:
        return "Parse EML/MBOX containers (native; PST/OST are out-of-scope unless optional tools are added)."

    def run(self, case_id: str, evidence_id: str | None, **kwargs) -> Dict[str, Any]:
        if not evidence_id:
            raise ValueError("Missing evidence_id")

        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)

        with SessionLocal() as session:
            ev = session.get(Evidence, evidence_id)
            if not ev:
                raise ValueError(f"Evidence {evidence_id} not found")
            file_path = settings.vault_dir / ev.path

        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found at {file_path}")

        ext = file_path.suffix.lower()
        max_messages = int(kwargs.get("max_messages", 200))

        messages: list[dict[str, Any]] = []
        kind = None

        if ext in {".eml"}:
            import email

            kind = "eml"
            with file_path.open("rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            messages.append(_msg_summary(msg))

        elif ext in {".mbox", ".mbx"} or file_path.name.lower().endswith(".mbox"):
            kind = "mbox"
            mbox = mailbox.mbox(str(file_path), factory=None, create=False)
            count = 0
            for msg in mbox:
                if msg is None:
                    continue
                try:
                    # mailbox can yield non-policy Messages; coerce via bytes
                    import email

                    raw = msg.as_bytes()
                    parsed = email.message_from_bytes(raw, policy=policy.default)
                    messages.append(_msg_summary(parsed))
                except Exception:
                    continue
                count += 1
                if count >= max_messages:
                    break

        else:
            return {"status": "skipped", "reason": "Unsupported email container type (supported: .eml, .mbox)"}

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "email"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"{evidence_id}.json"

        payload = {
            "schema_version": 1,
            "status": "success",
            "evidence_id": evidence_id,
            "kind": kind,
            "messages_count": len(messages),
            "max_messages": max_messages,
            "messages": messages,
        }
        output_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"status": "success", "messages_count": len(messages), "output_file": str(output_file)}

