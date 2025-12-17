from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import Evidence
from eviforge.modules.base import ForensicModule


EVTX_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _text(node, path: str) -> str | None:
    if node is None:
        return None
    found = node.find(path, EVTX_NS)
    if found is None:
        return None
    return (found.text or "").strip() or None


class EvtxModule(ForensicModule):
    @property
    def name(self) -> str:
        return "evtx"

    @property
    def description(self) -> str:
        return "Parse Windows EVTX event logs (optional dependency: python-evtx)."

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

        if file_path.suffix.lower() != ".evtx":
            return {"status": "skipped", "reason": "Not an EVTX file"}

        try:
            import Evtx.Evtx as evtx  # type: ignore
        except Exception:
            return {
                "status": "skipped",
                "reason": "python-evtx not installed (integration not enabled)",
                "how_to_enable": "Install python-evtx in the worker environment (or run docker worker image).",
            }

        try:
            import xml.etree.ElementTree as ET
        except Exception as e:
            return {"status": "failed", "error": f"XML parser unavailable: {e}"}

        max_records = int(kwargs.get("max_records", 5000))
        events: list[dict[str, Any]] = []
        parsed = 0

        try:
            with evtx.Evtx(str(file_path)) as log:
                for record in log.records():
                    if parsed >= max_records:
                        break
                    parsed += 1
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        sys_node = root.find("e:System", EVTX_NS)
                        provider_node = sys_node.find("e:Provider", EVTX_NS) if sys_node is not None else None
                        time_node = sys_node.find("e:TimeCreated", EVTX_NS) if sys_node is not None else None

                        events.append(
                            {
                                "offset": int(record.offset()),
                                "record_id": _text(sys_node, "e:EventRecordID"),
                                "event_id": _text(sys_node, "e:EventID"),
                                "channel": _text(sys_node, "e:Channel"),
                                "provider": provider_node.attrib.get("Name") if provider_node is not None else None,
                                "level": _text(sys_node, "e:Level"),
                                "computer": _text(sys_node, "e:Computer"),
                                "timestamp": time_node.attrib.get("SystemTime") if time_node is not None else None,
                                "xml_excerpt": xml_str[:1000],
                            }
                        )
                    except Exception:
                        continue
        except Exception as e:
            return {"status": "failed", "error": f"EVTX parsing failed: {e}"}

        case_vault = settings.vault_dir / case_id
        artifact_dir = case_vault / "artifacts" / "evtx"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_json = artifact_dir / f"{evidence_id}.json"
        output_csv = artifact_dir / f"{evidence_id}.csv"

        payload = {
            "schema_version": 1,
            "status": "success",
            "evidence_id": evidence_id,
            "max_records": max_records,
            "events_count": len(events),
            "events": events,
        }
        output_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        fieldnames = ["offset", "record_id", "event_id", "timestamp", "channel", "provider", "level", "computer", "xml_excerpt"]
        with output_csv.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for e in events:
                w.writerow({k: e.get(k) for k in fieldnames})

        return {
            "status": "success",
            "events_count": len(events),
            "output_file": str(output_json),
            "output_files": [str(output_json), str(output_csv)],
        }

