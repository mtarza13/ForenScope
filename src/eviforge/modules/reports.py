from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

from jinja2 import Template

from eviforge.config import ACK_TEXT, load_settings
from eviforge.core.custody import verify_chain
from eviforge.core.db import create_session_factory, get_setting
from eviforge.core.models import Case, Evidence, Job
from eviforge.modules.base import ForensicModule


REPORT_TEMPLATE = Template(
    """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>EviForge Report - {{ case.name }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; color: #111; }
    h1, h2, h3 { margin: 0.2rem 0; }
    .muted { color: #666; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    table { border-collapse: collapse; width: 100%; margin-top: 0.75rem; }
    th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; }
    .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.5rem; font-size: 0.85rem; }
    .ok { background: #e6ffed; border: 1px solid #b7f5c8; }
    .bad { background: #ffe6e6; border: 1px solid #f5b7b7; }
  </style>
</head>
<body>
  <h1>EviForge Case Report</h1>
  <div class="muted">Generated at: {{ generated_at }} (UTC)</div>

  <h2 style="margin-top:1.5rem;">Case</h2>
  <table>
    <tr><th>Case Name</th><td>{{ case.name }}</td></tr>
    <tr><th>Case ID</th><td class="mono">{{ case.id }}</td></tr>
    <tr><th>Created</th><td>{{ case.created_at }}</td></tr>
  </table>

  <h2 style="margin-top:1.5rem;">Authorization</h2>
  <table>
    <tr><th>Required Acknowledgement</th><td>{{ ack_required }}</td></tr>
    <tr><th>Acknowledged</th><td>{{ "Yes" if ack.acknowledged else "No" }}</td></tr>
    <tr><th>Actor</th><td>{{ ack.actor or "" }}</td></tr>
    <tr><th>Timestamp</th><td>{{ ack.ts or "" }}</td></tr>
  </table>

  <h2 style="margin-top:1.5rem;">Evidence</h2>
  <table>
    <thead>
      <tr>
        <th>Evidence ID</th>
        <th>Filename</th>
        <th>Size (bytes)</th>
        <th>Ingested</th>
        <th>SHA-256</th>
        <th>MD5</th>
      </tr>
    </thead>
    <tbody>
      {% for ev in evidence %}
      <tr>
        <td class="mono">{{ ev.id }}</td>
        <td>{{ ev.filename }}</td>
        <td>{{ ev.size_bytes }}</td>
        <td>{{ ev.ingested_at }}</td>
        <td class="mono">{{ ev.sha256 or "" }}</td>
        <td class="mono">{{ ev.md5 or "" }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2 style="margin-top:1.5rem;">Chain of Custody (File Log)</h2>
  <div>
    {% if custody_ok %}
      <span class="badge ok">Verified</span>
    {% else %}
      <span class="badge bad">Failed</span>
    {% endif %}
    <span class="muted">{{ custody_reason }}</span>
  </div>

  <h2 style="margin-top:1.5rem;">Jobs</h2>
  <table>
    <thead>
      <tr><th>Job ID</th><th>Module</th><th>Status</th><th>Created</th><th>Outputs</th><th>Error</th></tr>
    </thead>
    <tbody>
      {% for j in jobs %}
      <tr>
        <td class="mono">{{ j.id }}</td>
        <td>{{ j.tool }}</td>
        <td>{{ j.status }}</td>
        <td>{{ j.created_at }}</td>
        <td class="mono">
          {% for p in j.output_files %}
            {{ p }}<br/>
          {% endfor %}
        </td>
        <td class="mono">{{ j.error or "" }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2 style="margin-top:1.5rem;">Methodology / Limitations</h2>
  <ul>
    <li>Offline-first: evidence is processed locally; no uploads are performed.</li>
    <li>Evidence is never modified at the original source; analysis runs on copied vault data.</li>
    <li>Optional integrations (tshark, exiftool, bulk_extractor, etc.) may be feature-gated based on availability.</li>
    <li>This report is generated from EviForge job outputs and metadata as of the generation time above.</li>
  </ul>
</body>
</html>
"""
)


@dataclass(frozen=True)
class AckInfo:
    acknowledged: bool
    actor: str | None = None
    ts: str | None = None


class ReportModule(ForensicModule):
    @property
    def name(self) -> str:
        return "report"

    @property
    def description(self) -> str:
        return "Generate a case report (HTML)."

    @property
    def requires_evidence(self) -> bool:
        return False

    def run(self, case_id: str, evidence_id: str | None = None, **kwargs) -> Dict[str, Any]:
        settings = load_settings()
        SessionLocal = create_session_factory(settings.database_url)

        with SessionLocal() as session:
            case = session.get(Case, case_id)
            if not case:
                raise ValueError(f"Case {case_id} not found")

            evidence_rows = session.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.ingested_at.desc()).all()
            jobs_rows = session.query(Job).filter(Job.case_id == case_id).order_by(Job.created_at.desc()).all()
            ack = get_setting(session, "authorization_ack") or None

        ack_info = AckInfo(
            acknowledged=bool(ack),
            actor=(ack or {}).get("actor"),
            ts=(ack or {}).get("ts"),
        )

        evidence = [
            {
                "id": ev.id,
                "filename": Path(ev.path).name,
                "size_bytes": int(ev.size_bytes or 0),
                "ingested_at": ev.ingested_at.isoformat() if ev.ingested_at else "",
                "sha256": ev.sha256,
                "md5": ev.md5,
            }
            for ev in evidence_rows
        ]

        jobs = []
        for j in jobs_rows:
            output_files = []
            if j.output_files_json:
                try:
                    output_files = json.loads(j.output_files_json) or []
                except Exception:
                    output_files = []
            jobs.append(
                {
                    "id": j.id,
                    "tool": j.tool_name,
                    "status": j.status.value if hasattr(j.status, "value") else str(j.status),
                    "created_at": j.created_at.isoformat() if j.created_at else "",
                    "output_files": output_files,
                    "error": j.error_message,
                }
            )

        case_vault = settings.vault_dir / case_id
        custody_log = case_vault / "chain_of_custody.log"
        custody_ok, custody_reason = verify_chain(custody_log)

        html = REPORT_TEMPLATE.render(
            case={"id": case.id, "name": case.name, "created_at": case.created_at.isoformat() if case.created_at else ""},
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            ack_required=ACK_TEXT,
            ack=asdict(ack_info),
            evidence=evidence,
            jobs=jobs,
            custody_ok=custody_ok,
            custody_reason=custody_reason,
        )

        artifact_dir = case_vault / "artifacts" / "reports"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_file = artifact_dir / f"report_{int(time.time())}.html"
        output_file.write_text(html, encoding="utf-8")

        return {"status": "success", "output_file": str(output_file)}

