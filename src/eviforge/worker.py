from __future__ import annotations

import json
import os
import signal
import traceback
from contextlib import redirect_stderr, redirect_stdout
from datetime import timezone
from io import StringIO
from pathlib import Path
from typing import Any, Type

from redis import Redis
from rq import Queue, Worker

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory, utcnow
from eviforge.core.models import Job, JobStatus
from eviforge.core.sanitize import sanitize_text
from eviforge.modules.base import ForensicModule


MODULE_REGISTRY: dict[str, Type[ForensicModule]] = {}


def register_module(module_cls: Type[ForensicModule]) -> None:
    MODULE_REGISTRY[module_cls().name] = module_cls


def ensure_modules_registered() -> None:
    if MODULE_REGISTRY:
        return

    from eviforge.modules.inventory import InventoryModule
    from eviforge.modules.strings import StringsModule
    from eviforge.modules.timeline import TimelineModule
    from eviforge.modules.parse_text import ParseTextModule
    from eviforge.modules.exif import ExifModule
    from eviforge.modules.triage import TriageModule
    from eviforge.modules.yara import YaraModule
    from eviforge.modules.pcap import PcapModule
    from eviforge.modules.evtx import EvtxModule
    from eviforge.modules.registry import RegistryModule
    from eviforge.modules.browser import BrowserModule
    from eviforge.modules.email import EmailModule
    from eviforge.modules.bulk import BulkExtractorModule
    from eviforge.modules.carve import CarveModule
    from eviforge.modules.verification import VerifyModule
    from eviforge.modules.reports import ReportModule

    register_module(InventoryModule)
    register_module(StringsModule)
    register_module(TimelineModule)
    register_module(ParseTextModule)
    register_module(ExifModule)
    register_module(TriageModule)
    register_module(YaraModule)
    register_module(PcapModule)
    register_module(EvtxModule)
    register_module(RegistryModule)
    register_module(BrowserModule)
    register_module(EmailModule)
    register_module(BulkExtractorModule)
    register_module(CarveModule)
    register_module(VerifyModule)
    register_module(ReportModule)


class _Timeout(Exception):
    pass


def _with_alarm(timeout_seconds: int):
    def handler(_signum, _frame):
        raise _Timeout(f"Job timed out after {timeout_seconds}s")

    old = signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout_seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _extract_output_files(result: dict[str, Any], *, artifacts_root: Path) -> list[str]:
    out: list[str] = []
    output_file = result.get("output_file")
    if isinstance(output_file, str):
        try:
            p = Path(output_file).resolve()
            rel = p.relative_to(artifacts_root.resolve())
            out.append(rel.as_posix())
        except Exception:
            pass
    output_files = result.get("output_files")
    if isinstance(output_files, list):
        for item in output_files:
            if isinstance(item, str):
                try:
                    p = Path(item).resolve()
                    rel = p.relative_to(artifacts_root.resolve())
                    out.append(rel.as_posix())
                except Exception:
                    continue
    # de-dupe while preserving order
    seen = set()
    uniq: list[str] = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


def _result_preview(result: dict[str, Any]) -> dict[str, Any]:
    # Keep small, stable fields; avoid dumping huge arrays.
    preview: dict[str, Any] = {}
    for key in ("status", "error", "file_count", "count", "event_count", "parsed_objects", "tags_found", "entropy", "mime_magic", "mime_guessed", "is_suspicious", "limit_reached"):
        if key in result:
            preview[key] = result.get(key)
    if "output_file" in result:
        preview["output_file"] = result.get("output_file")
    return preview


def execute_module_task(job_id: str) -> dict[str, Any]:
    """RQ Task: execute a queued Job by id."""
    ensure_modules_registered()
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)

    timeout_seconds = int(os.getenv("EVIFORGE_JOB_TIMEOUT_SECONDS", "900"))

    with SessionLocal() as session:
        job = session.get(Job, job_id)
        if not job:
            raise ValueError(f"Job with ID {job_id} not found")

        job.status = JobStatus.RUNNING
        job.started_at = utcnow()
        session.add(job)
        session.commit()

        params = {}
        if job.params_json:
            try:
                params = json.loads(job.params_json)
            except Exception:
                params = {}

        tool_name = job.tool_name
        if tool_name not in MODULE_REGISTRY:
            job.status = JobStatus.FAILED
            job.error_message = f"Unknown module: {tool_name}"
            job.completed_at = utcnow()
            session.add(job)
            session.commit()
            raise ValueError(job.error_message)

        mod = MODULE_REGISTRY[tool_name]()
        evidence_id = job.evidence_id or params.get("evidence_id")
        if mod.requires_evidence and not evidence_id:
            job.status = JobStatus.FAILED
            job.error_message = "Missing evidence_id"
            job.completed_at = utcnow()
            session.add(job)
            session.commit()
            raise ValueError(job.error_message)

        module_kwargs = dict(params or {})
        module_kwargs.pop("case_id", None)
        module_kwargs.pop("evidence_id", None)
        stdout_buf = StringIO()
        stderr_buf = StringIO()

        try:
            # Best-effort resource limits (Linux)
            try:
                import resource

                cpu_limit = int(os.getenv("EVIFORGE_JOB_CPU_SECONDS", str(timeout_seconds + 5)))
                mem_mb = int(os.getenv("EVIFORGE_JOB_MAX_MB", "1024"))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
                resource.setrlimit(resource.RLIMIT_AS, (mem_mb * 1024 * 1024, mem_mb * 1024 * 1024))
            except Exception:
                pass

            from contextlib import contextmanager

            @contextmanager
            def alarm_ctx():
                def handler(_signum, _frame):
                    raise _Timeout(f"Job timed out after {timeout_seconds}s")

                old = signal.signal(signal.SIGALRM, handler)
                signal.alarm(timeout_seconds)
                try:
                    yield
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old)

            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf), alarm_ctx():
                result = mod.run(job.case_id, evidence_id, **module_kwargs)
                if not isinstance(result, dict):
                    raise ValueError("Module returned non-dict result")

            artifacts_root = (settings.vault_dir / job.case_id / "artifacts")
            output_files = _extract_output_files(result, artifacts_root=artifacts_root)
            preview = _result_preview(result)

            job.stdout_text = sanitize_text(stdout_buf.getvalue())
            job.stderr_text = sanitize_text(stderr_buf.getvalue())
            job.output_files_json = json.dumps(output_files, sort_keys=False)
            job.result_preview_json = json.dumps(preview, sort_keys=True)
            job.result_json = json.dumps(result, sort_keys=True)
            job.status = JobStatus.COMPLETED
            job.completed_at = utcnow()
            session.add(job)
            session.commit()
            # Chain-of-custody (file log): best effort
            try:
                from eviforge.core.custody import append_entry

                actor = str((params or {}).get("actor") or "worker")
                append_entry(
                    settings.vault_dir / job.case_id / "chain_of_custody.log",
                    actor=actor,
                    action="job.complete",
                    details={
                        "job_id": job.id,
                        "module": tool_name,
                        "evidence_id": evidence_id,
                        "status": "COMPLETED",
                        "output_files": output_files,
                    },
                )
            except Exception:
                pass
            return {"job_id": job.id, "status": job.status, "output_files": output_files, "preview": preview}

        except Exception as e:
            err = sanitize_text(f"{e}\n{traceback.format_exc()}")
            job.stdout_text = sanitize_text(stdout_buf.getvalue())
            job.stderr_text = sanitize_text(stderr_buf.getvalue())
            job.error_message = err
            job.status = JobStatus.FAILED
            job.completed_at = utcnow()
            session.add(job)
            session.commit()
            try:
                from eviforge.core.custody import append_entry

                actor = str((params or {}).get("actor") or "worker")
                append_entry(
                    settings.vault_dir / job.case_id / "chain_of_custody.log",
                    actor=actor,
                    action="job.failed",
                    details={
                        "job_id": job.id,
                        "module": tool_name,
                        "evidence_id": evidence_id,
                        "status": "FAILED",
                        "error": str(e),
                    },
                )
            except Exception:
                pass
            raise


def main() -> None:
    settings = load_settings()
    redis_url = os.getenv("EVIFORGE_REDIS_URL", settings.redis_url)

    ensure_modules_registered()
    conn = Redis.from_url(redis_url)
    q = Queue("default", connection=conn)
    worker = Worker([q], connection=conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()

# Rev 3

# Rev 9

# Rev 13

# Rev 14

# Rev 16

# Rev 26

# Rev 28

# Rev 29

# Rev 31

# Rev 52

# Rev 54

# Rev 59

# Rev 64

# Rev 70

# Rev 84

# Rev 86

# Rev 90
