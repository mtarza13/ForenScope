import os
import sys
import shutil
import time
import uuid
from pathlib import Path
from redis import Redis
from rq import Queue, Worker

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from eviforge.config import Settings
from eviforge.core.db import create_session_factory, Case
from eviforge.core.models import Evidence, Job
from eviforge.core.ingest import ingest_file
from eviforge.core.custody import log_action
from eviforge.core.jobs import enqueue_job
from eviforge.worker import register_module
from eviforge.modules.inventory import InventoryModule
from eviforge.modules.strings import StringsModule
from eviforge.modules.timeline import TimelineModule

# Register modules manually for the inline worker
register_module(InventoryModule)
register_module(StringsModule)
register_module(TimelineModule)

def main():
    print("="*60)
    print("      E V I F O R G E   D E M O")
    print("="*60)
    
    # 1. Setup Test Environment
    demo_root = Path("demo_env")
    if demo_root.exists():
        shutil.rmtree(demo_root)
    demo_root.mkdir()
    
    import_dir = demo_root / "import"
    import_dir.mkdir()
    
    print(f"[*] Environment initialized at {demo_root}")
    
    # Set env vars for the worker (which calls load_settings())
    os.environ["EVIFORGE_DATA_DIR"] = str(demo_root.resolve() / "data")
    os.environ["EVIFORGE_VAULT_DIR"] = str(demo_root.resolve() / "vault")
    os.environ["EVIFORGE_DATABASE_URL"] = f"sqlite:///{(demo_root.resolve() / 'demo.db').as_posix()}"
    os.environ["EVIFORGE_REDIS_URL"] = "redis://localhost:6380/0"
    
    settings = Settings(
        data_dir=demo_root.resolve() / "data",
        vault_dir=demo_root.resolve() / "vault",
        database_url=f"sqlite:///{(demo_root.resolve() / 'demo.db').as_posix()}",
        redis_url="redis://localhost:6380/0", 
        bind_host="127.0.0.1",
        bind_port=8000
    )
    
    # Init DB
    SessionLocal = create_session_factory(settings.database_url)
    
    # 2. Create Case
    with SessionLocal() as session:
        case = Case(name="DEMO-CASE-2025-001")
        session.add(case)
        session.flush()
        
        # Vault Init
        case_vault = settings.vault_dir / case.id
        (case_vault / "evidence").mkdir(parents=True, exist_ok=True)
        log_action(session, case.id, "system", "Case Created")
        session.commit()
        print(f"[*] Case Created: {case.name} ({case.id})")
        case_id = case.id

    # 3. Create Synthetic Evidence
    ev_file = import_dir / "malware_sample.bin"
    # Create a file with some printable strings and random bytes
    content = b"\x89PNG\r\n\x1a\n" + b"\x00"*20 + b"password=secret" + b"\x00"*10 + b"https://evil.com/c2"
    ev_file.write_bytes(content)
    
    print(f"[*] Created synthetic evidence: {ev_file.name}")
    
    # 4. Ingest
    with SessionLocal() as session:
        evidence = ingest_file(session, settings, case_id, ev_file)
        session.commit()
        evidence_id = evidence.id
        print(f"[*] Ingested Evidence: UUID={evidence_id}")
        print(f"    MD5: {evidence.md5}")

    # 5. Queue Jobs
    print(f"[*] Enqueueing modules...")
    with SessionLocal() as session:
        j1 = enqueue_job(session, settings, case_id, "inventory", {"evidence_id": evidence_id})
        j2 = enqueue_job(session, settings, case_id, "strings", {"evidence_id": evidence_id, "min_length": 4})
        j3 = enqueue_job(session, settings, case_id, "timeline", {"evidence_id": evidence_id})
        
        session.commit()
        job_ids = [j1.id, j2.id, j3.id]

    # 6. Run Worker (Burst Mode)
    print("amp;[*] Processing jobs (Burst Mode)...")
    conn = Redis.from_url(settings.redis_url)
    q = Queue("default", connection=conn)
    w = Worker([q], connection=conn)
    w.work(burst=True)

    # 7. Review Results
    print("\n" + "="*20 + " R E S U L T S " + "="*20)
    with SessionLocal() as session:
        for jid in job_ids:
            job = session.get(Job, jid)
            print(f"\n[JOB] {job.tool_name} ({job.status.value})")
            print(f"result: {job.result_json}")
            if job.error_message:
                print(f"ERROR: {job.error_message}")
                
    print("\n" + "="*60)
    print("Demo Complete.")

if __name__ == "__main__":
    main()
