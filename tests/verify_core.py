import sys
import shutil
import hashlib
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from eviforge.core.db import create_session_factory, Case
from eviforge.core.models import ChainOfCustody, Evidence
from eviforge.core.ingest import ingest_file
from eviforge.config import Settings
from eviforge.core.custody import log_action

def test_core_flow():
    # Setup test env
    test_root = Path("test_env")
    if test_root.exists():
        shutil.rmtree(test_root)
    test_root.mkdir()
    
    settings = Settings(
        data_dir=test_root / "data",
        vault_dir=test_root / "vault",
        database_url=f"sqlite:///{(test_root / 'test.db').as_posix()}",
        redis_url="redis://localhost:6379/0",
        bind_host="127.0.0.1",
        bind_port=8000
    )
    settings.vault_dir.mkdir()
    
    # Init DB
    SessionLocal = create_session_factory(settings.database_url)
    
    with SessionLocal() as session:
        print("[*] Creating Case...")
        case = Case(name="Test Case 001")
        session.add(case)
        session.flush()
        
        # Init vault (mimic logic in cases.py)
        case_vault = settings.vault_dir / case.id
        (case_vault / "evidence").mkdir(parents=True, exist_ok=True)
        
        log_action(session, case.id, "system", "Case Created")
        
        # Create dummy evidence
        import_dir = test_root / "import"
        import_dir.mkdir()
        evidence_file = import_dir / "suspect.txt"
        evidence_file.write_text("Secret evidence content")
        
        print("[*] Ingesting Evidence...")
        evidence = ingest_file(session, settings, case.id, evidence_file)
        session.commit()
        
        print(f"    Ingested: {evidence.id}")
        print(f"    MD5: {evidence.md5}")
        
        # Verification
        print("[*] Verifying Storage...")
        stored_path = settings.vault_dir / evidence.path
        if not stored_path.exists():
            print("FAIL: Stored file missing")
            sys.exit(1)
        if stored_path.read_text() != "Secret evidence content":
            print("FAIL: Content mismatch")
            sys.exit(1)
            
        print("[*] Verifying Chain of Custody...")
        logs = session.query(ChainOfCustody).filter_by(case_id=case.id).order_by(ChainOfCustody.timestamp).all()
        for log in logs:
            print(f"    [{log.timestamp}] {log.action}: {log.details} (Hash: {log.curr_hash[:8]}...)")
            
        if len(logs) != 2: # Created + Ingested
            print(f"FAIL: Expected 2 logs, got {len(logs)}")
            sys.exit(1)
            
        # Verify hash chain
        if logs[1].prev_hash != logs[0].curr_hash:
             print("FAIL: Hash chain broken")
             sys.exit(1)
             
        print("SUCCESS: Core flow verified")

if __name__ == "__main__":
    test_core_flow()
