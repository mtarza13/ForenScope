from __future__ import annotations

import os
import traceback
from typing import Type

from redis import Redis
from rq import Connection, Queue, Worker

from eviforge.config import load_settings
from eviforge.core.db import create_session_factory
from eviforge.core.models import JobStatus
from eviforge.core.jobs import update_job_status
from eviforge.modules.base import ForensicModule

# Registry of available modules
# Format: { "tool_name": ModuleClass }
MODULE_REGISTRY: dict[str, Type[ForensicModule]] = {}

def register_module(module_cls: Type[ForensicModule]) -> None:
    MODULE_REGISTRY[module_cls().name] = module_cls


def execute_module_task(job_id: str, tool_name: str, params: dict, **kwargs) -> dict:
    """
    RQ Task: Execute a forensic module.
    """
    settings = load_settings()
    SessionLocal = create_session_factory(settings.database_url)
    
    print(f"[*] Worker: Starting Job {job_id} ({tool_name})")
    
    with SessionLocal() as session:
        update_job_status(session, job_id, JobStatus.RUNNING)
        
        try:
            if tool_name not in MODULE_REGISTRY:
                raise ValueError(f"Module '{tool_name}' not found. Available: {list(MODULE_REGISTRY.keys())}")
            
            module_cls = MODULE_REGISTRY[tool_name]
            module = module_cls()
            
            # Run the module
            # params might contain 'evidence_id' etc.
            result = module.run(**params)
            
            update_job_status(session, job_id, JobStatus.COMPLETED, result=result)
            print(f"[*] Worker: Job {job_id} COMPLETED")
            return result
            
        except Exception as e:
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            update_job_status(session, job_id, JobStatus.FAILED, error=error_msg)
            print(f"[*] Worker: Job {job_id} FAILED: {e}")
            raise e  # Let RQ know it failed


def main() -> None:
    settings = load_settings()
    redis_url = os.getenv("EVIFORGE_REDIS_URL", settings.redis_url)

    # Pre-load modules here if needed
    # from eviforge.modules.inventory import InventoryModule
    # register_module(InventoryModule)

    conn = Redis.from_url(redis_url)
    with Connection(conn):
        q = Queue("default")
        worker = Worker([q])
        worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
