from __future__ import annotations

import json
from pathlib import Path

import typer
from rich import print

from eviforge.config import ACK_TEXT, load_settings
from eviforge.core.db import create_session_factory, get_setting

app = typer.Typer(add_completion=False, help="EviForge CLI (offline-first forensic platform)")


def _session_factory():
    settings = load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return create_session_factory(settings.database_url)


@app.command("ack")
def ack_cmd(actor: str = "local"):
    """Print the required authorization acknowledgement text."""
    print(ACK_TEXT)
    print("\nSubmit it with: eviforge ack-set --text \"...\"")


@app.command("ack-set")
def ack_set(text: str = typer.Option(..., "--text"), actor: str = "local"):
    """Persist the authorization acknowledgement locally (required before use)."""
    from eviforge.api.routes.auth import ack as ack_api, AckRequest

    ack_api(AckRequest(text=text, actor=actor))
    print("[green]Acknowledgement stored.[/green]")


@app.command("ack-status")
def ack_status():
    """Show whether authorization acknowledgement has been completed."""
    SessionLocal = _session_factory()
    with SessionLocal() as session:
        ack = get_setting(session, "authorization_ack")
    print(json.dumps({"acknowledged": ack is not None, "required_text": ACK_TEXT}, indent=2))


@app.command("api")
def run_api():
    """Run the API server (dev)."""
    import uvicorn

    settings = load_settings()
    uvicorn.run(
        "eviforge.api.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
        log_level="info",
    )


def main():
    app()
