# EviForge

EviForge is an **offline-first** digital forensics platform: local-first case management, evidence vaulting, defensible hashing/manifests, and a background worker pipeline.

## Safety / scope

- Authorized investigations only. First run requires acknowledgement: “I confirm I have legal authorization to process this evidence.”
- Defensive workflows only: no exploitation, persistence, stealth, credential theft, bypassing access controls, or remote collection agents.
- Evidence handling is **read-only by default**: ingest copies into a case vault (or can reference a provided path without modifying it).
- No cloud uploads; integrations run locally and only on user-provided evidence.

## Install (editable, dev)

```bash
python -m pip install -e .
```

## Run (Phase 1)

API (SQLite default):

```bash
eviforge api
```

Then open: http://127.0.0.1:8000/docs

Docker (Phase 1 scaffolding will add compose):

```bash
docker compose -f docker/docker-compose.yml up -d
```

## Quick start

```bash
dfir init MyCase --root ./cases --investigator "Analyst" --org "Org"
dfir list --root ./cases
dfir show ./cases/MyCase
```
