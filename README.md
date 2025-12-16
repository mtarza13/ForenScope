# EviForge

EviForge is an **offline-first** digital forensics platform: local-first case management, evidence vaulting, defensible hashing/manifests, and a background worker pipeline.

## Safety / scope

- Authorized investigations only. First run requires acknowledgement: “I confirm I have legal authorization to process this evidence.”
- Defensive workflows only: no exploitation, persistence, stealth, credential theft, bypassing access controls, or remote collection agents.
- Evidence handling is **read-only by default**: ingest copies into a case vault (or can reference a provided path without modifying it).
- No cloud uploads; integrations run locally and only on user-provided evidence.

## Module Capability Matrix

| Module | Category | Inputs | Outputs | Status |
| :--- | :--- | :--- | :--- | :--- |
| **inventory** | artifacts/inventory | Any | JSON, CSV | ✅ Working |
| **strings** | artifacts/strings | Binary/Text | JSON | ✅ Working |
| **timeline** | artifacts/timeline | Filesystem | JSON, CSV | ✅ Working |
| **triage** | artifacts/triage | Any | JSON | ✅ Working |
| **exif** | artifacts/exif | Images/Docs | JSON | ✅ Working |
| **parse_text** | artifacts/parse_text | Docs/PDF/HTML | JSON | ✅ Working (Tika) |
| **yara** | artifacts/yara | Any | JSON | ❌ Missing |
| **pcap** | artifacts/pcap | .pcap/.pcapng | JSON | ❌ Missing |
| **evtx** | artifacts/evtx | .evtx | JSON, CSV | ❌ Missing |
| **registry** | artifacts/registry | Hives | JSON | ❌ Missing |
| **browser** | artifacts/browser | SQLite (History) | JSON | ❌ Missing |
| **email** | artifacts/email | .eml/.mbox | JSON | ❌ Missing |
| **bulk** | artifacts/bulk_extractor | Image/Disk | Dir, JSON | ❌ Missing |
| **carve** | artifacts/carve | Image | Dir, JSON | ❌ Missing |
| **verify** | artifacts/verification | Evidence | JSON | ❌ Missing |
| **report** | artifacts/reports | Case | HTML | ❌ Missing |

## Production Deployment (Step 5)

### 1. Start Platform (Online Mode)
Use the production compose file which includes Caddy (HTTPS) and persistent volumes.
```bash
docker compose -f docker-compose.prod.yml up -d --build
```

### 2. Access & Login
- **Dashboard**: `http://localhost/web`
- **Admin**: `http://localhost/web/admin/login`
- **API**: `http://localhost/api/docs`

**Default Credentials**:
On the *first* login attempt to `/auth/token` (or via the Admin UI), the system will register the "admin" user with whatever password you provide (if no users exist).
*Recommendation*: Use `admin` / `SecurePass123!` for your first login.

### 3. Features
- **Case Management**: Create cases, ingest evidence, run modules.
- **SOC Workflow**: Manage IOCs, view findings, and entity matches.
- **OSINT Hub**: Track "FaceCheck.ID" opt-out requests (Defensive & Privacy-focused).
- **Admin Dashboard**: View system health and registered users.

### Admin Access
To access the Admin Dashboard at `/web/admin`, you must authenticate.
**Method 1: Environment Token (Recommended for automation)**
Set `ADMIN_TOKEN` in your environment (or `.env` file). The server will accept requests with the header `X-Admin-Token: <value_of_ADMIN_TOKEN>`.

**Method 2: Web Login (Recommended for users)**
Navigate to `/web/admin`. If not authenticated, you will be redirected to `/web/login`.
Log in using the credentials established during setup (default: `admin` / `admin`).
*Note: Default credentials should be changed immediately in production.*

### OSINT & Privacy Hub
The **OSINT & Privacy** tab in Case Details allows for tracking defensive removal requests (e.g., FaceCheck.ID opt-outs).
- **FaceCheck Removal**: Track status, notes, and upload proof of removal requests.
- **Privacy Workflow**: Designed for defensive tracking only.

## Development (Local)
1. **Start dependencies**:
   ```bash
   docker compose up -d db redis worker
   ```
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Run API
```bash
eviforge api
```
Then open: http://127.0.0.1:8000/docs

Docker (Phase 1 scaffolding will add compose):

```bash
docker compose -f docker/docker-compose.yml up -d
```

## Quickstart

### 1. Run Platform
```bash
docker compose up -d --build
# Verify status
docker compose ps
# Check health
curl http://127.0.0.1:8000/health
```

### 2. Create a Case
```bash
# Using curl (or via UI at /web)
curl -X POST "http://127.0.0.1:8000/cases" -H "Content-Type: application/json" -d '{"name": "Investigation-001"}'
```

### 3. Ingest Evidence
Place evidence file in `import/` folder (mapped to `/data/import` in container).
```bash
cp /path/to/suspect.dd ./import/
# Ingest (replace CASE_ID from creation step)
curl -X POST "http://127.0.0.1:8000/cases/<CASE_ID>/evidence" -H "Content-Type: application/json" -d '{"filename": "suspect.dd"}'
```

### 4. Run Modules
Ingestion returns an `evidence_id`. Use it to run modules.
```bash
# Run Strings
curl -X POST "http://127.0.0.1:8000/jobs" -H "Content-Type: application/json" -d '{"case_id": "<CASE_ID>", "tool": "strings", "params": {"evidence_id": "<EVIDENCE_ID>"}}'
```

### 5. View Results
Outputs are stored in `cases/<CASE_ID>/artifacts`.
Check job status via API or UI.

## Step 2: Verification (Case Details API & UI)

### 1. Create Case & Ingest
```bash
# Create Case
CASE_ID=$(curl -s -X POST "http://127.0.0.1:8000/cases" -H "Content-Type: application/json" -d '{"name": "Step2-Test"}' | jq -r .id)
echo "Case ID: $CASE_ID"

# Ingest Evidence
echo "sample data" > import/step2_test.txt
curl -s -X POST "http://127.0.0.1:8000/cases/$CASE_ID/evidence" -H "Content-Type: application/json" -d '{"filename": "step2_test.txt"}'
```

### 2. Verify List APIs
```bash
# List Evidence
curl -s "http://127.0.0.1:8000/cases/$CASE_ID/evidence" | jq

# Trigger Job (Step 2 Endpoint)
curl -s -X POST "http://127.0.0.1:8000/cases/$CASE_ID/jobs" -H "Content-Type: application/json" -d '{"module": "triage", "evidence_id": "<EVIDENCE_ID_FROM_ABOVE>"}'

# List Jobs
curl -s "http://127.0.0.1:8000/cases/$CASE_ID/jobs" | jq
```

### 3. UI Check
Open `http://localhost:8000/web/cases/<CASE_ID>` in browser.
- Check "Evidence" tab shows your file.
- Check "Jobs" tab shows the triggered job.

# Internal revision 9

# Internal revision 13

# Internal revision 15

# Internal revision 20

# Internal revision 33

# Internal revision 38

# Internal revision 46

# Internal revision 49

# Internal revision 53

# Internal revision 56

# Internal revision 59

# Internal revision 74

# Internal revision 83

# Internal revision 84

# Internal revision 85

# Internal revision 86

# Rev 18

# Rev 23

# Rev 34

# Rev 38

# Rev 41

# Rev 42
