# API Reference

The EviForge API is documented via OpenAPI (Swagger).

## Access
- **Local**: `http://localhost:8000/docs`
- **Prod**: `http://localhost/api/docs`

## Key Endpoints

### Cases
- `GET /cases`
- `POST /cases`

### Evidence
- `GET /cases/{id}/evidence`
- `POST /cases/{id}/evidence` (Ingest)

### Jobs
- `POST /jobs` (Run Module)
- `GET /jobs/{id}` (Status)
