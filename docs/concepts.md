# Verification & Testing

## Self-Check (Doctor)
Run the built-in doctor to verify tools:
```bash
docker compose exec api python3 -m eviforge.doctor
```

## Unit Tests
Run the test suite:
```bash
docker compose exec worker pytest
```
