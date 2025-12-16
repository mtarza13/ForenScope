FROM python:3.11-slim

# Optional tools container (Phase 1 stub)
# Later phases can add exiftool, tshark, volatility3, etc.

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

CMD ["bash", "-lc", "echo 'eviforge-tools (stub): no tools enabled yet.' && sleep infinity"]
