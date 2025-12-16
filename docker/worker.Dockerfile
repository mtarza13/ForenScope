FROM python:3.11-slim

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md SECURITY.md /app/
COPY src /app/src

RUN python -m pip install --upgrade pip && \
    python -m pip install -e ".[postgres]"

CMD ["python", "-m", "eviforge.worker"]
