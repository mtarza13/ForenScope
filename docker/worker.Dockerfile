FROM python:3.11-slim

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md SECURITY.md /app/
COPY src /app/src

RUN python -m pip install --upgrade pip && \
    python -m pip install -e ".[postgres]"

# Install system dependencies (exiftool, file/libmagic, yara, tshark, etc)
RUN apt-get update && apt-get install -y \
    binutils \
    exiftool \
    file \
    libmagic1 \
    yara \
    tshark \
    foremost \
    && rm -rf /var/lib/apt/lists/*

CMD ["python", "-m", "eviforge.worker"]
