# Backend Dockerfile for K9 Sentinel AI (FastAPI + uv)
FROM python:3.12-slim-bookworm AS base

# Install system dependencies (libzbar for QR decoding, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv for ultra-fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy dependency specifications
COPY pyproject.toml .

# Install dependencies using uv into system environment
RUN uv pip install --system -r pyproject.toml

# Copy backend source code
COPY . .

# Expose FastAPI default port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1

# Healthcheck to ensure FastAPI is responsive
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
