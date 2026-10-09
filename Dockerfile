# ==============================================================================
# Mobile Security Agent (MSA v2.0) - Production Container
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files to disc and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal OS dependencies for decompression and tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application source code
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY LICENSE /app/
COPY README.md /app/

# Create runtime artifact directories
RUN mkdir -p /app/uploads /app/reports /app/logs

# Expose FastAPI port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Launch FastAPI ASGI server
WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
