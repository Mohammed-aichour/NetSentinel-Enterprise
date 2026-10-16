# Multi-stage lightweight Python production image
FROM python:3.13-slim

WORKDIR /app

# Install system utilities for ICMP ping and networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY docs/ ./docs/
COPY scripts/ ./scripts/
COPY app.py .

# Expose Web SOC & API port
EXPOSE 8080

# Health check probe
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Launch NetSentinel server
CMD ["python", "app.py"]
