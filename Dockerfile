# Dockerfile
FROM python:3.12-slim

LABEL maintainer="security-team"
LABEL description="Production-ready PHP Security Scanner"
LABEL version="2.1.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/cache_data /app/reports /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:///./scanner.db

# Initialize database
RUN python -m db.cli init

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Default command: run API server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
