# DRAKBEN Dockerfile
# Multi-stage build for optimized image size

# ==================== BUILD STAGE ====================
# ==================== BUILD STAGE ====================
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ==================== RUNTIME STAGE ====================
FROM kalilinux/kali-rolling:latest

LABEL maintainer="DRAKBEN Team"
LABEL description="DRAKBEN - Autonomous Pentest AI Framework"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV TERM=xterm-256color

WORKDIR /app

# Install Kali tools and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    # Network tools
    nmap \
    netcat-openbsd \
    dnsutils \
    whois \
    curl \
    wget \
    # Web scanning
    nikto \
    gobuster \
    dirb \
    # Exploitation
    sqlmap \
    hydra \
    # Additional tools
    nuclei \
    subfinder \
    amass \
    # Utilities
    git \
    vim \
    less \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local/lib/python3.11/site-packages /usr/local/lib/python3.11/dist-packages

# Copy application code
COPY . .

# Setup User & Directories
RUN mkdir -p /app/logs /app/sessions /app/reports /app/config \
    # Create non-root user
    && useradd -m -s /bin/bash drakben \
    && chown -R drakben:drakben /app

# Switch to non-root user (optional, comment out for full Kali access)
# USER drakben

# Switch to non-root user (optional, comment out for full Kali access)
# USER drakben

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from core.state import AgentState; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python3"]
CMD ["drakben.py"]

# Expose no ports by default (CLI tool)
# EXPOSE 8080
