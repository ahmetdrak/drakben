# DRAKBEN Dockerfile
# Multi-stage build for optimized image size

# ==================== DRAKBEN RUNTIME ====================
FROM kalilinux/kali-rolling:2024.4

LABEL maintainer="DRAKBEN Team"
LABEL description="DRAKBEN - Autonomous Pentest AI Framework"
LABEL version="2.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

WORKDIR /app

# Install Kali tools, Python, and build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    gcc \
    libffi-dev \
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

# Install Python dependencies
# We use --break-system-packages because Kali manages python externally
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code
COPY . .

# Setup User & Directories
RUN mkdir -p /app/logs /app/sessions /app/reports /app/config \
    && useradd -m -s /bin/bash drakben \
    && chown -R drakben:drakben /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from core.agent.state import AgentState; print('OK')" || exit 1

# Switch to non-root user
USER drakben

# Default command
ENTRYPOINT ["python3"]
CMD ["drakben.py"]

# Expose no ports by default (CLI tool)
# EXPOSE 8080
