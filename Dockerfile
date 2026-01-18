FROM python:3.13-slim

# Metadata
LABEL maintainer="DRAKBEN Team"
LABEL description="DRAKBEN v5.0 - AI-Powered Penetration Testing Framework with 2024-2025 Modern Evasion"
LABEL version="5.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    netcat-traditional \
    curl \
    wget \
    git \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs config/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DRAKBEN_HOME=/app

# Expose ports (if needed for reverse shells)
EXPOSE 4444 8080

# Create non-root user for security
RUN useradd -m -u 1000 drakben && \
    chown -R drakben:drakben /app

# Switch to non-root user
USER drakben

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
ENTRYPOINT ["python3"]
CMD ["drakben.py"]
