# Backend Dockerfile for Samurai
FROM python:3.12-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
# - build-essential: for compiling the native C/C++ engines (af_packet, cpu_native, ...)
# - libpcap-dev: for Scapy
# - iproute2: for ip commands
# - curl: utility
# - git: utility
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpcap-dev \
    iproute2 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright dependencies
# We install playwright later via pip, but it needs system libs.
# The 'playwright install-deps' command usually handles this, but requires the python package first.

WORKDIR /app

# Copy requirements first for cache optimization
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers and system dependencies
RUN playwright install --with-deps chromium

# Copy the rest of the application
COPY . .

# Build C extensions in-place
RUN python setup.py build_ext --inplace

# Default to CLI entrypoint for this repository profile.
ENTRYPOINT ["python", "-m", "ddos_samurai.cli"]
CMD ["--help"]
