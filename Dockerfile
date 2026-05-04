# Base Image
FROM python:3.11-slim-bullseye

# Setup user for non-root execution (Railway / HuggingFace compatible)
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies (ClamAV for Antivirus scans)
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    libmagic1 \
    file \
    && rm -rf /var/lib/apt/lists/*

# Configure ClamAV directory permissions for the non-root user
RUN mkdir -p /var/run/clamav && \
    chown -R user:user /var/run/clamav && \
    chown -R user:user /var/log/clamav && \
    chown -R user:user /var/lib/clamav

# Copy requirements and install
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project code
COPY --chown=user . .

# Make startup scripts executable
RUN chmod +x start.sh startup_hf.sh

USER user

# NOTE: Do NOT set ENV PORT here — Railway injects its own PORT at runtime.
# The start.sh script uses ${PORT:-7860} to handle both Railway and local dev.

EXPOSE 7860

# Use the unified startup script
CMD ["./start.sh"]
