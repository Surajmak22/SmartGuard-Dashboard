# Base Image
FROM python:3.11-slim-bullseye

# Setup Hugging Face User Configuration
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR $HOME/app

# Install system dependencies (ClamAV for Antivirus scans)
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    libmagic1 \
    file \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV virus signatures (Required for Antivirus Layer)
RUN freshclam

# Configure ClamAV directory permissions for the Hugging Face user
RUN mkdir -p /var/run/clamav && \
    chown -R user:user /var/run/clamav && \
    chown -R user:user /var/log/clamav && \
    chown -R user:user /var/lib/clamav

# Copy requirements and install
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project code
COPY --chown=user . .

# Switch to the non-root user that Hugging Face Spaces requires
USER user

# We need a startup script to boot both ClamAV and the Web apps
RUN echo '#!/bin/bash\n\
echo "Starting ClamAV Daemon in background..."\n\
clamd &\n\
echo "Waiting 10s for ClamAV to initialize signatures in RAM..."\n\
sleep 10\n\
echo "Booting FastAPI Backend..."\n\
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --workers 1 &\n\
echo "Booting SmartGuard Streamlit Dashboard on Port 7860..."\n\
python -m streamlit run src/dashboard/main_app.py --server.port=7860 --server.address=0.0.0.0\n\
' > startup_hf.sh

RUN chmod +x startup_hf.sh

EXPOSE 7860

# Start the application
CMD ["./startup_hf.sh"]
