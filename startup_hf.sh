#!/bin/bash
set -e

# Run ClamAV init in the BACKGROUND so port 7860 opens immediately.
# HuggingFace marks the Space as "Starting" until port 7860 responds.
# The app's clam_wrapper.py has graceful fallback, so AV works once clamd is ready.
(
  echo "[ClamAV] Downloading virus signatures..."
  freshclam --quiet 2>/dev/null || echo "[ClamAV] freshclam warning (continuing)..."
  echo "[ClamAV] Starting clamd daemon..."
  clamd
  echo "[ClamAV] clamd is ready."
) &

echo "Booting FastAPI Backend..."
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --workers 1 &

echo "Booting SmartGuard Streamlit Dashboard on Port 7860..."
exec python -m streamlit run src/dashboard/main_app.py \
  --server.port=7860 \
  --server.address=0.0.0.0 \
  --server.enableCORS=false \
  --server.enableXsrfProtection=false
