#!/bin/bash
set -e

# Use PORT env var from Railway/HuggingFace, default 7860
APP_PORT=${PORT:-7860}
BACKEND_PORT=8000

export PYTHONUNBUFFERED=1
export PYTHONPATH=${PYTHONPATH:-}:/app
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

# --- ClamAV (background, non-blocking) ---
if command -v freshclam &> /dev/null; then
    (
        echo "Starting ClamAV Daemon in background..."
        freshclam --quiet 2>/dev/null || echo "[ClamAV] freshclam warning (continuing)..."
        if command -v clamd &> /dev/null; then
            clamd 2>/dev/null || echo "[ClamAV] clamd start warning (continuing)..."
        fi
        echo "[ClamAV] Init complete."
    ) &
fi

echo "Booting FastAPI Backend on 127.0.0.1:${BACKEND_PORT}..."
python -m uvicorn api.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --workers 1 --log-level warning &

echo "Booting SmartGuard Streamlit Dashboard on Port ${APP_PORT}..."
exec python -m streamlit run src/dashboard/main_app.py \
  --server.port=${APP_PORT} \
  --server.address=0.0.0.0 \
  --server.headless=true \
  --server.enableCORS=false \
  --server.enableXsrfProtection=false \
  --server.maxUploadSize=50 \
  --browser.gatherUsageStats=false \
  --theme.base=dark
