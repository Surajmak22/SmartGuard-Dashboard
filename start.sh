#!/bin/bash
set -e

# --- PERFORMANCE CONFIGURATION ---
export MALLOC_ARENA_MAX=2
export PYTHONUNBUFFERED=1
export PYTHONPATH=${PYTHONPATH:-}:/app

# Railway / Render / HF all inject PORT; default to 7860 for local dev
APP_PORT=${PORT:-7860}
BACKEND_PORT=8000

# Internal backend URL for Streamlit -> FastAPI calls
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

echo "==========================================="
echo "  SmartGuard AI — Production Boot Sequence"
echo "==========================================="
echo "  APP_PORT     = ${APP_PORT} (Railway \$PORT)"
echo "  BACKEND_PORT = ${BACKEND_PORT}"
echo "  BACKEND_URL  = ${BACKEND_API_URL}"
echo "==========================================="

# --- OPTIONAL: ClamAV (if installed) ---
if command -v freshclam &> /dev/null; then
    echo "Starting ClamAV Daemon in background..."
    (
        freshclam --quiet 2>/dev/null || echo "[ClamAV] freshclam warning (continuing)..."
        if command -v clamd &> /dev/null; then
            clamd 2>/dev/null || echo "[ClamAV] clamd start warning (continuing)..."
        fi
        echo "[ClamAV] Init complete."
    ) &
    echo "Waiting 5s for ClamAV to initialize signatures in RAM..."
    sleep 5
else
    echo "ClamAV not installed — skipping (heuristic + ML layers active)."
fi

# --- BACKEND STARTUP ---
echo "Booting FastAPI Backend on 127.0.0.1:${BACKEND_PORT}..."
python3 -m uvicorn api.main:app \
    --host 127.0.0.1 \
    --port ${BACKEND_PORT} \
    --workers 1 \
    --log-level warning &
BACKEND_PID=$!

# Give the backend a moment to bind
sleep 2

# --- FRONTEND STARTUP (must bind to 0.0.0.0:$APP_PORT for Railway) ---
echo "Booting Streamlit Dashboard on 0.0.0.0:${APP_PORT}..."
exec python3 -m streamlit run src/dashboard/main_app.py \
    --server.port=${APP_PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --server.enableXsrfProtection=false \
    --server.enableWebsocketCompression=false \
    --server.maxUploadSize=50 \
    --browser.gatherUsageStats=false \
    --theme.base=dark
