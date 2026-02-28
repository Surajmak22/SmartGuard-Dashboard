#!/bin/bash

# --- PERFORMANCE CONFIGURATION ---
# Optimize memory for 512MB containers
export MALLOC_ARENA_MAX=2
export PYTHONUNBUFFERED=1
export PYTHONPATH=$PYTHONPATH:/app

# Railway provides PORT, default to 8501 for local dev
STREAMLIT_PORT=${PORT:-8501}
BACKEND_PORT=8000

# Force backend URL to be local 127.0.0.1 for internal calls
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

echo "🛡️ SMARTGUARD AI - ACCELERATED BOOT SEQUENCE"
echo "🔧 ENV: PORT=$PORT, STREAMLIT_PORT=$STREAMLIT_PORT, BACKEND_PORT=$BACKEND_PORT"

# --- BACKEND STARTUP (INSTANT) ---
echo "🚀 Starting FastAPI Backend (Lazy Mode) on 127.0.0.1:${BACKEND_PORT}..."
# Using --workers 1 to keep memory usage low
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --workers 1 --log-level warning &
BACKEND_PID=$!

# --- FRONTEND STARTUP (PRIORITY BIND) ---
echo "📊 Binding Streamlit Dashboard to 0.0.0.0:${STREAMLIT_PORT}..."
# Optimized for immediate port binding to pass Railway health checks
python3 -m streamlit run src/dashboard/main_app.py \
    --server.port ${STREAMLIT_PORT} \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false \
    --server.webSocketCompression false \
    --server.maxUploadSize 50 \
    --browser.gatherUsageStats false \
    --theme.base dark
