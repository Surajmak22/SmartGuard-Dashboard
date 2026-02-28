#!/bin/bash

# --- CONFIGURATION ---
# Railway provides PORT, default to 8501 for local dev
STREAMLIT_PORT=${PORT:-8501}
BACKEND_PORT=8000

# Explicitly set PYTHONPATH to current directory
export PYTHONPATH=$PYTHONPATH:/app
# Force backend URL to be local 127.0.0.1 for internal calls
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

echo "🛡️ SMARTGUARD AI - ENTERPRISE BOOT SEQUENCE"
echo "🔧 ENV: PORT=$PORT, STREAMLIT_PORT=$STREAMLIT_PORT, BACKEND_PORT=$BACKEND_PORT"

# --- BACKEND STARTUP ---
echo "🚀 Starting FastAPI Backend (Internal) on 127.0.0.1:${BACKEND_PORT}..."
# Use python3 -m uvicorn for reliability
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --log-level info &
BACKEND_PID=$!

# --- FRONTEND STARTUP ---
echo "📊 Starting Streamlit Dashboard on 0.0.0.0:${STREAMLIT_PORT}..."
# Optimized for Cloud Proxies (Railway/Vercel)
# --server.webSocketCompression false helps high-latency mobile connections
# --server.maxUploadSize 50 ensures enough headroom for scan payloads
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
