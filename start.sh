#!/bin/bash

# --- CONFIGURATION ---
STREAMLIT_PORT=${PORT:-8501}
BACKEND_PORT=8000

# Explicitly set PYTHONPATH to current directory
export PYTHONPATH=$PYTHONPATH:/app
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

echo "🛡️ SMARTGUARD AI - BOOT SEQUENCE INITIATED"
echo "🔧 ENV: PORT=$PORT, STREAMLIT_PORT=$STREAMLIT_PORT, BACKEND_PORT=$BACKEND_PORT"

# --- BACKEND STARTUP ---
echo "🚀 Starting FastAPI Backend on 127.0.0.1:${BACKEND_PORT}..."
# Use python3 -m uvicorn for reliability
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --log-level info &
BACKEND_PID=$!

# --- HEALTH CHECK (BACKGROUND) ---
(
  echo "⏳ Monitoring Backend Health..."
  max_retries=30
  count=0
  while ! curl -s ${BACKEND_API_URL}/health > /dev/null; do
      count=$((count+1))
      if [ $count -ge $max_retries ]; then
          echo "❌ ERROR: Backend failed to respond at ${BACKEND_API_URL} after ${max_retries} attempts."
          kill $BACKEND_PID
          exit 1
      fi
      sleep 2
  done
  echo "✅ SUCCESS: Backend is active and initialized."
) &

# --- FRONTEND STARTUP ---
echo "📊 Starting Streamlit Dashboard on 0.0.0.0:${STREAMLIT_PORT}..."
# Headless production flags are critical for cloud environments
# --server.address 0.0.0.0 is required for external access via Railway/Vercel
# --server.headless true prevents Streamlit from trying to open a browser window
# --server.enableCORS false and --server.enableXsrfProtection false avoid proxy issues
python3 -m streamlit run src/dashboard/main_app.py \
    --server.port ${STREAMLIT_PORT} \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false \
    --browser.gatherUsageStats false \
    --theme.base dark
