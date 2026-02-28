#!/bin/bash

# Configuration
# Default to 8501 if PORT isn't set (local dev)
STREAMLIT_PORT=${PORT:-8501}
# Backend runs on a fixed internal port
BACKEND_PORT=8000

# Explicitly set PYTHONPATH to current directory
export PYTHONPATH=$PYTHONPATH:.
export BACKEND_API_URL="http://127.0.0.1:${BACKEND_PORT}"

echo "🔧 Environment Check:"
python3 --version

# Start FastAPI Backend in background
echo "🚀 Starting FastAPI Backend on port ${BACKEND_PORT}..."
# Use 127.0.0.1 for internal backend to avoid potential dual-stack resolution issues
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --log-level info &

# Wait for backend to be ready in background (non-blocking)
(
  echo "⏳ Background: Waiting for backend to warm up at ${BACKEND_API_URL}..."
  max_retries=20
  count=0
  while ! curl -s ${BACKEND_API_URL}/health > /dev/null; do
      count=$((count+1))
      if [ $count -ge $max_retries ]; then
          echo "❌ Backend failed to start after $max_retries attempts"
          exit 1
      fi
      sleep 2
  done
  echo "✅ Backend is UP and initialized via startup_event."
) &

# Start Streamlit Dashboard in foreground - THIS binds to Railway's $PORT
echo "📊 Starting Streamlit Dashboard on port ${STREAMLIT_PORT}..."
# Added production flags: headless, enableCORS=false
streamlit run src/dashboard/main_app.py \
    --server.port ${STREAMLIT_PORT} \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --browser.gatherUsageStats false \
    --theme.base dark
