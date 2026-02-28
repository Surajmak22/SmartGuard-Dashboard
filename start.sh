#!/bin/bash

# Configuration
# Default to 8501 if PORT isn't set (local dev)
STREAMLIT_PORT=${PORT:-8501}
# Backend runs on a fixed internal port
BACKEND_PORT=8000

export BACKEND_API_URL="http://localhost:${BACKEND_PORT}"

# Start FastAPI Backend in background
echo "🚀 Starting FastAPI Backend on port ${BACKEND_PORT}..."
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port ${BACKEND_PORT} --log-level info &

# Wait for backend to be ready
echo "⏳ Waiting for backend to warm up at ${BACKEND_API_URL}..."
max_retries=15
count=0
while ! curl -s ${BACKEND_API_URL}/health > /dev/null; do
    count=$((count+1))
    if [ $count -ge $max_retries ]; then
        echo "❌ Backend failed to start"
        exit 1
    fi
    sleep 2
done

# Initialize models
echo "🧠 Initializing ML Engines..."
curl -X POST ${BACKEND_API_URL}/initialize

# Start Streamlit Dashboard in foreground
echo "📊 Starting Streamlit Dashboard on port ${STREAMLIT_PORT}..."
# Headless mode for production
streamlit run src/dashboard/main_app.py --server.port ${STREAMLIT_PORT} --server.address 0.0.0.0 --theme.base dark
