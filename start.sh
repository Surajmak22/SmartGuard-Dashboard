#!/bin/bash

# Start FastAPI Backend in background
# In Docker, port 80 is often easier to map than 8000
echo "🚀 Starting FastAPI Backend on port 80..."
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 80 --log-level info &

# Wait for backend to be ready
echo "⏳ Waiting for backend to warm up..."
max_retries=10
count=0
while ! curl -s http://localhost:80/health > /dev/null; do
    count=$((count+1))
    if [ $count -ge $max_retries ]; then
        echo "❌ Backend failed to start"
        exit 1
    fi
    sleep 2
done

# Initialize models
echo "🧠 Initializing ML Engines..."
curl -X POST http://localhost:80/initialize

# Start Streamlit Dashboard in foreground
echo "📊 Starting Streamlit Dashboard on port 8501..."
# Headless mode for production
streamlit run src/dashboard/main_app.py --server.port 8501 --server.address 0.0.0.0 --theme.base dark
