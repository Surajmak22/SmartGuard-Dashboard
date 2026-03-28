#!/bin/bash
echo "Updating ClamAV virus signatures (this may take a few minutes)..."
freshclam --quiet || echo "freshclam warning (continuing anyway)..."

echo "Starting ClamAV Daemon in background..."
clamd &

echo "Waiting 30s for ClamAV to initialize signatures in RAM..."
sleep 30

echo "Booting FastAPI Backend..."
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --workers 1 &

echo "Booting SmartGuard Streamlit Dashboard on Port 7860..."
python -m streamlit run src/dashboard/main_app.py --server.port=7860 --server.address=0.0.0.0 --server.enableCORS=false --server.enableXsrfProtection=false
