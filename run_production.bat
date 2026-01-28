@echo off
setlocal

set "ROOT=%~dp0"
set "PYTHON=%ROOT%venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"
set "PYTHONPATH=%ROOT%"

echo ==========================================
echo   SmartGuard AI - Production Launch
echo ==========================================
echo.

:: 0. Clean up existing processes on ports 8000 and 8501
echo [0/3] Cleaning up existing services...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8501 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1

:: 1. Start FastAPI Backend
echo [1/3] Starting FastAPI Backend on port 8000...
start /b "" "%PYTHON%" -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --log-level info

:: Wait for backend to warm up
timeout /t 8 /nobreak >nul

:: 2. Initialize Models
echo [2/3] Initializing Hybrid Ensemble...
"%PYTHON%" -c "import requests; r = requests.post('http://localhost:8000/initialize'); print(r.json().get('message', 'Initialized'))"

:: 3. Start Streamlit Dashboard
echo [3/3] Starting Streamlit Portal on port 8501...
echo.
echo   • Portal:   http://localhost:8501
echo   • API:      http://localhost:8000
echo.
"%PYTHON%" -m streamlit run src\dashboard\main_app.py --server.port 8501 --server.address 127.0.0.1 --server.headless true

pause
