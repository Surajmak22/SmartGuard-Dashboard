@echo off
setlocal

:: Kill any existing Streamlit processes
taskkill /f /im streamlit.exe >nul 2>&1

:: Set Python and Streamlit paths
set "ROOT=%~dp0"
set "PYTHON=%ROOT%venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"
set "STREAMLIT_SCRIPT=%ROOT%src\dashboard\main_app.py"
:: Ensure src is on PYTHONPATH for Streamlit imports
set "PYTHONPATH=%ROOT%"

:: Preflight: ensure Streamlit is installed in this Python
"%PYTHON%" -c "import streamlit" >nul 2>&1
if errorlevel 1 goto no_streamlit

:: Preflight: ensure scikit-learn native modules are not blocked by Windows policy
"%PYTHON%" -c "import sklearn" >nul 2>&1
if errorlevel 1 goto no_sklearn

:: Find an available port
set PORT=8501
:find_port
netstat -ano | findstr /R /C:":%PORT% " >nul
if not errorlevel 1 goto port_in_use
goto port_free

:port_in_use
set /a PORT+=1
goto find_port

:port_free

:: Start Streamlit
echo Starting SmartGuard AI Dashboard on port %PORT%...
echo   • Local:   http://localhost:%PORT%
echo   • Press Ctrl+C in this window to stop
echo.

"%PYTHON%" -m streamlit run "%STREAMLIT_SCRIPT%" --server.port %PORT% --server.address 127.0.0.1 --server.headless false

pause
exit /b 0

:no_streamlit
echo.
echo ERROR: Streamlit is not installed for: %PYTHON%
echo Fix:   "%ROOT%venv\Scripts\python.exe" -m pip install -r "%ROOT%requirements.txt"
echo.
pause
exit /b 1

:no_sklearn
echo.
echo ERROR: scikit-learn failed to import in this environment.
echo This is commonly caused by Windows blocking sklearn's .pyd (Application Control / MOTW).
echo.
echo Best fix (PowerShell, run from project folder):
echo   Get-ChildItem -Recurse .\venv ^| Unblock-File
echo   Remove-Item -Recurse -Force .\venv
echo   python -m venv venv
echo   .\venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
pause
exit /b 1