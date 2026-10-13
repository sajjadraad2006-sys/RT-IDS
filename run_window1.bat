@echo off
title CyberGuard Window 1 - Web Server and LLM Engine (RTX 5050)
color 0A

echo =======================================================================
echo     CyberGuard Autonomous Active Defense - Server and LLM (Window 1)
echo     Accelerated on RTX 5050 8GB VRAM - Foundation-Sec-8B
echo =======================================================================
echo.

set PYTHONUTF8=1

:: Activate virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo [1/2] Launching Local LLM Engine (llama-server) on RTX 5050 GPU (Port 8080)...
start "CyberGuard LLM Engine (llama-server RTX 5050)" cmd /c "llama-server.exe -m models\Foundation-Sec-8B-Instruct.Q4_K_M.gguf --port 8080 --host 127.0.0.1 -ngl 99 -c 8192"

echo.
echo [2/2] Launching CyberGuard FastAPI Web Server (Port 8000)...
echo Website UI will be accessible at: http://127.0.0.1:8000
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

pause
