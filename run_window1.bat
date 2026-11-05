@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title CyberGuard Window 1 - Web Server and LLM Engine (RTX 5050)
color 0A

echo =======================================================================
echo     CyberGuard Autonomous Active Defense - Server and LLM (Window 1)
echo     Accelerated on RTX 5050 8GB VRAM - Foundation-Sec-8B
echo =======================================================================
echo.

set PYTHONUTF8=1
chcp 65001 >nul 2>&1

REM Activate virtual environment if present
if exist "%~dp0.venv\Scripts\activate.bat" (
    call "%~dp0.venv\Scripts\activate.bat"
) else if exist "%~dp0venv\Scripts\activate.bat" (
    call "%~dp0venv\Scripts\activate.bat"
)

set "PYTHON_EXE=python"
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
)

REM Check if llama-server is already running on port 8080
"%PYTHON_EXE%" scripts\run_local_llama.py --check-only && goto LLM_ALREADY_ACTIVE

echo [1/2] Launching Local LLM Engine on Port 8080 (RTX 5050 GPU)...
start "CyberGuard LLM Engine RTX 5050" "%PYTHON_EXE%" scripts\run_local_llama.py --port 8080 --ngl 99 --ctx 4096

echo [*] Waiting for LLM model weights to load into VRAM...
"%PYTHON_EXE%" scripts\run_local_llama.py --wait-ready
goto PROCEED_SERVER

:LLM_ALREADY_ACTIVE
echo [1/2] Local LLM Engine already active on Port 8080.

:PROCEED_SERVER

echo.
echo [2/2] Launching CyberGuard FastAPI Web Server (Port 8000)...
echo Website UI will be accessible at: http://127.0.0.1:8000
echo.
"%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
