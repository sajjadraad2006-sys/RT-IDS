@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   CyberGuard Autonomous Active Cyber Defense Launcher (Windows)
echo ============================================================

set PYTHONUTF8=1
chcp 65001 >nul 2>&1

:: Check virtual environment
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Executing preflight integrity checks...
"%PYTHON_EXE%" verify.py
if %ERRORLEVEL% neq 0 (
    echo [X] Verification failed. Aborting.
    pause
    exit /b %ERRORLEVEL%
)

echo [✓] Preflight verification passed.
echo [*] Starting CyberGuard on http://127.0.0.1:8000 ...

"%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
