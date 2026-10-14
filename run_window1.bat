@echo off
setlocal enabledelayedexpansion
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
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Locate llama-server.exe
set "LLAMA_EXE=llama-server.exe"
where llama-server.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe" (
        set "LLAMA_EXE=%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe"
    )
)

echo [1/2] Launching Local LLM Engine (llama-server) on Port 8080...
start "CyberGuard LLM Engine (llama-server RTX 5050)" cmd /c ""!LLAMA_EXE!" -m models\Foundation-Sec-8B-Instruct.Q4_K_M.gguf --port 8080 --host 127.0.0.1 -ngl 99 -c 4096"

echo.
echo [2/2] Launching CyberGuard FastAPI Web Server (Port 8000)...
echo Website UI will be accessible at: http://127.0.0.1:8000
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause
