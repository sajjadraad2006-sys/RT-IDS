@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

echo ============================================================
echo   CyberGuard Autonomous Active Cyber Defense Launcher (Windows)
echo ============================================================

set PYTHONUTF8=1
chcp 65001 >nul 2>&1

REM Check virtual environment
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Executing preflight integrity checks...
"%PYTHON_EXE%" "%~dp0verify.py"
if %ERRORLEVEL% neq 0 (
    echo [X] Verification failed. Aborting.
    pause
    exit /b %ERRORLEVEL%
)

echo [✓] Preflight verification passed.
echo.

REM Start Local LLM on RTX 5050 if available and not yet running
powershell -NoProfile -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('127.0.0.1', 8080); exit 0 } catch { exit 1 } finally { $client.Close() }" >nul 2>&1
if !ERRORLEVEL! neq 0 (
    set "LLAMA_EXE=llama-server.exe"
    where llama-server.exe >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        if exist "%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe" (
            set "LLAMA_EXE=%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe"
        )
    )
    if exist "%~dp0models\Foundation-Sec-8B-Instruct.Q4_K_M.gguf" (
        echo [*] Launching Local LLM Engine (Foundation-Sec-8B on RTX 5050 GPU Port 8080)...
        start "CyberGuard LLM Engine (RTX 5050 GPU)" /min "!LLAMA_EXE!" -m "%~dp0models\Foundation-Sec-8B-Instruct.Q4_K_M.gguf" --port 8080 --host 127.0.0.1 -ngl 99 -c 4096
    )
)

echo [*] Starting CyberGuard Web SOC Dashboard on http://127.0.0.1:8000 ...
"%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
