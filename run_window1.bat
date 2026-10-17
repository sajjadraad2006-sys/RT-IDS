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

REM Locate llama-server.exe
set "LLAMA_EXE=llama-server.exe"
where llama-server.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe" (
        set "LLAMA_EXE=%LOCALAPPDATA%\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe"
    )
)

REM Check if llama-server is already running on port 8080
powershell -NoProfile -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('127.0.0.1', 8080); exit 0 } catch { exit 1 } finally { $client.Close() }" >nul 2>&1
if %ERRORLEVEL% equ 0 goto LLM_ALREADY_ACTIVE

echo [1/2] Launching Local LLM Engine on Port 8080...
start "CyberGuard LLM Engine RTX 5050" cmd /c ""!LLAMA_EXE!" -m "%~dp0models\Foundation-Sec-8B-Instruct.Q4_K_M.gguf" --port 8080 --host 127.0.0.1 -ngl 99 -c 4096"
goto PROCEED_SERVER

:LLM_ALREADY_ACTIVE
echo [1/2] Local LLM Engine already active on Port 8080.

:PROCEED_SERVER

echo.
echo [2/2] Launching CyberGuard FastAPI Web Server (Port 8000)...
echo Website UI will be accessible at: http://127.0.0.1:8000
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
