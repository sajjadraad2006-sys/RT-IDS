@echo off
setlocal EnableDelayedExpansion
title CyberGuard RT-IDS (Admin Live Mode)
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator Privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

set "PYTHONPATH=%~dp0;%PYTHONPATH%"
set PYTHONUTF8=1

echo ============================================================
echo   CyberGuard Autonomous Active Cyber Defense Launcher (Admin)
echo ============================================================
echo [*] Status: Running as Administrator.
echo.

echo [*] Clearing port 8000...
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }" >nul 2>&1

set "PYTHON_EXE=python"
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
)

echo [*] Python executable: %PYTHON_EXE%

set CG_AUTOSTART_LIVE_WORKER=true
set CG_ENV=development

for /f "tokens=*" %%a in ('%PYTHON_EXE% scripts\get_lan_ip.py') do set "LOCAL_IP=%%a"
if "%LOCAL_IP%"=="" set "LOCAL_IP=127.0.0.1"

if "%CG_HOST%"=="" set "CG_HOST=127.0.0.1"
if "%CG_PORT%"=="" set "CG_PORT=8000"

echo.
echo ============================================================
echo   [OK] Server listening on:  http://%CG_HOST%:%CG_PORT%
echo   [OK] Local Dashboard (PC): http://127.0.0.1:%CG_PORT%/
if "%CG_HOST%"=="0.0.0.0" (
echo   [OK] Mobile Web Dashboard: http://%LOCAL_IP%:%CG_PORT%/
)
echo.
echo   Termux Attack Command:
echo   nmap -Pn -sT -p 1-150 %LOCAL_IP%
echo ============================================================
echo.

echo [*] Starting CyberGuard Server and Live Raw Sniffer...
"%PYTHON_EXE%" -m uvicorn backend.main:app --host %CG_HOST% --port %CG_PORT% --reload
pause
