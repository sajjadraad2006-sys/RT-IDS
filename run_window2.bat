@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title CyberGuard Window 2 - Attack Simulator and AI Behavior Console
color 0B

echo =======================================================================
echo     CyberGuard Attack Simulation ^& AI Log Analysis Console (Window 2)
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

python "%~dp0scripts\attack_simulation_console.py"
pause
