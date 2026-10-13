@echo off
title CyberGuard Window 2 - Attack Simulator and AI Behavior Console
color 0B

echo =======================================================================
echo     CyberGuard Attack Simulation ^& AI Log Analysis Console (Window 2)
echo =======================================================================
echo.

set PYTHONUTF8=1

:: Activate virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

python scripts\attack_simulation_console.py

pause
