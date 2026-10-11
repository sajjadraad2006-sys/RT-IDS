# CyberGuard Windows PowerShell Launcher
# Native execution script for Windows environments
[CmdletBinding()]
param(
    [switch]$Setup,
    [switch]$SkipLLM,
    [switch]$SkipMitreSync,
    [switch]$SkipVerify,
    [int]$Port = 8000,
    [string]$HostName = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Logging helpers
function Write-Success($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Info($msg)    { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)    { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)    { Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CyberGuard Autonomous Active Cyber Defense Launcher (Windows)  " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Force UTF-8 encoding across Windows console
$env:PYTHONUTF8 = "1"

# 2. Locate Python executable
$PythonPath = $null
if (Test-Path "$ScriptDir\.venv\Scripts\python.exe") {
    $PythonPath = "$ScriptDir\.venv\Scripts\python.exe"
} elseif (Test-Path "$ScriptDir\venv\Scripts\python.exe") {
    $PythonPath = "$ScriptDir\venv\Scripts\python.exe"
} else {
    $SysPython = Get-Command "python" -ErrorAction SilentlyContinue
    if ($SysPython) {
        $PythonPath = $SysPython.Source
    } else {
        Write-Fail "Python executable not found. Please install Python 3.10+ and add it to PATH."
    }
}
Write-Info "Using Python: $PythonPath"

# 3. Optional Setup / Dependency Installation
if ($Setup) {
    Write-Info "Installing dependencies from requirements.txt..."
    & $PythonPath -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Fail "Dependency installation failed." }
    Write-Success "Dependencies verified."
}

# 4. Preflight System Integrity Verification
if (-not $SkipVerify) {
    Write-Info "Running preflight integrity verification (verify.py)..."
    & $PythonPath verify.py
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Preflight verification failed. Use -SkipVerify to bypass if debugging."
    }
    Write-Success "All system integrity gates passed."
}

# 5. Environment configuration
if ($SkipMitreSync) {
    $env:CG_SKIP_MITRE_SYNC = "1"
}
if ($SkipLLM) {
    $env:CG_LLM_PROVIDER = "fallback"
}

# 6. Start CyberGuard FastAPI Application
$TargetUrl = "http://${HostName}:${Port}"
Write-Info "Starting CyberGuard Server on $TargetUrl ..."
Write-Host "Press Ctrl+C to terminate the server." -ForegroundColor Gray

& $PythonPath -m uvicorn backend.main:app --host $HostName --port $Port --log-level info
