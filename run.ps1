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
Write-Host "  Accelerated on RTX 5050 8GB VRAM - Foundation-Sec-8B  " -ForegroundColor Cyan
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

# 5. Environment & LLM Engine Startup
if ($SkipMitreSync) {
    $env:CG_SKIP_MITRE_SYNC = "1"
}
if ($SkipLLM) {
    $env:CG_LLM_PROVIDER = "fallback"
} else {
    Write-Info "Checking Local LLM Engine (Foundation-Sec-8B on RTX 5050)..."
    $llmRunning = $false
    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
        if ($res.status -eq "ok") { $llmRunning = $true }
    } catch {}

    if (-not $llmRunning) {
        Write-Info "Starting llama-server with GPU acceleration on port 8080..."
        Start-Process -FilePath $PythonPath -ArgumentList "scripts\run_local_llama.py --port 8080 --ngl 99 --ctx 4096" -WindowStyle Minimized
        
        Write-Info "Waiting for LLM model weights to load into GPU VRAM..."
        $tries = 0
        while ($tries -lt 30) {
            Start-Sleep -Milliseconds 500
            try {
                $r = Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
                if ($r.status -eq "ok") { $llmRunning = $true; break }
            } catch {}
            $tries++
        }
        if ($llmRunning) {
            Write-Success "Foundation-Sec-8B active on RTX 5050 GPU (Port 8080)."
        } else {
            Write-Warn "LLM Engine taking longer than expected; continuing startup..."
        }
    } else {
        Write-Success "Local LLM Engine already active on Port 8080."
    }
}

# 6. Start CyberGuard FastAPI Application
$TargetUrl = "http://${HostName}:${Port}"
Write-Info "Starting CyberGuard Server on $TargetUrl ..."
Write-Host "Press Ctrl+C to terminate the server." -ForegroundColor Gray

& $PythonPath -m uvicorn backend.main:app --host $HostName --port $Port --log-level info
