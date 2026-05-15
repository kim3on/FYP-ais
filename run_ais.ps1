# AIS-Detect Unified Launch Script
# ==================================
# This script starts both the FastAPI backend and the React frontend.
# It checks for a virtual environment and installs dependencies if missing.

$ErrorActionPreference = "Stop"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $PSScriptRoot

Write-Host "`n[AIS-Detect] Initiating system startup..." -ForegroundColor Cyan

# Keep Python/scikit-learn logs stable on Windows.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:LOKY_MAX_CPU_COUNT = [string]([Environment]::ProcessorCount)

# ── 1. Backend Environment Setup ─────────────────────────────────────
Write-Host "[1/4] Checking Python environment..." -ForegroundColor Gray

if (-not (Test-Path ".venv")) {
    Write-Host "    [!] Virtual environment not found. Creating .venv..." -ForegroundColor Yellow
    python -m venv .venv
}

$VENV_PYTHON = ".venv\Scripts\python.exe"
$VENV_UVICORN = ".venv\Scripts\uvicorn.exe"

# Verify pip dependencies
Write-Host "    [!] Verifying backend dependencies (requirements.txt)..." -ForegroundColor Gray
& $VENV_PYTHON -m pip install -q -r requirements.txt

# ── 2. Frontend Check ────────────────────────────────────────────────
Write-Host "[2/4] Checking Frontend dependencies..." -ForegroundColor Gray
if (-not (Test-Path "frontend\node_modules")) {
    Write-Host "    [!] node_modules missing. Running npm install..." -ForegroundColor Yellow
    Set-Location frontend
    npm install --silent
    Set-Location ..
}

# ── 3. Launch Backend ────────────────────────────────────────────────
Write-Host "[3/4] Launching FastAPI Backend (Port 8000)..." -ForegroundColor Green
$backendCommand = @"
`$env:PYTHONUTF8='1';
`$env:PYTHONIOENCODING='utf-8';
`$env:LOKY_MAX_CPU_COUNT='$env:LOKY_MAX_CPU_COUNT';
Set-Location '$PSScriptRoot';
.\.venv\Scripts\activate;
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCommand -WindowStyle Normal

# ── 4. Launch Frontend ───────────────────────────────────────────────
Write-Host "[4/4] Launching React Dev Server (Port 5173)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\frontend'; npm run dev" -WindowStyle Normal

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "  AIS-Detect is running! " -ForegroundColor White
Write-Host "  - Backend API : http://localhost:8000" -ForegroundColor Gray
Write-Host "  - Frontend UI : http://localhost:5173" -ForegroundColor Gray
Write-Host "====================================================`n" -ForegroundColor Cyan

Write-Host "Press any key to close this launcher (servers will keep running in their own windows)." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
