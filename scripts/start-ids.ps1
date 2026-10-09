# =============================================================================
# NIDS Project — Start Suricata IDS
# =============================================================================
# Starts Suricata in the background, capturing on the specified interface.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\start-ids.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\start-ids.ps1 -Interface "Wi-Fi"
#
# Requires: Administrator privileges (for raw packet capture)
# =============================================================================

param(
    [string]$Interface = "",
    [switch]$Service
)

# --- Configuration ---
$SURICATA_HOME = if ($env:SURICATA_HOME) { $env:SURICATA_HOME } else { "C:\Program Files\Suricata" }
$PROJECT_ROOT  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CONFIG_FILE   = Join-Path $PROJECT_ROOT "config\suricata-overrides.yaml"
$LOG_DIR       = Join-Path $PROJECT_ROOT "logs"
$PID_FILE      = Join-Path $LOG_DIR "suricata.pid"
$SURICATA_EXE  = Join-Path $SURICATA_HOME "suricata.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NIDS — Starting Suricata IDS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Check if Suricata is already running ---
if (Test-Path $PID_FILE) {
    $existingPid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
    $existingProcess = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
    if ($existingProcess) {
        Write-Host "  [WARNING] Suricata is already running (PID: $existingPid)" -ForegroundColor Yellow
        Write-Host "  Use stop-ids.ps1 to stop it first." -ForegroundColor Yellow
        exit 0
    } else {
        # Stale PID file
        Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
    }
}

# --- Validate prerequisites ---
if (-not (Test-Path $SURICATA_EXE)) {
    Write-Host "  [ERROR] Suricata not found: $SURICATA_EXE" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $CONFIG_FILE)) {
    Write-Host "  [ERROR] Config file not found: $CONFIG_FILE" -ForegroundColor Red
    Write-Host "  Run setup.ps1 first." -ForegroundColor Yellow
    exit 1
}

# --- Ensure log directory exists ---
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
}

# --- Select interface ---
if (-not $Interface) {
    Write-Host "  Available network interfaces:" -ForegroundColor Yellow
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Gray
    & $SURICATA_EXE --list-interfaces 2>&1 | ForEach-Object { Write-Host "    $_" }
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    $Interface = Read-Host "  Enter the interface name or number to capture on"
    if (-not $Interface) {
        Write-Host "  [ERROR] No interface specified. Exiting." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "  Configuration : $CONFIG_FILE" -ForegroundColor Gray
Write-Host "  Interface     : $Interface" -ForegroundColor Gray
Write-Host "  Log directory : $LOG_DIR" -ForegroundColor Gray
Write-Host ""

# --- Start Suricata ---
if ($Service) {
    # Install as a Windows service
    Write-Host "  Installing Suricata as a Windows service..." -ForegroundColor Yellow
    & $SURICATA_EXE -c $CONFIG_FILE -i $Interface --service-install 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Suricata service installed" -ForegroundColor Green
        Write-Host "  Start it with: Start-Service Suricata" -ForegroundColor Cyan
    } else {
        Write-Host "  [ERROR] Service installation failed (need admin?)" -ForegroundColor Red
    }
} else {
    # Start as a background process
    Write-Host "  Starting Suricata in background..." -ForegroundColor Yellow

    $process = Start-Process -FilePath $SURICATA_EXE `
        -ArgumentList "-c", "`"$CONFIG_FILE`"", "-i", "`"$Interface`"" `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LOG_DIR "suricata_stdout.log") `
        -RedirectStandardError (Join-Path $LOG_DIR "suricata_stderr.log")

    # Save PID
    $process.Id | Out-File -FilePath $PID_FILE -Encoding ascii -NoNewline

    # Wait a moment and check if it's still running
    Start-Sleep -Seconds 3
    $check = Get-Process -Id $process.Id -ErrorAction SilentlyContinue

    if ($check) {
        Write-Host "  [OK] Suricata started successfully!" -ForegroundColor Green
        Write-Host "  PID       : $($process.Id)" -ForegroundColor White
        Write-Host "  PID file  : $PID_FILE" -ForegroundColor Gray
        Write-Host "  Stdout log: $(Join-Path $LOG_DIR 'suricata_stdout.log')" -ForegroundColor Gray
        Write-Host "  Stderr log: $(Join-Path $LOG_DIR 'suricata_stderr.log')" -ForegroundColor Gray
        Write-Host "  Eve log   : $(Join-Path $LOG_DIR 'eve.json')" -ForegroundColor Gray
    } else {
        Write-Host "  [ERROR] Suricata process exited immediately." -ForegroundColor Red
        Write-Host "  Check stderr log: $(Join-Path $LOG_DIR 'suricata_stderr.log')" -ForegroundColor Yellow
        $stderrContent = Get-Content (Join-Path $LOG_DIR "suricata_stderr.log") -ErrorAction SilentlyContinue
        if ($stderrContent) {
            Write-Host "  --- stderr output ---" -ForegroundColor Gray
            $stderrContent | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
        Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

Write-Host ""
Write-Host "  Next: Run .\scripts\status-ids.ps1 to check status" -ForegroundColor Cyan
Write-Host ""
