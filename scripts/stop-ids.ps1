# =============================================================================
# NIDS Project — Stop Suricata IDS
# =============================================================================
# Stops the Suricata process that was started by start-ids.ps1.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\stop-ids.ps1
# =============================================================================

# --- Configuration ---
$PROJECT_ROOT = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LOG_DIR      = Join-Path $PROJECT_ROOT "logs"
$PID_FILE     = Join-Path $LOG_DIR "suricata.pid"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NIDS — Stopping Suricata IDS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$stopped = $false

# --- Method 1: Stop using saved PID ---
if (Test-Path $PID_FILE) {
    $savedPid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
    if ($savedPid) {
        $process = Get-Process -Id $savedPid -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "  Stopping Suricata (PID: $savedPid)..." -ForegroundColor Yellow
            Stop-Process -Id $savedPid -Force
            Start-Sleep -Seconds 2

            # Verify it's stopped
            $check = Get-Process -Id $savedPid -ErrorAction SilentlyContinue
            if (-not $check) {
                Write-Host "  [OK] Suricata stopped successfully" -ForegroundColor Green
                $stopped = $true
            } else {
                Write-Host "  [WARNING] Process still running, trying harder..." -ForegroundColor Yellow
                Stop-Process -Id $savedPid -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $stopped = $true
            }
        } else {
            Write-Host "  [INFO] PID $savedPid is not running (already stopped)" -ForegroundColor Gray
            $stopped = $true
        }
    }
    # Remove the PID file
    Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
}

# --- Method 2: Fallback — kill any suricata.exe process ---
if (-not $stopped) {
    $suricataProcesses = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
    if ($suricataProcesses) {
        Write-Host "  Found $($suricataProcesses.Count) Suricata process(es). Stopping..." -ForegroundColor Yellow
        $suricataProcesses | Stop-Process -Force
        Start-Sleep -Seconds 2
        Write-Host "  [OK] All Suricata processes stopped" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No running Suricata processes found" -ForegroundColor Gray
    }
}

# --- Also stop the Suricata service if it exists ---
$service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "  Stopping Suricata service..." -ForegroundColor Yellow
    Stop-Service -Name "Suricata" -Force
    Write-Host "  [OK] Suricata service stopped" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Suricata IDS is stopped." -ForegroundColor White
Write-Host ""
