# =============================================================================
# NIDS Project — Suricata IDS Status Check
# =============================================================================
# Shows whether Suricata is running, log file stats, and recent alerts.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\status-ids.ps1
# =============================================================================

# --- Configuration ---
$SURICATA_HOME = if ($env:SURICATA_HOME) { $env:SURICATA_HOME } else { "C:\Program Files\Suricata" }
$PROJECT_ROOT  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LOG_DIR       = Join-Path $PROJECT_ROOT "logs"
$PID_FILE      = Join-Path $LOG_DIR "suricata.pid"
$EVE_JSON      = Join-Path $LOG_DIR "eve.json"
$FAST_LOG      = Join-Path $LOG_DIR "fast.log"
$RULES_DIR     = Join-Path $PROJECT_ROOT "rules"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NIDS — Suricata IDS Status" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Process Status ---
Write-Host "  [Process Status]" -ForegroundColor Yellow

$isRunning = $false

# Check PID file
if (Test-Path $PID_FILE) {
    $savedPid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
    $process = Get-Process -Id $savedPid -ErrorAction SilentlyContinue
    if ($process) {
        $isRunning = $true
        $uptime = (Get-Date) - $process.StartTime
        Write-Host "    Status    : RUNNING" -ForegroundColor Green
        Write-Host "    PID       : $savedPid" -ForegroundColor White
        Write-Host "    Uptime    : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor White
        Write-Host "    CPU (s)   : $([math]::Round($process.CPU, 2))" -ForegroundColor Gray
        Write-Host "    Memory    : $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB" -ForegroundColor Gray
    }
}

# Check for any suricata process (without PID file)
if (-not $isRunning) {
    $suricataProcesses = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
    if ($suricataProcesses) {
        $isRunning = $true
        Write-Host "    Status    : RUNNING (no PID file)" -ForegroundColor Yellow
        $suricataProcesses | ForEach-Object {
            Write-Host "    PID       : $($_.Id)" -ForegroundColor White
        }
    }
}

# Check Suricata service
$service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "    Service   : $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Gray' })
}

if (-not $isRunning) {
    Write-Host "    Status    : STOPPED" -ForegroundColor Red
}

Write-Host ""

# --- Log File Stats ---
Write-Host "  [Log Files]" -ForegroundColor Yellow

if (Test-Path $EVE_JSON) {
    $eveInfo = Get-Item $EVE_JSON
    $eveSize = if ($eveInfo.Length -gt 1MB) {
        "$([math]::Round($eveInfo.Length / 1MB, 2)) MB"
    } else {
        "$([math]::Round($eveInfo.Length / 1KB, 2)) KB"
    }
    $eveLines = (Get-Content $EVE_JSON | Measure-Object).Count
    Write-Host "    eve.json  : $eveSize ($eveLines events)" -ForegroundColor White
    Write-Host "    Modified  : $($eveInfo.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "    eve.json  : Not found (no alerts yet)" -ForegroundColor Gray
}

if (Test-Path $FAST_LOG) {
    $fastInfo = Get-Item $FAST_LOG
    Write-Host "    fast.log  : $([math]::Round($fastInfo.Length / 1KB, 2)) KB" -ForegroundColor White
} else {
    Write-Host "    fast.log  : Not found" -ForegroundColor Gray
}

Write-Host ""

# --- Rule Count ---
Write-Host "  [Rules]" -ForegroundColor Yellow

$totalRules = 0
if (Test-Path $RULES_DIR) {
    $ruleFiles = Get-ChildItem -Path $RULES_DIR -Filter "*.rules" -ErrorAction SilentlyContinue
    foreach ($ruleFile in $ruleFiles) {
        $ruleCount = (Select-String -Path $ruleFile.FullName -Pattern "^alert |^drop |^pass |^reject " | Measure-Object).Count
        Write-Host "    $($ruleFile.Name) : $ruleCount rules" -ForegroundColor White
        $totalRules += $ruleCount
    }
}
Write-Host "    Total     : $totalRules rules loaded" -ForegroundColor White
Write-Host ""

# --- Recent Alerts ---
Write-Host "  [Recent Alerts (last 10)]" -ForegroundColor Yellow

if (Test-Path $EVE_JSON) {
    # Read only alert events from the last N lines
    $recentLines = Get-Content $EVE_JSON -Tail 100 -ErrorAction SilentlyContinue
    $alerts = @()

    foreach ($line in $recentLines) {
        try {
            $event = $line | ConvertFrom-Json
            if ($event.event_type -eq "alert") {
                $alerts += $event
            }
        } catch {
            # Skip malformed lines
        }
    }

    if ($alerts.Count -gt 0) {
        # Show last 10 alerts
        $recentAlerts = $alerts | Select-Object -Last 10
        Write-Host "  ------------------------------------------------------------" -ForegroundColor Gray

        foreach ($alert in $recentAlerts) {
            $severity = $alert.alert.severity
            $color = switch ($severity) {
                1 { "Red" }
                2 { "Yellow" }
                3 { "White" }
                default { "Gray" }
            }
            $ts = $alert.timestamp.Substring(0, 19)
            $sig = $alert.alert.signature
            $src = "$($alert.src_ip):$($alert.src_port)"
            $dst = "$($alert.dest_ip):$($alert.dest_port)"

            Write-Host "    [$ts] [Sev:$severity] $sig" -ForegroundColor $color
            Write-Host "      $src -> $dst ($($alert.proto))" -ForegroundColor Gray
        }

        Write-Host "  ------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "    Total alerts in log: $($alerts.Count)" -ForegroundColor White
    } else {
        Write-Host "    No alerts found in eve.json" -ForegroundColor Gray
    }
} else {
    Write-Host "    eve.json not found — start Suricata first" -ForegroundColor Gray
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
