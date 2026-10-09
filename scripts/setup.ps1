# =============================================================================
# NIDS Project — Automated Setup Script
# =============================================================================
# This script:
#   1. Validates that Suricata and Npcap are installed
#   2. Creates the required directory structure
#   3. Installs Python dependencies
#   4. Downloads Emerging Threats Open rules (if not already present)
#   5. Copies Npcap DLLs to Suricata directory (if needed)
#   6. Lists available network interfaces
#   7. Validates the Suricata configuration
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
#
# Run from the project root (C:\NIDS) or it will auto-detect.
# =============================================================================

# --- Configuration ---
# Set the Suricata installation directory (override with env var if desired)
$SURICATA_HOME = if ($env:SURICATA_HOME) { $env:SURICATA_HOME } else { "C:\Program Files\Suricata" }

# Project root — auto-detect from script location
$PROJECT_ROOT = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# ET Open rules URL (Suricata 7.x compatible)
$ET_RULES_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.tar.gz"
$ET_RULES_TAR = Join-Path $PROJECT_ROOT "rules\emerging-all.rules.tar.gz"
$ET_RULES_FILE = Join-Path $PROJECT_ROOT "rules\suricata.rules"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NIDS Project — Automated Setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Suricata Home : $SURICATA_HOME"
Write-Host "  Project Root  : $PROJECT_ROOT"
Write-Host ""

# =============================================================================
# STEP 1: Validate Prerequisites
# =============================================================================
Write-Host "[1/7] Validating prerequisites..." -ForegroundColor Yellow

# Check Suricata
$suricataExe = Join-Path $SURICATA_HOME "suricata.exe"
if (Test-Path $suricataExe) {
    $version = & $suricataExe --build-info 2>&1 | Select-String "Suricata version" | Select-Object -First 1
    Write-Host "  [OK] Suricata found: $suricataExe" -ForegroundColor Green
    Write-Host "       $version" -ForegroundColor Gray
} else {
    Write-Host "  [ERROR] Suricata not found at: $suricataExe" -ForegroundColor Red
    Write-Host "  Download from: https://suricata.io/download/" -ForegroundColor Yellow
    Write-Host "  Or set SURICATA_HOME environment variable." -ForegroundColor Yellow
    exit 1
}

# Check Npcap
$npcapDll = "C:\Windows\System32\Npcap\wpcap.dll"
$npcapCompat = "C:\Windows\System32\wpcap.dll"
if ((Test-Path $npcapDll) -or (Test-Path $npcapCompat)) {
    Write-Host "  [OK] Npcap detected" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Npcap not detected. Download from: https://npcap.com/" -ForegroundColor Red
    Write-Host "  Install with 'WinPcap API-compatible mode' and 'Support loopback traffic' enabled." -ForegroundColor Yellow
}

# Check Python
try {
    $pyVersion = & python --version 2>&1
    Write-Host "  [OK] Python found: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}

# Check Nmap (optional)
try {
    $nmapVersion = & nmap --version 2>&1 | Select-String "Nmap version" | Select-Object -First 1
    Write-Host "  [OK] Nmap found: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Nmap not found (optional — port scan tests will use fallback)" -ForegroundColor Gray
}

Write-Host ""

# =============================================================================
# STEP 2: Create Directory Structure
# =============================================================================
Write-Host "[2/7] Creating directory structure..." -ForegroundColor Yellow

$directories = @(
    (Join-Path $PROJECT_ROOT "config"),
    (Join-Path $PROJECT_ROOT "rules"),
    (Join-Path $PROJECT_ROOT "scripts"),
    (Join-Path $PROJECT_ROOT "response"),
    (Join-Path $PROJECT_ROOT "tests"),
    (Join-Path $PROJECT_ROOT "dashboard"),
    (Join-Path $PROJECT_ROOT "logs"),
    (Join-Path $PROJECT_ROOT "docs")
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  [CREATED] $dir" -ForegroundColor Green
    } else {
        Write-Host "  [EXISTS]  $dir" -ForegroundColor Gray
    }
}
Write-Host ""

# =============================================================================
# STEP 3: Install Python Dependencies
# =============================================================================
Write-Host "[3/7] Installing Python dependencies..." -ForegroundColor Yellow

$requirementsFile = Join-Path $PROJECT_ROOT "requirements.txt"
if (Test-Path $requirementsFile) {
    & python -m pip install -r $requirementsFile --quiet
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Python dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Some dependencies may have failed to install" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARNING] requirements.txt not found at $requirementsFile" -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# STEP 4: Download Emerging Threats Open Rules
# =============================================================================
Write-Host "[4/7] Checking Emerging Threats Open rules..." -ForegroundColor Yellow

if (Test-Path $ET_RULES_FILE) {
    Write-Host "  [EXISTS] ET rules already present: $ET_RULES_FILE" -ForegroundColor Gray
} else {
    # Try suricata-update first
    $suricataUpdate = Join-Path $SURICATA_HOME "suricata-update.exe"
    if (Test-Path $suricataUpdate) {
        Write-Host "  Trying suricata-update..." -ForegroundColor Gray
        & $suricataUpdate --suricata-conf (Join-Path $PROJECT_ROOT "config\suricata-overrides.yaml") `
                          --output (Join-Path $PROJECT_ROOT "rules") 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Rules updated via suricata-update" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] suricata-update failed, falling back to manual download" -ForegroundColor Yellow
        }
    }

    # Manual download fallback
    if (-not (Test-Path $ET_RULES_FILE)) {
        Write-Host "  Downloading ET Open rules from:" -ForegroundColor Gray
        Write-Host "    $ET_RULES_URL" -ForegroundColor Gray

        try {
            # Download the tar.gz
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $ET_RULES_URL -OutFile $ET_RULES_TAR -UseBasicParsing

            if (Test-Path $ET_RULES_TAR) {
                Write-Host "  [OK] Downloaded: $ET_RULES_TAR" -ForegroundColor Green

                # Extract using tar (built into Windows 10+)
                $rulesDir = Join-Path $PROJECT_ROOT "rules"
                & tar -xzf $ET_RULES_TAR -C $rulesDir 2>&1

                # The tar extracts to a subfolder; merge .rules files
                $extractedDir = Join-Path $rulesDir "rules"
                if (Test-Path $extractedDir) {
                    # Combine all .rules files into one suricata.rules
                    Get-ChildItem -Path $extractedDir -Filter "*.rules" |
                        ForEach-Object { Get-Content $_.FullName } |
                        Set-Content $ET_RULES_FILE
                    # Clean up extracted folder
                    Remove-Item $extractedDir -Recurse -Force
                    Write-Host "  [OK] ET rules extracted to: $ET_RULES_FILE" -ForegroundColor Green
                } else {
                    Write-Host "  [WARNING] Extraction completed but rules subfolder not found" -ForegroundColor Yellow
                    Write-Host "  Check $rulesDir for extracted files" -ForegroundColor Yellow
                }

                # Clean up tar.gz
                Remove-Item $ET_RULES_TAR -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "  [ERROR] Failed to download ET rules: $_" -ForegroundColor Red
            Write-Host "  You can manually download from:" -ForegroundColor Yellow
            Write-Host "    $ET_RULES_URL" -ForegroundColor Yellow
            Write-Host "  Extract and place as: $ET_RULES_FILE" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# =============================================================================
# STEP 5: Copy Npcap DLLs (if needed)
# =============================================================================
Write-Host "[5/7] Checking Npcap DLLs in Suricata directory..." -ForegroundColor Yellow

$npcapSysDir = "C:\Windows\System32\Npcap"
$dllsToCopy = @("wpcap.dll", "Packet.dll")

foreach ($dll in $dllsToCopy) {
    $srcPath = Join-Path $npcapSysDir $dll
    $dstPath = Join-Path $SURICATA_HOME $dll

    if ((Test-Path $srcPath) -and (-not (Test-Path $dstPath))) {
        try {
            Copy-Item $srcPath $dstPath -Force
            Write-Host "  [COPIED] $dll -> $SURICATA_HOME" -ForegroundColor Green
        } catch {
            Write-Host "  [WARNING] Could not copy $dll (may need admin rights): $_" -ForegroundColor Yellow
        }
    } elseif (Test-Path $dstPath) {
        Write-Host "  [EXISTS] $dll already in Suricata directory" -ForegroundColor Gray
    } else {
        Write-Host "  [INFO] $dll not found in $npcapSysDir" -ForegroundColor Gray
    }
}
Write-Host ""

# =============================================================================
# STEP 6: List Network Interfaces
# =============================================================================
Write-Host "[6/7] Available network interfaces:" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Gray

& $suricataExe --list-interfaces 2>&1 | ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "  TIP: Look for your Wi-Fi/Ethernet adapter and the" -ForegroundColor Cyan
Write-Host "  'Npcap Loopback Adapter' for localhost testing." -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# STEP 7: Validate Suricata Configuration
# =============================================================================
Write-Host "[7/7] Validating Suricata configuration..." -ForegroundColor Yellow

$configFile = Join-Path $PROJECT_ROOT "config\suricata-overrides.yaml"

if (Test-Path $configFile) {
    Write-Host "  Running: suricata.exe -T -c `"$configFile`"" -ForegroundColor Gray
    Write-Host "------------------------------------------------------------" -ForegroundColor Gray

    & $suricataExe -T -c $configFile 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host "------------------------------------------------------------" -ForegroundColor Gray
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Configuration is valid!" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Configuration validation returned errors." -ForegroundColor Yellow
        Write-Host "  Review the output above and fix any issues." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [ERROR] Config file not found: $configFile" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Note your network interface name from the list above"
Write-Host "    2. Start Suricata:  .\scripts\start-ids.ps1"
Write-Host "    3. Check status:    .\scripts\status-ids.ps1"
Write-Host "    4. Run tests:       python tests\run_all_tests.py"
Write-Host "    5. View dashboard:  streamlit run dashboard\app.py"
Write-Host "    6. Response engine: python response\response.py"
Write-Host ""
