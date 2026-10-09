# Windows Network Intrusion Detection System (NIDS)

A comprehensive Network Intrusion Detection System built for Windows environments using Suricata, Python, and PowerShell.

## Architecture

```mermaid
graph TD
    A[Network Traffic\n(Npcap/Loopback)] -->|Captures Packets| B(Suricata NIDS Engine)
    B -->|Matches Rules| C{Rules Engine\nC:\\NIDS\\rules}
    C -->|Generates Alerts| D[Logs\nC:\\NIDS\\logs\\eve.json]
    D -->|Tails & Parses| E(Response Engine\nresponse.py)
    D -->|Visualizes| F(Dashboard\napp.py)
    E -->|Executes Block| G[Windows Firewall]
    
    H[Test Scripts] -->|Generates Traffic| A
```

## Prerequisites

- **Windows 10/11**
- **Suricata**: Download from [suricata.io](https://suricata.io/download/) and install to `C:\Program Files\Suricata`
- **Npcap**: Download from [npcap.com](https://npcap.com/) (Must be installed with "WinPcap API-compatible mode" and "Loopback support" enabled)
- **Python 3.8+**: Download from [python.org](https://python.org)
- **Nmap for Windows** (Optional): Download from [nmap.org](https://nmap.org/download) for running port scan tests

## Project Structure

```
C:\NIDS\
├── config/
│   └── suricata-overrides.yaml
├── rules/
│   └── local.rules
├── scripts/
│   ├── setup.ps1
│   ├── start-ids.ps1
│   ├── stop-ids.ps1
│   └── status-ids.ps1
├── response/
│   └── response.py
├── tests/
│   ├── test_portscan.ps1
│   ├── test_ping_flood.ps1
│   ├── test_bruteforce.ps1
│   ├── test_web_attacks.ps1
│   ├── test_dns.py
│   ├── test_ftp_cleartext.py
│   ├── generate_pcap.py
│   ├── local_webserver.py
│   └── run_all_tests.py
├── dashboard/
│   └── app.py
├── logs/
├── docs/
│   ├── README.md
│   └── REPORT.md
└── requirements.txt
```

## Quick Start

1. **Install Prerequisites**: Ensure Suricata, Npcap, and Python are installed.
2. **Run Setup**: 
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
   ```
3. **Start Suricata**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\start-ids.ps1
   ```
4. **Check Status**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\status-ids.ps1
   ```
5. **Run Tests**:
   ```powershell
   python tests\run_all_tests.py
   ```
6. **Start Dashboard**:
   ```powershell
   streamlit run dashboard\app.py
   ```
7. **Start Response Engine**:
   - Dry-run mode: `python response\response.py`
   - Live mode (Requires Admin): `python response\response.py --live`
8. **Stop Suricata**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\stop-ids.ps1
   ```

## Component Details

### Suricata Engine
The core NIDS engine that inspects network traffic against defined rules in `rules/local.rules`. Configured via `config/suricata-overrides.yaml` to ensure Windows compatibility.

### Monitoring Scripts
PowerShell scripts located in `scripts/` automate the deployment, start, stop, and status checking of the Suricata service.

### Testing Suite
Located in `tests/`, this includes various PowerShell and Python scripts to simulate malicious traffic (e.g., Ping Floods, Brute Force, Web Attacks) locally for verifying rules.

### Dashboard
A Streamlit web application in `dashboard/app.py` that visualizes alerts and metrics parsed from Suricata's `eve.json` log file.

### Response Engine
`response/response.py` constantly monitors `eve.json` for high-severity alerts and can actively modify Windows Firewall rules to block attacking IP addresses when run in `--live` mode.

## Troubleshooting

- **Npcap not found**: Copy `wpcap.dll` and `Packet.dll` from `C:\Windows\System32\Npcap\` to the Suricata installation directory (`C:\Program Files\Suricata`).
- **Interface names**: Use `suricata.exe --list-interfaces` to find the correct interface names for your machine.
- **Permission denied**: Ensure you are running PowerShell as Administrator.
- **Rules not loading**: Verify that the paths in `suricata.yaml` and `suricata-overrides.yaml` use forward slashes (`/`), not backslashes.
- **No alerts appearing**: 
  - Verify that `HOME_NET` in your configuration includes your subnet.
  - Check that Suricata is capturing on the correct interface (e.g., the loopback adapter for local tests).
- **Loopback capture**: Ensure you use the Npcap Loopback Adapter for localhost traffic, or use pcap replay as a fallback.
- **Dashboard won't start**: Ensure dependencies are installed by running `pip install -r requirements.txt` before starting the dashboard.
- **Firewall blocking**: The response engine must be run in an Administrator PowerShell session for live mode to successfully add firewall rules.
