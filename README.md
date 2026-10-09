# codealpha_tasks
# NIDS: Network Intrusion Detection System

A network intrusion detection system built on **Suricata** with custom detection rules and a real-time **Streamlit** dashboard. Suricata inspects traffic and writes alerts to `eve.json`, and the dashboard reads that log and visualizes the alerts as they arrive.

## Features

- **Custom Suricata rules**: 12 signatures in `rules/local.rules` (SIDs from 1000001), including DNS queries to blocklisted domains and SYN-only probes to sensitive ports such as RDP
- **Real-time dashboard**: alert counters, alerts over time, top source IPs, top signatures, severity breakdown, and a recent-alerts table, with auto-refresh and severity filters
- **Attack simulation**: Scapy-based generator that builds a test `.pcap` of attack traffic, plus test scripts for several attack types
- **Management scripts**: PowerShell scripts to set up, start, stop and check the IDS
- **Automated response module** (`response/`)
- **One-click launcher** for replaying the test traffic and opening the dashboard

## Architecture

```
Traffic / test .pcap  ->  Suricata (custom rules)  ->  eve.json + fast.log  ->  Streamlit dashboard
```

## Project Structure

```
NIDS/
├── config/        Suricata configuration overrides
├── rules/         Custom detection rules (local.rules)
├── scripts/       setup / start / stop / status (PowerShell)
├── tests/         Attack simulations and pcap generator
├── response/      Automated response module
├── dashboard/     Streamlit dashboard (app.py)
├── docs/          Project documentation and report
├── logs/          Suricata output (eve.json, fast.log)
└── requirements.txt
```

## Requirements

- Windows 10/11
- [Suricata](https://suricata.io/download/) 8.x
- [Npcap](https://npcap.com) (required for live capture)
- Python 3.10+

## Setup

```powershell
git clone <your-repo-url> C:\NIDS
cd C:\NIDS
pip install -r requirements.txt
```

## Usage

**Replay the test attack traffic through Suricata:**

```powershell
& "C:\Program Files\Suricata\suricata.exe" -c "C:\NIDS\config\suricata-overrides.yaml" -S "C:\NIDS\rules\local.rules" -r "C:\NIDS\tests\attack_samples.pcap" -l "C:\NIDS\logs"
```

**Start the dashboard:**

```powershell
streamlit run C:\NIDS\dashboard\app.py
```

Then open <http://localhost:8501> and click **Refresh Now**.

For live monitoring, run `scripts\start-ids.ps1` from a PowerShell window opened as Administrator.

## Results

Replaying the generated test pcap (166 packets) triggers the custom rule **"DNS Query to Blocklisted Domain"**, and the alert appears on the dashboard with its source IP, destination, protocol, signature and severity.

## Limitations

- The test pcap is synthetic and built offline, so only rules that match single packets fire. Rules that depend on full connections or repeated attempts need live or replayed real traffic.
- Replaying the same pcap twice logs the same alert twice.
- The dashboard's "High Severity" counter does not exactly match the severity breakdown chart (known minor bug).

## Ethical Use

Only test and monitor networks and devices you own or have permission to monitor. The attack simulations are for local testing against your own machine.

## Tech Stack

Suricata · Python · Streamlit · Scapy · PowerShell

## Author

Prapto Costa
