import os
import time
import json
import argparse
import subprocess
import threading
import ipaddress
import signal
import sys
from datetime import datetime

# Default allowlist of networks that should never be blocked
ALLOWLIST_NETWORKS = [
    '127.0.0.1/32',
    '::1/128',
    '0.0.0.0/32',
    '192.168.0.0/16',
    '10.0.0.0/8'
]

# Track currently blocked IPs to avoid duplicate rules
blocked_ips = set()
running = True

def signal_handler(sig, frame):
    """Handles graceful shutdown on Ctrl+C"""
    global running
    print("\n[INFO] Graceful shutdown initiated. Stopping response engine...")
    running = False
    sys.exit(0)

def is_allowlisted(ip_str):
    """Checks if an IP address is within the allowlisted networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network_str in ALLOWLIST_NETWORKS:
            network = ipaddress.ip_network(network_str)
            if ip in network:
                return True
        return False
    except ValueError:
        print(f"[ERROR] Invalid IP address encountered: {ip_str}")
        return False

def unblock_ip(ip, log_path):
    """Removes the firewall rule for a given IP."""
    global blocked_ips
    if ip in blocked_ips:
        blocked_ips.remove(ip)
    
    cmd = f"powershell -Command \"Remove-NetFirewallRule -DisplayName 'NIDS-Block-{ip}' -ErrorAction SilentlyContinue\""
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_action(log_path, "UNBLOCK", ip, "IP auto-unblocked after timeout")
        print(f"[{datetime.now().isoformat()}] [INFO] Unblocked IP: {ip}")
    except Exception as e:
        print(f"[ERROR] Failed to unblock {ip}: {e}")

def log_action(log_path, action, ip, details):
    """Logs the action taken to a JSON file."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "ip": ip,
        "details": details
    }
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write to response log: {e}")

def block_ip(ip, is_live, timeout, log_path, no_allowlist):
    """Executes the block action for an IP address."""
    if not no_allowlist and is_allowlisted(ip):
        log_action(log_path, "SKIP", ip, "IP is in allowlist")
        print(f"[{datetime.now().isoformat()}] [WARN] Skipped blocking {ip} (Allowlisted)")
        return

    if ip in blocked_ips:
        return # Already blocked, skip
    
    if not is_live:
        log_action(log_path, "DRY-RUN", ip, "Would block IP")
        print(f"[{datetime.now().isoformat()}] [DRY-RUN] Would block IP: {ip}")
        return

    # Live blocking
    blocked_ips.add(ip)
    cmd = f"powershell -Command \"New-NetFirewallRule -DisplayName 'NIDS-Block-{ip}' -Direction Inbound -Action Block -RemoteAddress {ip} -Profile Any\""
    
    print(f"[{datetime.now().isoformat()}] [BLOCK] Blocking IP: {ip} (Requires Admin rights)")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Firewall rule failed for {ip}: {result.stderr}")
            blocked_ips.remove(ip)
            return
            
        log_action(log_path, "BLOCK", ip, f"Blocked for {timeout} seconds")
        
        # Schedule auto-unblock
        timer = threading.Timer(timeout, unblock_ip, args=[ip, log_path])
        timer.daemon = True
        timer.start()
        print(f"[{datetime.now().isoformat()}] [INFO] Scheduled auto-unblock for {ip} in {timeout}s")
        
    except Exception as e:
        blocked_ips.remove(ip)
        print(f"[ERROR] Failed to execute firewall command: {e}")

def tail_eve_json(eve_path, log_path, is_live, timeout, no_allowlist):
    """Tails the Suricata eve.json log file and processes alerts."""
    
    if not os.path.exists(eve_path):
        print(f"[WARN] File not found: {eve_path}. Waiting for it to be created...")
        while not os.path.exists(eve_path) and running:
            time.sleep(1)
            
    if not running: return
            
    print(f"[{datetime.now().isoformat()}] [INFO] Tailing {eve_path}...")
    
    with open(eve_path, "r", encoding="utf-8") as f:
        # Seek to the end of the file initially
        f.seek(0, os.SEEK_END)
        
        while running:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
                
            try:
                event = json.loads(line.strip())
                
                # Check if it's an alert
                if event.get("event_type") == "alert":
                    alert_data = event.get("alert", {})
                    severity = alert_data.get("severity", 3)
                    src_ip = event.get("src_ip")
                    msg = alert_data.get("signature", "Unknown Alert")
                    
                    # High severity filtering (severity <= 2)
                    if severity <= 2 and src_ip:
                        print(f"[{datetime.now().isoformat()}] [ALERT] Sev {severity} from {src_ip}: {msg}")
                        block_ip(src_ip, is_live, timeout, log_path, no_allowlist)
                        
            except json.JSONDecodeError:
                continue

def main():
    parser = argparse.ArgumentParser(description="NIDS Automated Response Script")
    parser.add_argument("--live", action="store_true", help="Enable live blocking (default: dry-run)")
    parser.add_argument("--timeout", type=int, default=300, help="Auto-unblock timeout in seconds (default: 300)")
    parser.add_argument("--no-allowlist", action="store_true", help="Disable allowlist checks")
    parser.add_argument("--eve-path", type=str, default=r"C:\NIDS\logs\eve.json", help="Path to eve.json")
    parser.add_argument("--log-path", type=str, default=r"C:\NIDS\logs\response_log.json", help="Path to response log")
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    mode = "LIVE" if args.live else "DRY-RUN"
    print(f"Starting NIDS Response Engine in {mode} mode")
    print(f"Eve JSON path: {args.eve_path}")
    print(f"Response log path: {args.log_path}")
    if args.live:
        print("Note: Live blocking requires Administrative privileges.")
        
    tail_eve_json(args.eve_path, args.log_path, args.live, args.timeout, args.no_allowlist)

if __name__ == "__main__":
    main()
