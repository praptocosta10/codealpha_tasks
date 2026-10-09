import os
import sys
import time
import json
import argparse
import subprocess

def get_eve_line_count(eve_path):
    if not os.path.exists(eve_path):
        return 0
    with open(eve_path, 'r', encoding='utf-8') as f:
        return sum(1 for _ in f)

def parse_eve_for_alerts(eve_path, start_line):
    if not os.path.exists(eve_path):
        return set()
    detected_sids = set()
    with open(eve_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i < start_line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    sid = event.get("alert", {}).get("signature_id")
                    if sid:
                        detected_sids.add(sid)
            except json.JSONDecodeError:
                pass
    return detected_sids

def main():
    parser = argparse.ArgumentParser(description="Run all NIDS tests.")
    parser.add_argument('--pcap-mode', action='store_true', help='Use pcap replay instead of live tests')
    
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(tests_dir)
    default_eve_path = os.path.join(project_root, 'logs', 'eve.json')
    parser.add_argument('--eve-path', type=str, default=default_eve_path, help='Path to eve.json log file')
    
    args = parser.parse_args()
    eve_path = args.eve_path
    
    suricata_home = os.environ.get('SURICATA_HOME', r'C:\Program Files\Suricata')
    suricata_exe = os.path.join(suricata_home, 'suricata.exe')
    suricata_config = os.path.join(project_root, 'config', 'suricata-overrides.yaml')
    
    # Record starting line in eve.json
    start_line = get_eve_line_count(eve_path)
    print(f"Initial eve.json line count: {start_line}")

    if args.pcap_mode:
        print("Running in PCAP mode...")
        pcap_script = os.path.join(tests_dir, "generate_pcap.py")
        pcap_file = os.path.join(tests_dir, "attack_samples.pcap")
        
        # 1. Generate pcap
        subprocess.run([sys.executable, pcap_script], check=True)
        
        # 2. Run Suricata in pcap mode
        cmd = [suricata_exe, "-c", suricata_config, "-r", pcap_file, "-l", os.path.join(project_root, 'logs')]
        print(f"Running Suricata: {' '.join(cmd)}")
        subprocess.run(cmd)
        
        # Wait a bit for processing
        time.sleep(5)
    else:
        print("Running in LIVE mode...")
        # 1. Start local web server
        webserver_script = os.path.join(tests_dir, "local_webserver.py")
        print("Starting local web server...")
        server_proc = subprocess.Popen([sys.executable, webserver_script])
        
        # 2. Wait 2 seconds
        time.sleep(2)
        
        try:
            # 3. Run each test script
            scripts = [
                (["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(tests_dir, "test_portscan.ps1")], "Port Scan"),
                (["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(tests_dir, "test_ping_flood.ps1")], "Ping Flood"),
                (["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(tests_dir, "test_bruteforce.ps1")], "RDP Brute-Force"),
                (["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(tests_dir, "test_web_attacks.ps1")], "Web Attacks"),
                ([sys.executable, os.path.join(tests_dir, "test_dns.py")], "DNS Blocklist"),
                ([sys.executable, os.path.join(tests_dir, "test_ftp_cleartext.py")], "FTP Cleartext"),
            ]
            
            for cmd, name in scripts:
                print(f"\n--- Running {name} Test ---")
                subprocess.run(cmd)
                time.sleep(1) # small pause between tests
                
        finally:
            # 4. Stop web server
            print("\nStopping local web server...")
            server_proc.terminate()
            server_proc.wait()
            
        print("\nWaiting 5 seconds for Suricata to flush logs...")
        time.sleep(5)

    print("\nAnalyzing results...")
    detected_sids = parse_eve_for_alerts(eve_path, start_line)

    rules_expected = [
        (1000001, "Nmap SYN", "Port Scan"),
        (1000002, "Ping Flood", "ICMP Flood"),
        (1000003, "RDP Brute-Force", "RDP SYN Spam"),
        (1000004, "SQLi (UNION)", "Web Attack"),
        (1000005, "Dir Traversal", "Web Attack"),
        (1000006, "Suspicious UA", "Web Attack"),
        (1000007, "DNS Blocklist", "DNS Malicious"),
        (1000008, "FTP Cleartext", "FTP User/Pass"),
        (1000009, "SQLi (DROP)", "Web Attack"),
        (1000010, "DirBuster UA", "Web Attack"),
        (1000011, "DNS C2", "DNS Malicious"),
        (1000012, "FTP Cleartext", "FTP User/Pass"),
    ]

    print("-" * 65)
    print(f"{'Rule SID':<10} | {'Rule Name':<15} | {'Test':<15} | {'Detected':<10}")
    print("-" * 65)
    
    all_detected = True
    for sid, name, test in rules_expected:
        detected = "YES" if sid in detected_sids else "NO"
        if detected == "NO":
            all_detected = False
        print(f"{sid:<10} | {name:<15} | {test:<15} | {detected:<10}")
    print("-" * 65)

    if all_detected:
        print("\nSUCCESS: All expected rules triggered.")
        sys.exit(0)
    else:
        print("\nWARNING: Not all rules triggered. Check Suricata logs or rules configuration.")
        sys.exit(1)

if __name__ == "__main__":
    main()
