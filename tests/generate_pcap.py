import sys
import os

try:
    from scapy.all import IP, TCP, ICMP, UDP, DNS, DNSQR, wrpcap, Ether, Raw
except ImportError:
    print("Scapy not found. Install it with: pip install scapy")
    sys.exit(1)

def generate_pcap(output_file):
    print("Generating PCAP file with attack samples...")
    packets = []

    # Common IP header
    ip = IP(src="10.0.0.100", dst="10.0.0.1")
    eth = Ether()

    # 1. SYN scan: 50 TCP SYN packets to different ports
    print("Adding SYN scan packets...")
    for port in range(1, 51):
        packets.append(eth / IP(src="10.0.0.100", dst="10.0.0.1") / TCP(dport=port, flags="S"))

    # 2. ICMP flood: 100 ICMP echo-request packets
    print("Adding ICMP flood packets...")
    for _ in range(100):
        packets.append(eth / IP(src="10.0.0.100", dst="10.0.0.1") / ICMP(type=8, code=0) / Raw(b"X" * 64))

    # 3. RDP brute-force: 10 TCP SYN packets to port 3389
    print("Adding RDP brute-force packets...")
    for _ in range(10):
        packets.append(eth / IP(src="10.0.0.100", dst="10.0.0.1") / TCP(dport=3389, flags="S"))

    # 4. HTTP with SQLi payload in URI
    print("Adding HTTP SQLi packet...")
    http_sqli = eth / ip / TCP(dport=80, flags="PA") / Raw(b"GET /search?id=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
    packets.append(http_sqli)

    # 5. HTTP with directory traversal in URI
    print("Adding HTTP Directory Traversal packet...")
    http_dt = eth / ip / TCP(dport=80, flags="PA") / Raw(b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
    packets.append(http_dt)

    # 6. HTTP with sqlmap User-Agent
    print("Adding HTTP suspicious User-Agent packet...")
    http_ua = eth / ip / TCP(dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: sqlmap/1.5.2\r\n\r\n")
    packets.append(http_ua)

    # 7. DNS query for malware.testdomain.local
    print("Adding DNS query packet...")
    dns_query = eth / ip / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="malware.testdomain.local"))
    packets.append(dns_query)

    # 8. FTP USER/PASS commands
    print("Adding FTP credentials packet...")
    ftp_user = eth / ip / TCP(dport=21, flags="PA") / Raw(b"USER testuser\r\n")
    ftp_pass = eth / ip / TCP(dport=21, flags="PA") / Raw(b"PASS testpassword123\r\n")
    packets.append(ftp_user)
    packets.append(ftp_pass)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    wrpcap(output_file, packets)
    print(f"Generated {len(packets)} packets and saved to: {output_file}")

if __name__ == "__main__":
    output_path = os.path.join(os.path.dirname(__file__), "attack_samples.pcap")
    generate_pcap(output_path)
