import socket
import sys

print("Starting DNS Blocklist Simulation")

malicious_domains = [
    "malware.testdomain.local",
    "evil.example.com",
    "c2.malware-domain.test"
]

for domain in malicious_domains:
    print(f"Attempting to resolve: {domain}")
    try:
        # We don't care if it fails, the query is what matters
        socket.getaddrinfo(domain, 80)
    except socket.gaierror:
        print(f"  -> Resolution failed (Expected)")
    except Exception as e:
        print(f"  -> Error: {e}")

print("DNS Blocklist Simulation Complete.")
