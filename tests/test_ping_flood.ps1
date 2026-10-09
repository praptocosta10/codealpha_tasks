Write-Host "Starting ICMP Ping Flood Simulation against localhost (127.0.0.1)"
Write-Host "Sending 100 ICMP echo requests..."

# Send 100 rapid pings
ping -n 100 -l 64 127.0.0.1

Write-Host "ICMP Ping Flood Simulation Complete."
