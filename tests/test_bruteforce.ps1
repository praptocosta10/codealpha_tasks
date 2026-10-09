Write-Host "Starting RDP Brute-Force Simulation against localhost:3389"
$target = "127.0.0.1"
$port = 3389

# Rapidly attempt 15 TCP connections
for ($i = 1; $i -le 15; $i++) {
    Write-Host "Attempt $i to connect to $target`:$port"
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($target, $port)
        $tcp.Close()
    } catch {
        # Connection might fail, that's fine, the SYN was still sent
        Write-Host "  -> Connection refused or timeout (Expected)"
    }
    Start-Sleep -Milliseconds 100
}

Write-Host "RDP Brute-Force Simulation Complete."
