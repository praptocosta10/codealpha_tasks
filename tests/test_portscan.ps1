Write-Host "Starting Port Scan Simulation against localhost (127.0.0.1)"
$target = "127.0.0.1"

# Check if nmap is available
$nmap_path = Get-Command "nmap" -ErrorAction SilentlyContinue

if ($nmap_path) {
    Write-Host "Nmap found. Running SYN scan on ports 1-100..."
    nmap -sS -p 1-100 $target
} else {
    Write-Host "Nmap not found. Using fallback: System.Net.Sockets.TcpClient for ports 1-100..."
    for ($port = 1; $port -le 100; $port++) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $async = $tcp.BeginConnect($target, $port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(50, $false)
            if ($wait -and $tcp.Connected) {
                Write-Host "Port $port is open."
            }
            $tcp.Close()
        } catch {
            # Ignore errors
        }
    }
}
Write-Host "Port Scan Simulation Complete."
