Write-Host "Starting Web Attacks Simulation against local web server"
Write-Host "NOTE: Make sure local_webserver.py is running on port 8080 before running this script."
Start-Sleep -Seconds 1

$base_url = "http://127.0.0.1:8080"

Write-Host "`n--- Testing SQL Injection (SID 1000004, 1000009) ---"
$urls = @(
    "$base_url/search?id=1'+UNION+SELECT+username,password+FROM+users--",
    "$base_url/login?user=admin'OR+1=1--",
    "$base_url/page?id=1;+DROP+TABLE+users"
)
foreach ($url in $urls) {
    Write-Host "Running: curl.exe -s `"$url`""
    curl.exe -s "$url" | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "`n--- Testing Directory Traversal (SID 1000005) ---"
$urls = @(
    "$base_url/../../../../etc/passwd",
    "$base_url/..%2F..%2F..%2Fetc%2Fpasswd",
    "$base_url/files?path=../../windows/system32/config/sam"
)
foreach ($url in $urls) {
    Write-Host "Running: curl.exe -s `"$url`""
    curl.exe -s "$url" | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "`n--- Testing Suspicious User-Agents (SID 1000006, 1000010) ---"
$user_agents = @(
    @("sqlmap/1.5.2", "$base_url/"),
    @("Nikto/2.1.6", "$base_url/admin"),
    @("DirBuster-1.0", "$base_url/secret")
)
foreach ($ua in $user_agents) {
    $agent = $ua[0]
    $url = $ua[1]
    Write-Host "Running: curl.exe -s -A `"$agent`" `"$url`""
    curl.exe -s -A "$agent" "$url" | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "`nWeb Attacks Simulation Complete."
