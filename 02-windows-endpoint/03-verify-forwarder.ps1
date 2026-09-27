# 02-windows-endpoint / 03-verify-forwarder.ps1
# Verification checklist (no GUI): confirms the UF service is running, the
# receiver is reachable, Sysmon is producing events, and the forwarder has
# actually shipped bytes to the indexer. Run on the Windows VM.
$ErrorActionPreference = 'Continue'
$SplunkHost  = if ($env:SPLUNK_HOST_IP) { $env:SPLUNK_HOST_IP } else { Read-Host 'Mac/Splunk IP reachable from this VM' }
$ReceivePort = if ($env:SPLUNK_RECEIVE_PORT) { $env:SPLUNK_RECEIVE_PORT } else { '9997' }
$UFHome      = "C:\Program Files\SplunkUniversalForwarder"

$parsedSplunkHost = $null
if (-not [System.Net.IPAddress]::TryParse($SplunkHost, [ref]$parsedSplunkHost)) {
    throw "SPLUNK_HOST_IP must be a valid IP address, received: $SplunkHost"
}

function Check($label, $ok, $detail='') {
    $c = if ($ok) { 'Green' } else { 'Red' }
    $mark = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("  [{0}] {1}  {2}" -f $mark, $label, $detail) -ForegroundColor $c
}

Write-Host "`n=== Splunk UF Verification (Windows) ===" -ForegroundColor Cyan

# 1. UF service
$svc = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
Check "UF service installed" ([bool]$svc) ($svc.Status)
if ($svc) { Check "UF service running" ($svc.Status -eq 'Running') }

# 2. Receiver reachability (TCP 9997 to the Mac)
$tcp = Test-NetConnection -ComputerName $SplunkHost -Port $ReceivePort -WarningAction SilentlyContinue
Check "Receiver $SplunkHost`:$ReceivePort reachable" $tcp.TcpTestSucceeded

# 3. Sysmon service + recent event volume
$smon = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
Check "Sysmon service running" ($smon -and $smon.Status -eq 'Running')
try {
    $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
    Check "Sysmon Operational producing events" ($events.Count -ge 1) ("last event: $($events.TimeCreated)")
} catch {
    Check "Sysmon Operational producing events" $false "no events / log not enabled"
}

# 4. Security log enabled (needed for 4624/4625 brute-force detection)
$sec = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
Check "Security log enabled" ($sec -and $sec.IsEnabled)

# 5. Forwarder metric: bytes queued/sent (from metrics.log)
Start-Sleep -Seconds 1
$metrics = "$UFHome\var\log\splunk\metrics.log"
if (Test-Path $metrics) {
    $last = Get-Content $metrics -Tail 50 | Select-String 'group=tcpout_connections'
    Check "Forwarder has tcpout connection to indexer" ([bool]$last)
    if ($last) { Write-Host "    sample: $($last[0])" -ForegroundColor DarkGray }
} else {
    Check "metrics.log present" $false "$metrics missing"
}

# 6. splunkd process alive
$pd = Get-Process -Name splunkd -ErrorAction SilentlyContinue
Check "splunkd process alive" ([bool]$pd)

Write-Host "`nIf any FAIL: check outputs.conf host/port, the Mac receiver (setup-splunk-macos.sh),`nand that the macOS app firewall isn't blocking 9997.`n" -ForegroundColor Yellow
