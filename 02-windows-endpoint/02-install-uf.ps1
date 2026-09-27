# 02-windows-endpoint / 02-install-uf.ps1
# Silent install of the Splunk Universal Forwarder, pointed at the Mac indexer
# (<mac-ip>:9997). Uses the pinned UF 10.4.3 build from Splunk downloads.
#
# Run as Administrator on the Windows 11 VM.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# ---- Config (override with env vars if needed) -----------------------------
$SplunkHost   = if ($env:SPLUNK_HOST_IP) { $env:SPLUNK_HOST_IP } else { Read-Host 'Mac/Splunk IP reachable from this VM' }
$ReceivePort  = if ($env:SPLUNK_RECEIVE_PORT) { $env:SPLUNK_RECEIVE_PORT } else { '9997' }
$UFIndex      = if ($env:SPLUNK_INDEX) { $env:SPLUNK_INDEX } else { 'soc_capstone' }
$UFVersion    = '10.4.3'
$UFBuild      = '4174a2deda5d'
$UFUrl        = "https://download.splunk.com/products/universalforwarder/releases/$UFVersion/windows/splunkforwarder-$UFVersion-$UFBuild-windows-x64.msi"
$UFMsi        = "$env:TEMP\splunkforwarder.msi"
$UFHome       = "C:\Program Files\SplunkUniversalForwarder"

$parsedSplunkHost = $null
if (-not [System.Net.IPAddress]::TryParse($SplunkHost, [ref]$parsedSplunkHost)) {
    throw "SPLUNK_HOST_IP must be a valid IP address, received: $SplunkHost"
}

Write-Host "[*] Splunk indexer target : $SplunkHost`:$ReceivePort" -ForegroundColor Cyan
Write-Host "[*] Index                 : $UFIndex" -ForegroundColor Cyan
Write-Host "[*] Downloading UF $UFVersion (current build)..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $UFUrl -OutFile $UFMsi -UseBasicParsing

# Silent install args:
#  /q                       unattended
#  AGREETOLICENSE=Yes        accept EULA
#  RECEIVING_INDEXER=ip:port points the UF at the Mac receiver on first boot
#  SPLUNKUSERNAME/PASSWORD   local UF admin (forwarder rarely needs UI login,
#                            but set a throwaway so install doesn't prompt)
Write-Host "[*] Running unattended msiexec install..." -ForegroundColor Cyan
$ufPassword = Read-Host 'Choose a local Universal Forwarder admin password' -AsSecureString
$ufPasswordText = [System.Net.NetworkCredential]::new('', $ufPassword).Password
$msiArgs = @(
    "/i", $UFMsi,
    "/q",
    "AGREETOLICENSE=Yes",
    "RECEIVING_INDEXER=$SplunkHost`:$ReceivePort",
    "SPLUNKUSERNAME=admin",
    "SPLUNKPASSWORD=$ufPasswordText",
    "/norestart"
)
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
$ufPasswordText = $null
if ($proc.ExitCode -ne 0) {
    Write-Host "[!] msiexec exit code: $($proc.ExitCode) (1641/3010 = reboot needed)" -ForegroundColor Yellow
}

# ---- Set the default index on the forwarder side ---------------------------
$outPath = "$UFHome\etc\system\local\outputs.conf"
Write-Host "[*] Writing outputs.conf (defaultGroup -> $SplunkHost`:$ReceivePort, index=$UFIndex)" -ForegroundColor Cyan
@"
[tcpout]
defaultGroup = soc_lab
disabled = false

[tcpout:soc_lab]
server = $SplunkHost`:$ReceivePort

[tcpout:indexedredirect]
index = $UFIndex
"@ | Set-Content -Path $outPath -Encoding ASCII
Copy-Item -Path (Join-Path $PSScriptRoot 'inputs.conf') -Destination "$UFHome\etc\system\local\inputs.conf" -Force

# The LocalSystem service account can read Sysmon's Operational channel.
& sc.exe config SplunkForwarder obj= LocalSystem | Out-Null

# Restart the forwarder so outputs.conf takes effect.
$ufBin = "$UFHome\bin\splunk.exe"
if (Test-Path $ufBin) {
    Write-Host "[*] Restarting forwarder..." -ForegroundColor Cyan
    & $ufBin restart 2>&1 | Out-Null
}

Write-Host "[*] UF install complete. Next: copy inputs.conf and run 03-verify-forwarder.ps1" -ForegroundColor Green
