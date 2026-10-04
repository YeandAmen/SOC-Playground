# Project 3: SIEM Deployment — SOC Playground

## 1. Executive Summary

A fully functional Security Operations Center (SOC) laboratory was built using Splunk Enterprise as the SIEM platform. The lab monitors two endpoints (Windows 11 and Kali Linux) from a macOS host running Splunk. Four simulated attacks were executed, detected by Splunk SPL, and visualized through a real-time console. All infrastructure is code-driven and repeatable via the SOC-Playground GitHub repository.

## 2. Architecture Overview

| Node | IP | Role | Software |
|------|-----|------|----------|
| macOS host | 192.168.64.1 | SIEM manager (indexer, search head, receiver) | Splunk Enterprise 10.2.6 |
| Windows 11 VM | 192.168.64.2 | Victim endpoint | Sysmon + Splunk Universal Forwarder |
| Kali Linux VM | 192.168.64.4 | Attacker + monitored endpoint | Splunk Universal Forwarder |

Data flow: Both VMs forward logs via TCP 9997 to the Mac receiver. The Mac indexes into the dedicated `soc_capstone` index. The SignalScope console queries Splunk's REST API on 8089 and renders a live waveform.

## 3. Splunk Manager Setup

Splunk Enterprise 10.2.6 was installed on the macOS host. The setup script (`01-splunk-manager/setup-splunk-macos.sh`) performs:

- Admin password initialization via `user-seed.conf`
- Splunk start with license acceptance
- Receiver port 9997 enabled
- Dedicated `soc_capstone` index created
- macOS Application Firewall exceptions (if enabled)
- LaunchAgent for auto-start at login
- Port verification (8000 web, 9997 receive, 8089 management)

**Why a dedicated index:** Evidence isolation, independent retention policies, per-index RBAC, and cleaner searches versus the default `main` index.

## 4. Windows Endpoint (192.168.64.2)

The Windows 11 VM was configured with:

### 4.1 Sysmon + SwiftOnSecurity Config
Sysmon (Sysinternals) was installed with the SwiftOnSecurity community configuration, which ships ~300 high-signal rules capturing: process creation with command lines, network connections, file creations, image loads, and registry modifications. This provides significantly richer telemetry than default Windows event logging.

### 4.2 Splunk Universal Forwarder
Installed silently via msiexec with `RECEIVING_INDEXER=192.168.64.1:9997`. The forwarder was reconfigured to run as `LocalSystem` to resolve Sysmon channel ACL issues (errorCode=5). Forwarded logs:

- Security (logon events 4624/4625, account operations 4720/4728/4732)
- System (service installs, driver loads)
- Application (app-level events)
- Sysmon Operational (process/network/file events with XML rendering)

### 4.3 Firewall
Windows outbound firewall rule added for TCP 9997. ProtonVPN was disconnected during lab operation to prevent traffic routing conflicts.

## 5. Kali Linux Endpoint (192.168.64.4)

### 5.1 rsyslog Installation
Kali ships with journald only. rsyslog was installed to produce `/var/log/auth.log` and `/var/log/syslog`.

### 5.2 Splunk Universal Forwarder
Installed via the amd64 .deb package. The `splunkfwd` user was added to the `adm` group for log file read access. Forwarded logs:

- `/var/log/auth.log` as `linux_secure` sourcetype
- `/var/log/syslog` as `syslog` sourcetype

## 6. Attack Simulations

Four attacks were designed and executed, each producing timestamped timeline logs and Splunk-detectable events.

### 6.1 Attk101 — SSH Password Brute Force (Credential Access)
A Python script using paramiko attempted 15 passwords against the Kali SSH service. 14 attempts failed; the 15th succeeded with the correct password. This generated `Failed password` entries in `/var/log/auth.log`.

**Detection:** `sourcetype=linux_secure "Failed password" | stats count by src | where count >= 10`

**Result:** 15 matching events, 1 SSH failure burst detection triggered.

### 6.2 Attk102 — Hidden Local Admin (Persistence)
A local account `playadmin` was created on Windows via `net user playadmin Capstone2026! /add` and added to the Administrators group. This generated Windows Security events 4720 (account created) and 4732 (member added to security group).

**Detection:** `sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4732)`

**Result:** 2 matching events, account change detection triggered.

### 6.3 Attk103 — PowerShell Download-and-Execute (Execution)
A benign marker payload was hosted on the Mac's Splunk Web server. On Windows, PowerShell executed `IEX (New-Object Net.WebClient).DownloadString(...)` to download and execute the payload. This generated Sysmon EID 1 (Process Create) with `DownloadString` in the command line and EID 3 (Network Connect) to port 8000.

**Detection:** `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (DownloadString OR Invoke-WebRequest)`

**Result:** 1 matching event, PowerShell download detection triggered.

### 6.4 Attk104 — Log Wipe (Defense Evasion, provided but not executed)
Script clears the Windows Security log via `wevtutil cl Security`. Documented for use with prior evidence export.

## 7. Detection Implementation

Seven SPL saved searches were deployed as the `soc_capstone_detections` app:

| Search Name | Detection Target |
|------------|------------------|
| `SOC - Attk101 SSH Password Attempts (Linux)` | SSH brute force via auth.log |
| `SOC - Attk101 Windows Failed Logons (4625)` | RDP/SSH brute force via Security log |
| `SOC - Attk102 Local Account Created` | Account creation via EID 4720 |
| `SOC - Attk102 Account Added to Administrators` | Admin group changes via EID 4728/4732/4738 |
| `SOC - Attk103 PowerShell Download Cradle` | PowerShell download via Sysmon EID 1 |
| `SOC - Attk103 Network Connect From PowerShell` | PowerShell outbound via Sysmon EID 3 |
| `SOC - Attk104 Security Log Cleared` | Log clearing via EID 1102 / Sysmon EID 4 |

A Splunk dashboard `SOC Playground — Attack Detection Dashboard` was created with panels for each attack type plus a proof-of-ingestion overview.

## 8. SignalScope Console

A real-time browser console runs on the Mac at `http://127.0.0.1:8765`. It queries Splunk every 5 seconds, renders a 60-bin waveform with smoothed curves, mirrored envelopes, technique-colored traces, and vertical capture threads.

- Backend: Python `http.server` bridge (no external dependencies)
- Frontend: Canvas-based waveform with hover inspection
- Detections: Highlighted with severity-coded cards
- Authentication: Admin password entered once, held in server memory only

**Live results during testing:**
- 18 matching events in 1-hour window
- 3 active detections (Attk101, Attk102, Attk103)
- 2 hosts monitored (WIN-JCNJR9HDAMK, kali)
- Peak density: 14 events/minute (SSH burst)

## 9. Results Summary

| Metric | Value |
|--------|-------|
| Total events indexed | ~43,000+ across 6 sourcetypes |
| Matching telemetry | 18 events (attack-correlated) |
| Detections triggered | 3 of 4 techniques |
| Active forwarders | 2 (Windows + Kali) |
| Splunk dashboard panels | 9 |
| Saved searches | 7 |
| Repo | `github.com/YeandAmen/SOC-Playground` |

## 10. Conclusion

The SOC Playground lab demonstrates a complete SIEM deployment workflow: endpoint instrumentation, log forwarding, centralized indexing, attack simulation, detection engineering, and real-time visualization. All components are automated via scripts and version-controlled in the public repository. The platform is reproducible — any clone with Splunk Enterprise and two lab VMs can rebuild the full environment.