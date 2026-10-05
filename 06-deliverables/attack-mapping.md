# Attack Mapping — Simulated Techniques

| # | Label | Description | Tactic | Script | Target | Detection source / Event IDs |
|---|-------|-------------|--------|--------|--------|------------------------------|
| a | **Attk101** | SSH password guessing | Credential access | `Attk101_psuedoattacks.py` (paramiko) | Kali SSH | `auth.log` `Failed password`; 4625 if RDP |
| b | **Attk102** | Local administrator creation | Persistence | `Attk102_psuedoattacks.ps1` | Windows | Security EID 4720 (created), 4732 (added to Administrators) |
| c | **Attk103** | PowerShell download-and-execute | Execution | `Attk103_psuedoattacks.ps1` | Windows | Sysmon EID 1 (PowerShell w/ DownloadString), EID 3 (to payload host) |
| d | **Attk104** | Clear Windows Security log | Defense evasion | `Attk104_psuedoattacks.ps1` (`wevtutil cl`) | Windows | Security EID 1102, Sysmon EID 4 |

## Splunk detection mapping
| Label | Saved search | Sourcetype / Event IDs |
|-------|-------------|------------------------|
| Attk101 | `SOC - Attk101 SSH Password Attempts (Linux)` / `SOC - Attk101 Windows Failed Logons (4625)` | `linux_secure`; `WinEventLog:Security` 4625 |
| Attk102 | `SOC - Attk102 Local Account Created` / `SOC - Attk102 Account Added to Administrators` | `WinEventLog:Security` 4720, 4728, 4732 |
| Attk103 | `SOC - Attk103 PowerShell Download Cradle` / `SOC - Attk103 Network Connect From PowerShell` | Sysmon Operational EID 1, 3 |
| Attk104 | `SOC - Attk104 Security Log Cleared` | Security EID 1102, Sysmon EID 4 |