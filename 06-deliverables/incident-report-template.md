# Incident Report — Template (one attack, fully documented)

> Fill in the bracketed fields. This matches a standard SOC capstone rubric:
> detection → analysis → timeline → scope → remediation → lessons learned.
> Replace `<TECHNIQUE>` with the chosen attack (e.g. Attk101 SSH password guessing).

---

## 1. Incident Summary
- **Incident ID:** IR-<YYYYMMDD>-<NN>
- **Title:** <e.g. SSH Brute Force Against Kali Endpoint>
- **Date detected:** <UTC timestamp>
- **Detection source:** Splunk saved search `SOC - Attk101 SSH Password Attempts (Linux)`
- **Severity:** <Low/Med/High/Critical>
- **Status:** <Open/Closed>
- **Analyst:** <name>

## 2. Attack Mapping
| Attack ID | Name | Tactic |
|--------------|------|--------|
| <Attk101> | <SSH password guessing> | <Credential access> |

## 3. Affected Systems
| Hostname | IP | OS | Role |
|----------|----|----|------|
| <kali> | <kali-ip> | Kali | <victim endpoint> |

## 4. Detection Logic (SPL)
```splunk
index=soc_capstone sourcetype=linux_secure "Failed password"
| stats count, dc(user) as users_tried, values(user) as users by src, host
| where count >= 10
| sort - count
```
**Why this works:** groups failed SSH authentications by source IP and fires
when ≥10 failures occur in the window — the canonical brute-force signature.

## 5. Timeline of Events
| Time (UTC) | Event | Source | Evidence |
|------------|-------|--------|----------|
| <ts> | Brute force begins from <src> | `attk101_timeline.log` | `[Attk101] Brute Force START` |
| <ts> | Nth failed login | `auth.log` / Splunk | `Failed password for kali from <src>` |
| <ts> | Valid credential found | `attk101_timeline.log` | `[Attk101] SUCCESS ... pass=<pw>` |
| <ts> | Detection fires | Splunk alert | saved search triggered |
| <ts> | Containment | analyst action | <e.g. firewall block> |

## 6. Raw Log Evidence
```
<Paste 5–10 representative raw events from Splunk / the *_timeline.log>
```

## 7. Analysis / Conclusion
<2–4 sentences: what happened, how confirmed, attacker objective.>

## 8. Impact Assessment
- **Confidentiality:** <e.g. one set of credentials compromised>
- **Integrity:** <e.g. none — access not escalated>
- **Availability:** <e.g. none>

## 9. Remediation
- [ ] Disable / rotate the compromised credential
- [ ] Block attacker source IP at the host firewall
- [ ] Enforce key-based SSH (disable password auth)
- [ ] Add fail2ban / account lockout policy
- [ ] Tune the Splunk detection threshold if FP/TP rate is off

## 10. Lessons Learned / Recommendations
- <e.g. forward `/var/log/auth.log` retention > 7 days>
- <e.g. add a correlation: brute force → successful 4624 within 1h = critical>

## 11. Appendices
- A. Full `attk101_timeline.log`
- B. Splunk search screenshot (PNG)
- C. Dashboard panel screenshot
