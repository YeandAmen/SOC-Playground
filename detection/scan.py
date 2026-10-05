#!/usr/bin/env python3
"""SOC Playground status scanner.
Queries Splunk saved searches, tags each as red (attack detected) or blue (normal),
writes detection/status.json for GitHub + SOC analyst review.

Usage:
  python3 detection/scan.py
  python3 detection/scan.py --commit   # auto-commit & push to GitHub
"""
import json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLUNK_BIN = "/Applications/Splunk/bin/splunk"
AUTH = "admin:Denymenot2"
OUT = ROOT / "detection" / "status.json"

SEARCHES = {
    "SSH brute force": 'index=soc_capstone sourcetype=linux_secure "Failed password" | stats count as total by host | eval threshold=if(total>=10,1,0) | table host total threshold',
    "Windows 4625": 'index=soc_capstone EventCode=4625 | stats count as total by ComputerName | eval threshold=if(total>=5,1,0) | table ComputerName total threshold',
    "Account created": 'index=soc_capstone sourcetype=WinEventLog:Security EventCode=4720 | stats count as total by host | eval threshold=1 | table host total',
    "Admin group add": 'index=soc_capstone sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4738) | stats count as total by host | eval threshold=1 | table host total',
    "PS download cradle": 'index=soc_capstone DownloadString | stats count as total by host | eval threshold=1 | table host total',
    "PS network": 'index=soc_capstone sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "EventID>3<" | stats count as total by host | eval threshold=1 | table host total',
    "Log cleared": 'index=soc_capstone sourcetype=WinEventLog:Security EventCode=1102 | stats count as total by host | eval threshold=1 | table host total',
}

def run(query):
    try:
        r = subprocess.run([SPLUNK_BIN, "search", query, "-auth", AUTH], capture_output=True, text=True, timeout=30)
        out = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("WARNING") and not l.startswith("INFO")]
        return out
    except Exception as e:
        return [f"ERROR: {e}"]

def tag(results):
    if not results or len(results) < 2:
        return "blue", 0
    for line in results:
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            n = int(parts[-1])
            return ("red", n) if n > 0 else ("blue", n)
    return "blue", 0

def main():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries = []
    total_red = 0
    total_blue = 0
    for name, query in SEARCHES.items():
        out = run(query)
        color, count = tag(out)
        if color == "red":
            total_red += 1
        else:
            total_blue += 1
        entries.append({"check": name, "tag": color, "count": count, "raw": out[:3]})

    status = {
        "timestamp": ts,
        "summary": f"{total_red} red / {total_blue} blue",
        "tags": entries,
        "risk": "elevated" if total_red > 0 else "normal"
    }
    OUT.write_text(json.dumps(status, indent=2))
    print(f"[{ts}] {status['summary']} — risk: {status['risk']}")
    print(f"Wrote {OUT}")

    if "--commit" in sys.argv:
        os.chdir(ROOT)
        subprocess.run(["git", "add", "detection/status.json"], capture_output=True)
        subprocess.run(["git", "commit", "-m", "update status"], capture_output=True)
        r = subprocess.run(["git", "push"], capture_output=True, text=True)
        print("Push:", r.stdout.strip()[-60:] if r.stdout else r.stderr.strip()[-60:])

if __name__ == "__main__":
    main()