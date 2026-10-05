#!/usr/bin/env python3
"""Continuous detection scanner.
Queries Splunk for each check, tags red/blue with per-attack timestamps,
writes detection/status.json.

Usage:  python3 detection/scan.py            # one shot
        python3 detection/scan.py --watch    # every 30s
"""
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLUNK = os.environ.get("SPLUNK_BIN", "/Applications/Splunk/bin/splunk")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
OUT = ROOT / "detection" / "status.json"
INTERVAL = 30

CHECKS = [
    ("SSH brute force", 'sourcetype=linux_secure "Failed password"', 10),
    ("Windows 4625", 'EventCode=4625', 5),
    ("Account created", 'sourcetype=WinEventLog:Security EventCode=4720', 1),
    ("Admin group add", 'sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4738)', 1),
    ("PS download cradle", 'DownloadString', 1),
    ("PS network", 'sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "EventID>3<"', 1),
    ("Log cleared", 'sourcetype=WinEventLog:Security EventCode=1102', 1),
]

def splunk(cmd):
    if not SPLUNK_PASSWORD:
        raise SystemExit("Set SPLUNK_PASSWORD before running detection/scan.py")
    try:
        r = subprocess.run([SPLUNK, "search", cmd, "-auth", f"{SPLUNK_USER}:{SPLUNK_PASSWORD}"], capture_output=True, text=True, timeout=25)
        out = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("WARNING") and not l.startswith("INFO")]
        return out
    except subprocess.SubprocessError:
        return []

def get_count(name, query, threshold):
    q = f'index=soc_capstone {query} | stats count'
    out = splunk(q)
    for l in out:
        for p in l.split():
            if p.isdigit():
                n = int(p)
                return ("red" if n >= threshold else "blue", n)
    return ("blue", 0)

def get_ts(query):
    q = f'index=soc_capstone {query} | head 1 | table _time'
    out = splunk(q)
    for l in out:
        parts = l.split()
        if len(parts) >= 2 and "-" in parts[0] and ":" in parts[1]:
            return f"{parts[0]}T{parts[1].split('.')[0]}"
    return "-"

def scan():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries = []
    reds = 0
    for name, query, threshold in CHECKS:
        tag, count = get_count(name, query, threshold)
        ts = get_ts(query) if count > 0 else "-"
        if tag == "red": reds += 1
        entries.append({"check": name, "tag": tag, "count": count, "last_event": ts, "threshold": threshold})

    blues = len(entries) - reds
    risk = "elevated" if reds > 0 else "normal"
    status = {
        "scanned_at": now,
        "risk": risk,
        "summary": f"{reds} red / {blues} blue",
        "checks": entries
    }
    OUT.write_text(json.dumps(status, indent=2))
    return status

def push():
    os.chdir(ROOT)
    subprocess.run(["git", "add", "detection/status.json"], capture_output=True)
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        return
    subprocess.run(["git", "commit", "-m", "Update generated detection status"], check=False)
    subprocess.run(["git", "push", "origin", "main"], check=False)

if __name__ == "__main__":
    watch = "--watch" in sys.argv or "-w" in sys.argv
    auto_push = "--push" in sys.argv or "-p" in sys.argv
    if watch:
        print(f"Scanning every {INTERVAL}s. Ctrl+C to stop.")
        while True:
            s = scan()
            print(f"[{s['scanned_at']}] {s['summary']} — risk: {s['risk']}")
            if auto_push:
                push()
            time.sleep(INTERVAL)
    else:
        s = scan()
        print(f"[{s['scanned_at']}] {s['summary']} — risk: {s['risk']}")
        if auto_push:
            push()
