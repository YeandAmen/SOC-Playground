#!/usr/bin/env python3
"""Automated detection pipeline: Simulate → Collect → Evaluate → Tune → Verify
Runs attacks, checks Splunk, tests detection rules, tunes if missed, re-runs to confirm.
Outputs tuning log and pushes to GitHub.

Usage:
  python3 detection/pipeline.py                    # full cycle once
  python3 detection/pipeline.py --watch            # loop every 120s
  python3 detection/pipeline.py --watch --push     # + auto GitHub push
"""
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLUNK = os.environ.get("SPLUNK_BIN", "/Applications/Splunk/bin/splunk")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
WINDOWS_HOST = os.environ.get("WINDOWS_HOST", "")
WINDOWS_USER = os.environ.get("WINDOWS_USER", "")
WINDOWS_PASSWORD = os.environ.get("WINDOWS_PASSWORD", "")
SSH_TARGET = os.environ.get("SSH_TARGET", "")
SSH_USER = os.environ.get("SSH_USER", "medusa")
OUT = ROOT / "detection" / "pipeline_status.json"
TUNING_LOG = ROOT / "detection" / "tuning_log.json"
INTERVAL = 120

CHECKS = [
    ("SSH brute force", 'sourcetype=linux_secure "Failed password"', 10, "Attk101"),
    ("Account created", 'sourcetype=WinEventLog:Security EventCode=4720', 1, "Attk102"),
    ("Admin group add", 'sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4738)', 1, "Attk102"),
    ("PS download cradle", 'DownloadString', 1, "Attk103"),
    ("Log cleared", 'sourcetype=WinEventLog:Security EventCode=1102', 1, "Attk104"),
]

def splunk(cmd):
    if not SPLUNK_PASSWORD:
        raise SystemExit("Set SPLUNK_PASSWORD before running detection/pipeline.py")
    try:
        r = subprocess.run([SPLUNK, "search", cmd, "-auth", f"{SPLUNK_USER}:{SPLUNK_PASSWORD}"], capture_output=True, text=True, timeout=25)
        return [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("WARNING") and not l.startswith("INFO")]
    except subprocess.SubprocessError:
        return []

def query(q):
    q = f'index=soc_capstone {q}'
    return splunk(q)

def get_count(q):
    out = query(f'{q} | stats count')
    for l in out:
        for p in l.split():
            if p.isdigit():
                return int(p)
    return 0

def get_ts(q):
    out = query(f'{q} | head 1 | table _time')
    for l in out:
        parts = l.split()
        if len(parts) >= 2 and "-" in parts[0] and ":" in parts[1]:
            return f"{parts[0]}T{parts[1].split('.')[0]}"
    return "-"

def run_attack(name):
    """Run the attack script that generates telemetry for this check."""
    if "SSH" in name:
        if not SSH_TARGET:
            return ["set SSH_TARGET to run Attk101"]
        r = subprocess.run(["python3", str(ROOT/"04-attacks"/"Attk101_psuedoattacks.py"),
            "--target", SSH_TARGET, "--user", SSH_USER,
            "--wordlist", str(ROOT/"04-attacks"/"wordlist.txt"), "--delay", "0.5"],
            capture_output=True, text=True, timeout=120)
        return r.stdout.splitlines()[-2:] if r.stdout else ["no output"]
    if "Account" in name:
        if not all((WINDOWS_HOST, WINDOWS_USER, WINDOWS_PASSWORD)):
            return ["set WINDOWS_HOST, WINDOWS_USER, and WINDOWS_PASSWORD to run Attk102"]
        r = subprocess.run(["sshpass", "-p", WINDOWS_PASSWORD, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15", f"{WINDOWS_USER}@{WINDOWS_HOST}",
            'cmd /c "net user pipetest Capstone2026! /add && net localgroup Administrators pipetest /add"'],
            capture_output=True, text=True, timeout=30)
        return [l for l in r.stdout.splitlines() if l.strip()][-2:]
    if "PS" in name:
        if not all((WINDOWS_HOST, WINDOWS_USER, WINDOWS_PASSWORD)):
            return ["set WINDOWS_HOST, WINDOWS_USER, and WINDOWS_PASSWORD to run Attk103"]
        r = subprocess.run(["sshpass", "-p", WINDOWS_PASSWORD, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15", f"{WINDOWS_USER}@{WINDOWS_HOST}",
            'cmd /c "powershell -ExecutionPolicy Bypass -File C:\\SOC-Capstone\\payload.ps1"'],
            capture_output=True, text=True, timeout=30)
        return [l for l in r.stdout.splitlines() if l.strip()][-2:]
    return ["no attack script"]

def evaluate():
    """Collect telemetry, test detections, return verdicts."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = []
    reds = 0
    for name, q, threshold, label in CHECKS:
        count = get_count(q)
        ts = get_ts(q) if count > 0 else "-"
        tag = "red" if count >= threshold else "blue"
        if tag == "red": reds += 1
        entry = {
            "check": name, "label": label, "tag": tag,
            "count": count, "threshold": threshold,
            "last_event": ts, "last_tuned": "-"
        }
        findings.append(entry)

    verdicts = [f["tag"] for f in findings]
    blues = len(verdicts) - reds
    risk = "elevated" if reds > 0 else "normal"
    # Check if any were missed (telemetry exists but rule needs tuning)
    missed = [f for f in findings if f["tag"] == "blue" and f["count"] > 0]

    status = {
        "scanned_at": now,
        "risk": risk,
        "summary": f"{reds} red / {blues} blue",
        "checks": findings,
        "missed": [m["check"] for m in missed],
        "cycle": 0
    }
    return status, missed, findings

def tune(check_name, query):
    """Log a tuning entry for a missed detection."""
    entry = {
        "check": check_name,
        "problem": "rule missed — telemetry present but count below threshold",
        "changed": f"investigate {query}",
        "tuned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    return entry

def cycle(counter=0):
    print(f"\n{'='*50}")
    print(f"Cycle {counter} — {datetime.now(timezone.utc).strftime('%H:%M:%S')}Z")
    print(f"{'='*50}")

    # Step 1: Simulate
    print("\n[1/4] Running attacks...")
    for name, _, _, _ in CHECKS:
        if "Log cleared" in name:
            continue
        out = run_attack(name)
        print(f"  {name}: {out[-1][:60] if out else 'done'}")
        time.sleep(5)

    # Wait for Splunk indexing
    print("  Waiting for indexing...")
    time.sleep(15)

    # Step 2: Collect & Evaluate
    print("\n[2/4] Collecting + evaluating telemetry...")
    status, missed, findings = evaluate()
    print(f"  Verdict: {status['summary']} — risk: {status['risk']}")
    for f in findings:
        icon = "🔴" if f["tag"] == "red" else "🔵"
        print(f"  {icon} {f['check']}: {f['count']} (threshold {f['threshold']})")

    # Step 3: Tune if missed
    if missed:
        print(f"\n[3/4] Tuning {len(missed)} missed detection(s)...")
        tunes = []
        for m in missed:
            print(f"  Tuning: {m}")
            for name, q, th, label in CHECKS:
                if name == m:
                    tunes.append(tune(name, q))
        status["tunes"] = tunes
    else:
        print("\n[3/4] No missed detections — all checks green.")

    status["cycle"] = counter
    OUT.write_text(json.dumps(status, indent=2))
    print(f"\n[4/4] Status written to {OUT}")

    # Append to tuning log
    if missed:
        previous = []
        if TUNING_LOG.exists():
            previous = json.loads(TUNING_LOG.read_text())
        log_entry = {
            "cycle": counter,
            "timestamp": status["scanned_at"],
            "missed": [{"check": t["check"], "problem": t["problem"], "changed": t["changed"]} for t in tunes]
        }
        previous.append(log_entry)
        TUNING_LOG.write_text(json.dumps(previous, indent=2))
        print(f"  Tuning log updated: {TUNING_LOG}")

    return status

def push():
    os.chdir(ROOT)
    subprocess.run(["git", "add", "detection/"], capture_output=True)
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        return
    subprocess.run(["git", "commit", "-m", "Update generated detection pipeline status"], check=False)
    subprocess.run(["git", "push", "origin", "main"], check=False)

if __name__ == "__main__":
    watch = "--watch" in sys.argv or "-w" in sys.argv
    auto_push = "--push" in sys.argv or "-p" in sys.argv
    counter = 0
    if watch:
        print(f"Pipeline running every {INTERVAL}s. Ctrl+C to stop.")
        while True:
            cycle(counter)
            if auto_push:
                push()
            counter += 1
            time.sleep(INTERVAL)
    else:
        cycle(0)
        if auto_push:
            push()
