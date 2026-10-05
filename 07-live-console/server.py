#!/usr/bin/env python3
"""Local, read-only bridge from Splunk search to SOC Playground."""

import base64
import ipaddress
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPLUNK_URL = os.environ.get("SPLUNK_URL", "https://127.0.0.1:8089").rstrip("/")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
INDEX = os.environ.get("SPLUNK_INDEX", "soc_capstone")
PORT = int(os.environ.get("CONSOLE_PORT", "8765"))
HOST = os.environ.get("CONSOLE_HOST", "127.0.0.1")
TLS_VERIFY = os.environ.get("SPLUNK_TLS_VERIFY", "0") == "1"

SEARCHES = {
    "normal": '(sourcetype=linux_secure "Accepted password") OR (sourcetype=WinEventLog:System) OR (sourcetype=WinEventLog:Application)',
    "ssh": 'sourcetype=linux_secure ("Failed password" OR "Accepted password")',
    "account": 'sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4732 OR EventCode=1102)',
    "powershell": 'sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (DownloadString OR DownloadFile OR Invoke-WebRequest OR Net.WebClient OR EncodedCommand)',
}
MAX_PER_SEARCH = 250
_cache = {}
_cache_lock = threading.Lock()


def auth_header(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def check_splunk_login(user, password):
    request = urllib.request.Request(
        f"{SPLUNK_URL}/services/server/info?output_mode=json",
        headers={"Authorization": auth_header(user, password)},
    )
    context = None if TLS_VERIFY else ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        return response.status == 200


def run_export(search):
    body = urllib.parse.urlencode({"search": search, "output_mode": "json", "preview": "false"}).encode()
    request = urllib.request.Request(
        f"{SPLUNK_URL}/services/search/jobs/export",
        data=body,
        headers={
            "Authorization": auth_header(SPLUNK_USER, SPLUNK_PASSWORD),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    context = None if TLS_VERIFY else ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=25, context=context) as response:
        items = [json.loads(line) for line in response if line.strip()]
    errors = [message.get("text", "Splunk search error") for item in items for message in item.get("messages", []) if message.get("type") == "ERROR"]
    if errors:
        raise ValueError("; ".join(errors))
    return [item["result"] for item in items if "result" in item]


def splunk_search(query, earliest):
    search = f"search index={INDEX} earliest=-{earliest}h {query} | head {MAX_PER_SEARCH} | eval event_epoch=round(_time,3) | table event_epoch _time host sourcetype EventCode EventID src Source_Network_Address User Account_Name TargetUserName CommandLine _raw"
    return run_export(search)


def parse_time(value):
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
            return float(value)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0


def classify(kind, row):
    raw = row.get("_raw", "") or ""
    code = str(row.get("EventCode") or row.get("EventID") or "")
    if kind == "normal":
        # Baseline event — count it for the waveform but don't tag as detection
        label = "system" if "System" in (row.get("sourcetype") or "") else "auth_ok"
        return (label, "baseline", "info", row.get("host") or "unknown")
    if kind == "ssh":
        failed = "Failed password" in raw
        match = re.search(r"from ([0-9a-fA-F:.]+)", raw)
        return ("SSH failure" if failed else "SSH success", "Attk101", "high" if failed else "medium", match.group(1) if match else (row.get("src") or "unknown"))
    if kind == "account":
        if code == "4732" and "Administrators" not in raw and "S-1-5-32-544" not in raw:
            return None
        labels = {"4720": ("Local account created", "Attk102", "high"), "4732": ("Administrator group changed", "Attk102", "high"), "1102": ("Security log cleared", "Attk104", "critical")}
        for candidate, label in labels.items():
            if code == candidate or re.search(r"EventCode\s*=\s*" + candidate, raw):
                return (*label, row.get("TargetUserName") or row.get("Account_Name") or "")
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    if root.findtext(".//{*}System/{*}EventID") != "1":
        return None
    fields = {item.get("Name"): item.text or "" for item in root.findall(".//{*}EventData/{*}Data")}
    image = (fields.get("Image") or row.get("Image") or "").lower()
    command = fields.get("CommandLine") or row.get("CommandLine") or ""
    if not image.endswith(("powershell.exe", "pwsh.exe")):
        return None
    cradle = ("downloadstring", "downloadfile", "invoke-webrequest", "net.webclient", "encodedcommand")
    lab_scripts = ("run_attk103_direct.ps1", "Attk103_psuedoattacks.ps1")
    if not any(marker in command.lower() for marker in cradle + lab_scripts):
        return None
    row["CommandLine"] = command
    label = "PowerShell download command" if any(marker in command.lower() for marker in cradle) else "PowerShell lab payload script"
    return (label, "Attk103", "high", fields.get("User") or row.get("User") or "")


def build_snapshot(rows_by_kind, hours):
    events = []
    baseline_events = []
    unparsed_time = 0
    for kind, rows in rows_by_kind.items():
        for row in rows:
            classified = classify(kind, row)
            if not classified:
                continue
            label, technique, severity, actor = classified
            timestamp = parse_time(row.get("event_epoch") or row.get("_time"))
            if not timestamp:
                unparsed_time += 1
                continue
            entry = {
                "time": timestamp,
                "host": row.get("host") or "unknown",
                "label": label,
                "technique": technique,
                "severity": severity,
                "actor": actor,
                "detail": (row.get("CommandLine") or row.get("_raw") or "")[:340],
            }
            if technique == "baseline":
                baseline_events.append(entry)
            else:
                events.append(entry)
    events.sort(key=lambda event: event["time"], reverse=True)
    baseline_events.sort(key=lambda event: event["time"], reverse=True)
    now = time.time()
    window_start = now - hours * 3600
    # Baseline bins (gentle wave of normal activity)
    base_bins = [0] * 60
    for event in baseline_events:
        index = int((event["time"] - window_start) / (hours * 3600) * 60)
        if 0 <= index < 60:
            base_bins[index] += 1
    # Attack bins (colored spikes)
    attack_bins = [Counter() for _ in range(60)]
    for event in events:
        index = int((event["time"] - window_start) / (hours * 3600) * 60)
        if 0 <= index < 60:
            attack_bins[index][event["technique"]] += 1
    ssh_failures = [event for event in events if event["label"] == "SSH failure"]
    burst = any(sum(1 for other in ssh_failures if 0 <= event["time"] - other["time"] <= 300 and event["actor"] == other["actor"]) >= 10 for event in ssh_failures)
    detections = []
    if burst:
        detections.append({"title": "SSH failure burst", "technique": "Attk101", "severity": "high", "reason": "10+ failures from one source within five minutes"})
    for technique, title in (("Attk102", "Account change"), ("Attk103", "PowerShell download"), ("Attk104", "Security log cleared")):
        matching = [event for event in events if event["technique"] == technique]
        if matching:
            detections.append({"title": title, "technique": technique, "severity": "critical" if technique == "Attk104" else "high", "reason": f"{len(matching)} matching event(s) in selected window"})
    return {
        "updated_at": now,
        "hours": hours,
        "events": events[:100],
        "baseline_events": baseline_events[:100],
        "trace_events": [{"time": event["time"], "technique": event["technique"]} for event in events] + [{"time": event["time"], "technique": "baseline"} for event in baseline_events],
        "trace": [dict(item) for item in attack_bins],
        "baseline_trace": base_bins,
        "detections": detections,
        "counts": dict(Counter(event["technique"] for event in events)),
        "baseline_total": sum(base_bins),
        "hosts": sorted({event["host"] for event in events + baseline_events}),
        "total": len(events),
        "limited": any(len(rows) == MAX_PER_SEARCH for rows in rows_by_kind.values()),
        "source_rows": {kind: len(rows) for kind, rows in rows_by_kind.items()},
        "unparsed_time": unparsed_time,
    }


def snapshot(hours):
    with _cache_lock:
        cached = _cache.get(hours)
        if cached and time.time() - cached[0] < 3:
            return cached[1]
    rows = {kind: splunk_search(query, hours) for kind, query in SEARCHES.items()}
    result = build_snapshot(rows, hours)
    with _cache_lock:
        _cache[hours] = (time.time(), result)
    return result


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/connect":
            return self.send_error(404)
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            return self.send_json({"error": "Local access only"}, 403)
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{self.headers.get('Host')}":
            return self.send_json({"error": "Invalid origin"}, 403)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                return self.send_json({"error": "Invalid request"}, 400)
            payload = json.loads(self.rfile.read(length))
            user = str(payload.get("user", "admin"))
            password = str(payload.get("password", ""))
            if not user or not password:
                return self.send_json({"error": "Enter a Splunk username and password"}, 400)
            if not check_splunk_login(user, password):
                return self.send_json({"error": "Splunk rejected these credentials"}, 401)
            global SPLUNK_USER, SPLUNK_PASSWORD
            with _cache_lock:
                SPLUNK_USER, SPLUNK_PASSWORD = user, password
                _cache.clear()
            return self.send_json({"connected": True})
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return self.send_json({"error": "Splunk rejected these credentials"}, 401)
            return self.send_json({"error": f"Splunk returned HTTP {exc.code}"}, 502)
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": f"Could not connect to Splunk: {exc}"}, 502)

    def do_GET(self):
        route = urllib.parse.urlparse(self.path)
        if route.path == "/api/status":
            try:
                status = (ROOT.parent / "detection" / "status.json").read_text()
                return self.send_json(json.loads(status))
            except (FileNotFoundError, json.JSONDecodeError):
                return self.send_json({"error": "no status.json — run detection/scan.py"}, 503)
        if route.path == "/api/health":
            if not SPLUNK_PASSWORD:
                return self.send_json({"error": "Connect to Splunk first"}, 503)
            try:
                rows = run_export(f"search index={INDEX} earliest=-72h | stats count by sourcetype")
                return self.send_json({"index": INDEX, "sourcetypes": rows})
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                return self.send_json({"error": f"Splunk search failed: {exc}"}, 502)
        if route.path == "/api/events":
            if not SPLUNK_PASSWORD:
                return self.send_json({"error": "Connect to Splunk to view live events."}, 503)
            try:
                hours = int(urllib.parse.parse_qs(route.query).get("hours", [24])[0])
                if hours not in (1, 6, 24, 72):
                    return self.send_json({"error": "hours must be 1, 6, 24 or 72"}, 400)
                return self.send_json(snapshot(hours))
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                return self.send_json({"error": f"Splunk search failed: {exc}"}, 502)
        if route.path in ("/", "/index.html"):
            return self.send_file(ROOT / "index.html", "text/html; charset=utf-8")
        if route.path == "/app.css":
            return self.send_file(ROOT / "app.css", "text/css; charset=utf-8")
        if route.path == "/stats.css":
            return self.send_file(ROOT / "stats.css", "text/css; charset=utf-8")
        if route.path == "/app.js":
            return self.send_file(ROOT / "app.js", "text/javascript; charset=utf-8")
        self.send_error(404)

    def send_json(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, mime):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")


if __name__ == "__main__":
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", INDEX):
        raise SystemExit("SPLUNK_INDEX contains unsupported characters")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SOC console: http://{HOST}:{PORT} (Splunk: {SPLUNK_URL}, index: {INDEX})", flush=True)
    server.serve_forever()
