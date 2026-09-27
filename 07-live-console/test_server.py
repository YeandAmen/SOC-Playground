import importlib.util
import json
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


spec = importlib.util.spec_from_file_location("console_server", Path(__file__).with_name("server.py"))
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class SnapshotTests(unittest.TestCase):
    def test_trace_keeps_events_beyond_table_limit(self):
        now = time.time()
        rows = {"account": [{"event_epoch": now - index, "EventCode": "4720", "_raw": "EventCode=4720"} for index in range(125)]}
        result = server.build_snapshot(rows, 1)
        self.assertEqual(len(result["events"]), 100)
        self.assertEqual(len(result["trace_events"]), 125)
        self.assertEqual(result["total"], 125)

    def test_static_responses_include_browser_security_headers(self):
        console = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=console.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{console.server_port}/") as response:
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        finally:
            console.shutdown()
            console.server_close()

    def test_real_event_shapes_create_detections_and_trace(self):
        now = time.time()
        stamp = lambda seconds: __import__("datetime").datetime.fromtimestamp(seconds, __import__("datetime").timezone.utc).isoformat()
        rows = {
            "ssh": [{"_time": "09/24/2026 06:00:00 PM", "event_epoch": str(now - i * 10), "host": "kali", "_raw": "Failed password for medusa from <mac-ip> port 50000 ssh2"} for i in range(10)],
            "account": [{"_time": stamp(now - 30), "host": "WIN-LAB", "EventCode": "4720", "TargetUserName": "capstone_admin", "_raw": "EventCode=4720"}],
            "powershell": [{"_time": stamp(now - 20), "host": "WIN-LAB", "EventID": "1", "User": "lab", "_raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID></System><EventData><Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='CommandLine'>powershell.exe DownloadString(...)</Data></EventData></Event>"}],
        }
        result = server.build_snapshot(rows, 1)
        self.assertEqual(result["total"], 12)
        self.assertEqual(len(result["detections"]), 3)
        self.assertEqual(len(result["trace"]), 60)
        self.assertEqual(sum(bin.get("Attk101", 0) for bin in result["trace"]), 10)
        self.assertEqual(result["hosts"], ["WIN-LAB", "kali"])

    def test_security_log_clear_is_critical(self):
        stamp = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        result = server.build_snapshot({"account": [{"_time": stamp, "host": "WIN-LAB", "EventCode": "1102", "_raw": "EventCode=1102"}]}, 24)
        self.assertEqual(result["detections"][0]["severity"], "critical")

    def test_sysmon_download_requires_process_creation(self):
        def xml(event_id):
            return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                    f"<System><EventID>{event_id}</EventID></System><EventData>"
                    "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
                    "<Data Name='CommandLine'>powershell.exe -File C:\\SOC-Capstone\\run_attk103_direct.ps1</Data>"
                    "</EventData></Event>")
        self.assertIsNone(server.classify("powershell", {"_raw": xml(11)}))
        self.assertEqual(server.classify("powershell", {"_raw": xml(1)})[1], "Attk103")

    def test_splunk_export_transport(self):
        class FakeSplunk(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def do_POST(self):
                body = json.dumps({"result": {"_time": "2026-09-24T18:00:00+00:00", "host": "kali"}}).encode() + b"\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeSplunk)
        thread = threading.Thread(target=fake.serve_forever, daemon=True)
        thread.start()
        original_url = server.SPLUNK_URL
        try:
            server.SPLUNK_URL = f"http://127.0.0.1:{fake.server_port}"
            self.assertTrue(server.check_splunk_login("admin", "test"))
            self.assertEqual(server.splunk_search("sourcetype=linux_secure", 24)[0]["host"], "kali")
        finally:
            server.SPLUNK_URL = original_url
            fake.shutdown()
            fake.server_close()


if __name__ == "__main__":
    unittest.main()
