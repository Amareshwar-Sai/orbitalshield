"""
OrbitalShield - Dashboard API Server
Aggregates data from all components and exposes it to the React dashboard.
Also handles CORS so the React dev server can connect.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import threading
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from config.settings import *
from comm.logger import read_log
from response.engine import get_response_state, run as start_response


def _fetch_json(port: int, path: str) ->  dict:
    try:
        url = f"http://{HOST}:{port}{path}"
        with urllib.request.urlopen(url, timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/status":
            data = self._build_status()
        elif path == "/api/telemetry":
            gs = _fetch_json(GROUND_STATION_PORT, "/telemetry")
            data = gs or {"telemetry": []}
        elif path == "/api/telemetry/latest":
            data = _fetch_json(GROUND_STATION_PORT, "/telemetry/latest") or {}
        elif path == "/api/commands":
            gs = _fetch_json(GROUND_STATION_PORT, "/commands")
            data = gs or {"commands": []}
        elif path == "/api/alerts":
            alerts = read_log(ALERT_LOG, 100)
            data = {"alerts": alerts}
        elif path == "/api/events":
            events = read_log(EVENTS_LOG, 100)
            data = {"events": events}
        elif path == "/api/response":
            data = get_response_state()
        elif path == "/api/mission":
            data = self._build_mission_summary()
        elif path == "/api/health":
            data = {"status": "UP", "ts": time.time()}
        else:
            self._respond(404, {"error": "Not found"})
            return

        self._respond(200, data)

    def _build_status(self) -> dict:
        sat = _fetch_json(SATELLITE_PORT, "/health")
        gs = _fetch_json(GROUND_STATION_PORT, "/status")
        resp_state = get_response_state()
        alerts = read_log(ALERT_LOG, 200)
        critical = [a for a in alerts if a.get("severity") == "CRITICAL"]
        high = [a for a in alerts if a.get("severity") == "HIGH"]

        return {
            "satellite": sat or {"status": "OFFLINE"},
            "ground_station": gs or {"status": "OFFLINE"},
            "mission_mode": resp_state["mission_mode"],
            "alert_counts": {
                "critical": len(critical),
                "high": len(high),
                "total": len(alerts),
            },
            "blocked_ips": resp_state["blocked_ips"],
            "locked_accounts": resp_state["locked_accounts"],
            "ts": time.time(),
        }

    def _build_mission_summary(self) -> dict:
        alerts = read_log(ALERT_LOG, 200)
        commands = read_log(COMMAND_LOG, 200)
        events = read_log(EVENTS_LOG, 200)

        # Alert type breakdown
        type_counts = {}
        for a in alerts:
            t = a.get("alert_type", "UNKNOWN")
            type_counts[t] = type_counts.get(t, 0) + 1

        # Command outcome breakdown
        cmd_outcomes = {}
        for c in commands:
            s = c.get("status", "UNKNOWN")
            cmd_outcomes[s] = cmd_outcomes.get(s, 0) + 1

        # Recent attack timeline (last 20 alerts)
        timeline = sorted(alerts[-20:], key=lambda x: x.get("_ts", 0))

        return {
            "alert_type_breakdown": type_counts,
            "command_outcomes": cmd_outcomes,
            "attack_timeline": timeline,
            "total_events": len(events),
            "ts": time.time(),
        }

    def _respond(self, code: int, data: dict):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


def run():
    print(f"📊 Dashboard API starting on port {DASHBOARD_API_PORT}...")
    server = HTTPServer((HOST, DASHBOARD_API_PORT), DashboardHandler)
    print(f"📊 Dashboard API online at http://{HOST}:{DASHBOARD_API_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    start_response()
    run()
