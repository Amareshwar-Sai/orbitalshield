"""
OrbitalShield - Ground Station Simulator
Receives satellite telemetry, stores it, sends commands, exposes API for mission control.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import threading
import urllib.request
import urllib.error
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from config.settings import *
from auth.integrity import generate_token, sign_message, verify_message
from comm.logger import log_event, log_command, log_alert
from detection.engine import detect_dos

# In-memory stores
telemetry_store = []   # last 200 readings
command_history = []   # last 200 commands
alert_store = []       # live alerts
_store_lock = threading.Lock()

# Login tracking for brute-force detection
login_attempts = {}    # {ip: [timestamps]}
# Demo-only fallback credentials, same pattern as SECRET_KEY in config/settings.py —
# override with ORBITALSHIELD_OPS_PASSWORD / ORBITALSHIELD_ANALYST_PASSWORD for
# anything beyond a local demo.
OPERATOR_CREDENTIALS = {
    "ops_admin": os.environ.get("ORBITALSHIELD_OPS_PASSWORD", "demo-ops-password-change-me"),
    "analyst": os.environ.get("ORBITALSHIELD_ANALYST_PASSWORD", "demo-analyst-password-change-me"),
}


def fetch_telemetry_from_satellite() ->  dict:
    try:
        url = f"http://{HOST}:{SATELLITE_PORT}/telemetry"
        req = urllib.request.Request(url, headers={"User-Agent": "GS/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return data
    except Exception as e:
        log_event("GS_ERROR", GROUND_STATION_ID, {"message": f"Telemetry fetch failed: {e}"})
        return None


def verify_and_store_telemetry(telem: dict):
    """Validate integrity of incoming telemetry, then store."""
    valid, reason = verify_message(telem)
    if not valid:
        log_alert("HIGH", "TELEMETRY_TAMPER", GROUND_STATION_ID,
                  {"message": f"Telemetry integrity failure: {reason}"})
        telem["_integrity"] = "FAILED"
        telem["_integrity_reason"] = reason
    else:
        telem["_integrity"] = "OK"

    with _store_lock:
        telemetry_store.append(telem)
        if len(telemetry_store) > 200:
            telemetry_store.pop(0)


def send_command_to_satellite(action: str, parameters: dict = None, source: str = GROUND_STATION_ID) -> dict:
    """Build, sign, and send a command to the satellite."""
    token = generate_token(source)
    command = {
        "command_id": f"CMD-{int(time.time()*1000)}",
        "source": source,
        "target": SATELLITE_ID,
        "action": action,
        "parameters": parameters or {},
        "token": token,
        "timestamp": time.time(),
    }
    command = sign_message(command)

    try:
        url = f"http://{HOST}:{SATELLITE_PORT}/command"
        body = json.dumps(command).encode()
        req = urllib.request.Request(url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "GS/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        result = {"error": str(e), "status": "HTTP_ERROR"}
    except Exception as e:
        result = {"error": str(e), "status": "NETWORK_ERROR"}

    log_command(command, result.get("status", "UNKNOWN"), result.get("message", ""))
    with _store_lock:
        command_history.append({**command, "result": result})
        if len(command_history) > 200:
            command_history.pop(0)
    return result


def telemetry_poll_loop():
    """Continuously poll satellite for telemetry."""
    while True:
        telem = fetch_telemetry_from_satellite()
        if telem:
            verify_and_store_telemetry(telem)
        time.sleep(TELEMETRY_INTERVAL_SECONDS)


class GroundStationHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        detect_dos(self.client_address[0], 1)  # live rate check, independent of any attack script
        if self.path == "/telemetry":
            with _store_lock:
                data = telemetry_store[-50:]
            self._respond(200, {"telemetry": data})

        elif self.path == "/telemetry/latest":
            with _store_lock:
                latest = telemetry_store[-1] if telemetry_store else {}
            self._respond(200, latest)

        elif self.path == "/commands":
            with _store_lock:
                data = command_history[-50:]
            self._respond(200, {"commands": data})

        elif self.path == "/alerts":
            from comm.logger import read_log
            from config.settings import ALERT_LOG
            alerts = read_log(ALERT_LOG, 100)
            self._respond(200, {"alerts": alerts})

        elif self.path == "/status":
            self._respond(200, {
                "id": GROUND_STATION_ID,
                "status": "UP",
                "telemetry_count": len(telemetry_store),
                "command_count": len(command_history),
            })
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        detect_dos(self.client_address[0], 1)  # live rate check, independent of any attack script
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except Exception:
            self._respond(400, {"error": "Invalid JSON"})
            return

        if self.path == "/command":
            action = payload.get("action")
            params = payload.get("parameters", {})
            source = payload.get("source", MISSION_CONTROL_ID)
            result = send_command_to_satellite(action, params, source)
            self._respond(200, result)

        elif self.path == "/telemetry/relay":
            # Ingest telemetry relayed via a secondary path (e.g. a backup
            # ground station or relay satellite) instead of the primary poll.
            # Runs through the exact same verify_and_store_telemetry() the
            # poller uses, so a tampered payload sent here is genuinely
            # integrity-checked, not just tested against a detector in isolation.
            verify_and_store_telemetry(payload)
            self._respond(200, {
                "status": "received",
                "integrity": payload.get("_integrity", "UNKNOWN"),
            })

        elif self.path == "/login":
            ip = self.client_address[0]
            username = payload.get("username")
            password = payload.get("password")
            self._handle_login(ip, username, password)

        else:
            self._respond(404, {"error": "Not found"})

    def _handle_login(self, ip: str, username: str, password: str):
        now = time.time()
        # Track attempts per IP
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]  # last 60 sec
        attempts.append(now)
        login_attempts[ip] = attempts

        if len(attempts) > MAX_FAILED_LOGINS:
            log_alert("HIGH", "BRUTE_FORCE", ip,
                      {"message": f"{len(attempts)} login attempts in 60s", "username": username})
            self._respond(429, {"error": "Too many attempts. Account locked."})
            return

        if OPERATOR_CREDENTIALS.get(username) == password:
            log_event("LOGIN_SUCCESS", ip, {"username": username})
            token = generate_token(username)
            self._respond(200, {"token": token, "message": "Login successful"})
        else:
            log_event("LOGIN_FAILED", ip, {"username": username})
            if len(attempts) >= MAX_FAILED_LOGINS:
                log_alert("HIGH", "BRUTE_FORCE", ip,
                          {"message": f"Possible brute force: {len(attempts)} failed logins",
                           "username": username})
            self._respond(401, {"error": "Invalid credentials"})

    def _respond(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run():
    print(f"📡 Ground station starting on port {GROUND_STATION_PORT}...")
    t = threading.Thread(target=telemetry_poll_loop, daemon=True)
    t.start()
    server = HTTPServer((HOST, GROUND_STATION_PORT), GroundStationHandler)
    print(f"📡 {GROUND_STATION_ID} online.")
    server.serve_forever()


if __name__ == "__main__":
    run()
