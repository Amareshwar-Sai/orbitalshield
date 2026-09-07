"""
OrbitalShield - Satellite Simulator
Emits telemetry and accepts authenticated commands via HTTP.
"""
from typing import Tuple, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
import time
import random
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from config.settings import *
from auth.integrity import verify_message, sign_message, generate_token
from comm.logger import log_telemetry, log_event, log_command, log_alert
from detection.engine import detect_dos


class SatelliteState:
    def __init__(self):
        self.satellite_id = SATELLITE_ID
        self.battery = 85.0
        self.temperature = 22.0
        self.orientation = {"pitch": 0.0, "roll": 0.0, "yaw": 0.0}
        self.mode = "NOMINAL"          # NOMINAL, SAFE, EMERGENCY
        self.payload_active = True
        self.comm_health = "OK"
        self.orbit_phase = "SUNLIT"
        self.command_count = 0
        self.lock = threading.Lock()

    def tick(self):
        """Natural drift of satellite state."""
        with self.lock:
            self.battery = max(BATTERY_MIN, min(BATTERY_MAX,
                self.battery + random.uniform(-0.5, 0.3) if self.orbit_phase == "ECLIPSE" else
                self.battery + random.uniform(-0.2, 0.8)))
            self.temperature += random.uniform(-0.3, 0.3)
            self.temperature = max(TEMP_MIN, min(TEMP_MAX, self.temperature))
            self.orientation["pitch"] += random.uniform(-0.1, 0.1)
            self.orientation["roll"] += random.uniform(-0.05, 0.05)
            if random.random() < 0.02:
                self.orbit_phase = "ECLIPSE" if self.orbit_phase == "SUNLIT" else "SUNLIT"

    def get_telemetry(self) -> dict:
        with self.lock:
            telem = {
                "source_id": self.satellite_id,
                "battery_pct": round(self.battery, 2),
                "temperature_c": round(self.temperature, 2),
                "orientation": {k: round(v, 3) for k, v in self.orientation.items()},
                "mode": self.mode,
                "payload_active": self.payload_active,
                "comm_health": self.comm_health,
                "orbit_phase": self.orbit_phase,
                "timestamp": time.time(),
            }
            return sign_message(telem)

    def apply_command(self, command: dict) -> Tuple[bool, str]:
        """Apply a verified command and return (success, message)."""
        action = command.get("action")
        params = command.get("parameters", {})

        with self.lock:
            if action == "SET_MODE":
                new_mode = params.get("mode", "NOMINAL")
                if new_mode not in ("NOMINAL", "SAFE", "EMERGENCY"):
                    return False, f"Unknown mode: {new_mode}"
                self.mode = new_mode
                return True, f"Mode set to {new_mode}"

            elif action == "TOGGLE_PAYLOAD":
                self.payload_active = not self.payload_active
                return True, f"Payload {'activated' if self.payload_active else 'deactivated'}"

            elif action == "ADJUST_ORIENTATION":
                for axis in ("pitch", "roll", "yaw"):
                    if axis in params:
                        self.orientation[axis] = float(params[axis])
                return True, "Orientation updated"

            elif action == "RESET_SUBSYSTEM":
                subsystem = params.get("subsystem", "COMM")
                self.comm_health = "OK"
                return True, f"Subsystem {subsystem} reset"

            elif action == "PING":
                return True, "PONG"

            else:
                return False, f"Unknown action: {action}"


# Global satellite state
state = SatelliteState()


class SatelliteHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default HTTP logging

    def do_GET(self):
        detect_dos(self.client_address[0], 1)  # live rate check, independent of any attack script
        if self.path == "/telemetry":
            telem = state.get_telemetry()
            self._respond(200, telem)
        elif self.path == "/health":
            self._respond(200, {"status": "UP", "id": SATELLITE_ID})
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        detect_dos(self.client_address[0], 1)  # live rate check, independent of any attack script
        if self.path == "/command":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                command = json.loads(body)
            except Exception:
                self._respond(400, {"error": "Invalid JSON"})
                return

            # 1. Token check
            token = command.get("token")
            if not token:
                log_command(command, "REJECTED", "Missing auth token")
                log_event("COMMAND_REJECTED", command.get("source", "UNKNOWN"),
                          {"message": "No token", "action": command.get("action")})
                log_alert("HIGH", "COMMAND_INJECTION", command.get("source", "UNKNOWN"), {
                    "message": "Command with no auth token", "action": command.get("action"),
                })
                self._respond(401, {"error": "Missing auth token"})
                return

            from auth.integrity import validate_token
            valid, reason = validate_token(token)
            if not valid:
                log_command(command, "REJECTED", reason)
                log_event("COMMAND_REJECTED", command.get("source", "UNKNOWN"),
                          {"message": reason, "action": command.get("action")})
                log_alert("HIGH", "COMMAND_INJECTION", command.get("source", "UNKNOWN"), {
                    "message": f"Invalid/forged auth token: {reason}", "action": command.get("action"),
                })
                self._respond(403, {"error": reason})
                return

            # 2. Source whitelist check
            source = command.get("source")
            if source not in (GROUND_STATION_ID, MISSION_CONTROL_ID):
                log_command(command, "REJECTED", f"Untrusted source: {source}")
                log_event("COMMAND_REJECTED", source or "UNKNOWN",
                          {"message": "Source not whitelisted", "action": command.get("action")})
                log_alert("CRITICAL", "COMMAND_INJECTION", source or "UNKNOWN", {
                    "message": f"Command from unauthorized source: {source}", "action": command.get("action"),
                })
                self._respond(403, {"error": f"Source not authorized: {source}"})
                return

            # 3. Integrity + replay check
            from auth.integrity import verify_message
            valid, reason = verify_message(command)
            if not valid:
                log_command(command, "REJECTED", reason)
                log_event("INTEGRITY_FAILURE", source,
                          {"message": reason, "action": command.get("action")})
                if "Replay" in reason:
                    log_alert("CRITICAL", "REPLAY_ATTACK", source, {
                        "message": reason, "nonce": command.get("nonce"),
                        "action": command.get("action"),
                    })
                else:
                    log_alert("HIGH", "COMMAND_INJECTION", source, {
                        "message": f"Command integrity check failed: {reason}", "action": command.get("action"),
                    })
                self._respond(400, {"error": reason})
                return

            # 4. Apply
            success, msg = state.apply_command(command)
            status = "EXECUTED" if success else "FAILED"
            log_command(command, status, msg)
            log_event("COMMAND_EXECUTED" if success else "COMMAND_FAILED", source,
                      {"action": command.get("action"), "message": msg})
            self._respond(200 if success else 400, {"status": status, "message": msg})
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def telemetry_broadcast():
    """Continuously update and log satellite telemetry."""
    while True:
        state.tick()
        telem = state.get_telemetry()
        log_telemetry(telem)
        time.sleep(TELEMETRY_INTERVAL_SECONDS)


def run():
    print(f"🛰️  Satellite simulator starting on port {SATELLITE_PORT}...")
    t = threading.Thread(target=telemetry_broadcast, daemon=True)
    t.start()
    server = HTTPServer((HOST, SATELLITE_PORT), SatelliteHandler)
    print(f"🛰️  {SATELLITE_ID} online.")
    server.serve_forever()


if __name__ == "__main__":
    run()
