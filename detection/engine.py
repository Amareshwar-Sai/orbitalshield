"""
OrbitalShield - Detection Engine
Monitors logs, telemetry, commands, and events.
Detects: replay attacks, command injection, telemetry tampering,
         DoS patterns, brute force, credential abuse, log gaps.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import threading
from collections import defaultdict, deque
from config.settings import *
from comm.logger import log_alert, read_log, register_alert_hook, verify_log_chain

# ─── State ───────────────────────────────────────────────────────────────────

class DetectionState:
    def __init__(self):
        # Sliding window: source → deque of timestamps
        self.command_windows = defaultdict(lambda: deque(maxlen=100))
        self.packet_rate_windows = defaultdict(lambda: deque(maxlen=500))
        self.failed_logins = defaultdict(list)

        # Seen nonces (for local replay tracking)
        self.seen_nonces = {}

        # Last known telemetry values for delta checking
        self.last_telemetry = {}

        # Suppression: avoid alert spam
        self.last_alert = {}  # {alert_key: timestamp}
        self.alert_cooldown = 10  # seconds

        self.lock = threading.Lock()

    def should_fire(self, key: str) -> bool:
        """Return True if alert cooldown has passed."""
        now = time.time()
        last = self.last_alert.get(key, 0)
        if now - last > self.alert_cooldown:
            self.last_alert[key] = now
            return True
        return False


dstate = DetectionState()

# ─── Individual Detectors ────────────────────────────────────────────────────

# NOTE: detect_replay() and detect_command_injection() below are kept for
# isolated/manual testing, but the live system no longer relies on them —
# they were never called by anything, live or otherwise. Real-time replay and
# injection alerts are now raised directly at the point of rejection in
# simulator/satellite.py's do_POST, which has ground-truth on exactly why a
# command was rejected and can alert on it immediately rather than waiting
# for a poll cycle. See the Findings Log for why this path was preferred
# over resurrecting these two functions as-is.

def detect_replay(message: dict, source: str = "unknown") -> bool:
    """Detect if a nonce has been reused (replay attack)."""
    nonce = message.get("nonce")
    if not nonce:
        return False

    now = time.time()
    with dstate.lock:
        # Clean expired nonces
        expired = [n for n, t in dstate.seen_nonces.items() if now - t > NONCE_EXPIRY_SECONDS * 2]
        for n in expired:
            del dstate.seen_nonces[n]

        if nonce in dstate.seen_nonces:
            if dstate.should_fire(f"replay:{nonce[:8]}"):
                log_alert("CRITICAL", "REPLAY_ATTACK", source, {
                    "message": f"Nonce {nonce[:12]}... reused. Replay attack detected.",
                    "nonce": nonce,
                    "original_ts": dstate.seen_nonces[nonce],
                })
            return True
        dstate.seen_nonces[nonce] = now
    return False


def detect_command_injection(command: dict) -> bool:
    """Detect commands from unauthorized sources."""
    source = command.get("source", "UNKNOWN")
    action = command.get("action", "")
    token = command.get("token")

    # Source not whitelisted
    if source not in (GROUND_STATION_ID, MISSION_CONTROL_ID):
        if dstate.should_fire(f"inject:{source}"):
            log_alert("CRITICAL", "COMMAND_INJECTION", source, {
                "message": f"Command from unauthorized source: {source}",
                "action": action,
            })
        return True

    # No token
    if not token:
        if dstate.should_fire(f"notoken:{source}"):
            log_alert("HIGH", "COMMAND_INJECTION", source, {
                "message": "Command with no auth token",
                "action": action,
            })
        return True

    return False


def detect_command_rate(source: str) -> bool:
    """Detect abnormally high command rate from a source (DoS or automation abuse)."""
    now = time.time()
    with dstate.lock:
        window = dstate.command_windows[source]
        window.append(now)
        recent = [t for t in window if now - t < 60]
        count = len(recent)

    if count > MAX_COMMANDS_PER_MINUTE:
        if dstate.should_fire(f"cmdrate:{source}"):
            log_alert("HIGH", "COMMAND_RATE_ABUSE", source, {
                "message": f"{count} commands in last 60s (limit: {MAX_COMMANDS_PER_MINUTE})",
                "count": count,
            })
        return True
    return False


def detect_telemetry_anomaly(telem: dict) -> list[str]:
    """
    Detect physical anomalies in telemetry:
    - Values out of safe range
    - Impossible jumps between readings
    - Integrity failures
    """
    alerts = []
    sat_id = telem.get("source_id", "unknown")

    # Integrity flag from ground station
    if telem.get("_integrity") == "FAILED":
        reason = telem.get("_integrity_reason", "unknown")
        if dstate.should_fire(f"telem_integrity:{sat_id}"):
            log_alert("CRITICAL", "TELEMETRY_TAMPER", sat_id, {
                "message": f"Telemetry integrity check failed: {reason}",
            })
        alerts.append("TAMPER")

    # Range checks
    battery = telem.get("battery_pct")
    if battery is not None:
        if battery < BATTERY_MIN:
            if dstate.should_fire(f"battery_low:{sat_id}"):
                log_alert("HIGH", "TELEMETRY_ANOMALY", sat_id, {
                    "message": f"Battery critical: {battery}%",
                    "field": "battery_pct", "value": battery,
                })
            alerts.append("BATTERY_LOW")

    temp = telem.get("temperature_c")
    if temp is not None:
        if temp < TEMP_MIN or temp > TEMP_MAX:
            if dstate.should_fire(f"temp:{sat_id}"):
                log_alert("MEDIUM", "TELEMETRY_ANOMALY", sat_id, {
                    "message": f"Temperature out of range: {temp}°C",
                    "field": "temperature_c", "value": temp,
                })
            alerts.append("TEMP_OOB")

    # Delta checks vs last reading
    last = dstate.last_telemetry.get(sat_id)
    if last:
        if battery is not None and last.get("battery_pct") is not None:
            delta = abs(battery - last["battery_pct"])
            if delta > 20:  # impossible 20% jump in 2 seconds
                if dstate.should_fire(f"battery_jump:{sat_id}"):
                    log_alert("HIGH", "TELEMETRY_ANOMALY", sat_id, {
                        "message": f"Impossible battery jump: {last['battery_pct']}% → {battery}% (Δ{delta:.1f}%)",
                        "field": "battery_pct",
                    })
                alerts.append("IMPOSSIBLE_DELTA")

        if temp is not None and last.get("temperature_c") is not None:
            delta = abs(temp - last["temperature_c"])
            if delta > 30:
                if dstate.should_fire(f"temp_jump:{sat_id}"):
                    log_alert("HIGH", "TELEMETRY_ANOMALY", sat_id, {
                        "message": f"Impossible temp jump: {last['temperature_c']}°C → {temp}°C (Δ{delta:.1f}°C)",
                    })
                alerts.append("IMPOSSIBLE_DELTA")

    with dstate.lock:
        dstate.last_telemetry[sat_id] = telem

    return alerts


def detect_dos(source_ip: str, request_count: int) -> bool:
    """Detect denial-of-service based on request rate."""
    now = time.time()
    with dstate.lock:
        window = dstate.packet_rate_windows[source_ip]
        window.append(now)
        recent = [t for t in window if now - t < 5]  # 5-second window
        rate = len(recent)

    if rate > MAX_PACKET_RATE:
        if dstate.should_fire(f"dos:{source_ip}"):
            log_alert("CRITICAL", "DOS_ATTACK", source_ip, {
                "message": f"DoS pattern: {rate} requests in 5s from {source_ip}",
                "rate_per_5s": rate,
            })
        return True
    return False


def detect_brute_force(ip: str, username: str, failed: bool) -> bool:
    """Detect brute force login attempts."""
    now = time.time()
    with dstate.lock:
        attempts = dstate.failed_logins[ip]
        attempts = [t for t in attempts if now - t < 60]
        if failed:
            attempts.append(now)
        dstate.failed_logins[ip] = attempts
        count = len(attempts)

    if count >= MAX_FAILED_LOGINS:
        if dstate.should_fire(f"brute:{ip}"):
            log_alert("HIGH", "BRUTE_FORCE", ip, {
                "message": f"{count} failed logins in 60s from {ip}",
                "username": username,
            })
        return True
    return False


def detect_log_gap(log_path: str, max_gap_seconds: float = 30.0) -> bool:
    """Detect missing log entries (potential log tampering)."""
    records = read_log(log_path, 50)
    if len(records) < 2:
        return False

    for i in range(1, len(records)):
        ts_prev = records[i-1].get("_ts", 0)
        ts_curr = records[i].get("_ts", 0)
        gap = ts_curr - ts_prev
        if gap > max_gap_seconds:
            key = f"loggap:{log_path}:{i}"
            if dstate.should_fire(key):
                log_alert("MEDIUM", "LOG_TAMPERING", "SYSTEM", {
                    "message": f"Log gap detected in {log_path}: {gap:.1f}s gap at index {i}",
                    "gap_seconds": gap,
                })
            return True
    return False


# ─── Correlation Engine ───────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Correlates multiple low-level alerts into high-level attack chains.
    Example: failed login → command injection → telemetry tamper = ACTIVE COMPROMISE
    """

    def __init__(self, window_seconds: float = 120.0):
        self.window = window_seconds
        self.recent_alerts = deque()  # (timestamp, alert_type, source)
        # RLock, not Lock: _check_chains() below can call log_alert(), which
        # fires the alert hook back into add_alert() on the SAME thread (an
        # ATTACK_CHAIN_DETECTED alert is itself an alert). A plain Lock would
        # self-deadlock on that re-entry — which is exactly what happened
        # the first time this was wired up and tested end-to-end.
        self.lock = threading.RLock()
        # Per-chain cooldown, same idea as DetectionState.should_fire(). Without
        # this, firing an ATTACK_CHAIN_DETECTED alert feeds it back through the
        # hook into add_alert() — and since the original triggering alerts are
        # still sitting in the window, _check_chains() matches again
        # immediately, forever. Found this the hard way: it hung both HTTP
        # servers by pinning the process in a recursive alert storm the first
        # time this was tested end-to-end.
        self.last_fired = {}
        self.chain_cooldown = 30

    def add_alert(self, alert_type: str, source: str):
        now = time.time()
        with self.lock:
            self.recent_alerts.append((now, alert_type, source))
            # Clean old
            cutoff = now - self.window
            while self.recent_alerts and self.recent_alerts[0][0] < cutoff:
                self.recent_alerts.popleft()
            self._check_chains()

    def _should_fire_chain(self, name: str) -> bool:
        now = time.time()
        last = self.last_fired.get(name, 0)
        if now - last > self.chain_cooldown:
            self.last_fired[name] = now
            return True
        return False

    def _check_chains(self):
        types = [a[1] for a in self.recent_alerts]

        # Chain 1: Brute force → Command injection → Telemetry tamper
        if ("BRUTE_FORCE" in types and "COMMAND_INJECTION" in types and "TELEMETRY_TAMPER" in types):
            if self._should_fire_chain("chain1"):
                log_alert("CRITICAL", "ATTACK_CHAIN_DETECTED", "CORRELATION_ENGINE", {
                    "message": "⚠️ Full attack chain: Auth abuse → Command injection → Telemetry compromise",
                    "chain": ["BRUTE_FORCE", "COMMAND_INJECTION", "TELEMETRY_TAMPER"],
                })

        # Chain 2: Replay + Command injection
        if ("REPLAY_ATTACK" in types and "COMMAND_INJECTION" in types):
            if self._should_fire_chain("chain2"):
                log_alert("CRITICAL", "ATTACK_CHAIN_DETECTED", "CORRELATION_ENGINE", {
                    "message": "⚠️ Command compromise chain: Replay attack + Injection detected",
                    "chain": ["REPLAY_ATTACK", "COMMAND_INJECTION"],
                })

        # Chain 3: DoS + Brute force (distraction + intrusion)
        if ("DOS_ATTACK" in types and "BRUTE_FORCE" in types):
            if self._should_fire_chain("chain3"):
                log_alert("HIGH", "ATTACK_CHAIN_DETECTED", "CORRELATION_ENGINE", {
                    "message": "⚠️ Distraction pattern: DoS + concurrent brute force",
                    "chain": ["DOS_ATTACK", "BRUTE_FORCE"],
                })


correlator = CorrelationEngine()

# Wire every alert into the correlator. Before this line, correlator.add_alert()
# was called by nothing anywhere in the codebase — the correlation engine
# existed but was permanently inert, regardless of which detectors fired.
register_alert_hook(lambda severity, alert_type, source, detail: correlator.add_alert(alert_type, source))


# ─── Background monitor loop ─────────────────────────────────────────────────

def monitor_loop():
    """Continuously scan logs for anomalies."""
    print("🔍 Detection engine active...")
    while True:
        try:
            # Check for log gaps AND hash-chain tampering (edited/deleted lines)
            for log in [TELEMETRY_LOG, COMMAND_LOG, EVENTS_LOG, ALERT_LOG]:
                if os.path.exists(log):
                    detect_log_gap(log)
                    valid, reason = verify_log_chain(log)
                    if not valid:
                        if dstate.should_fire(f"chain:{log}"):
                            log_alert("CRITICAL", "LOG_TAMPERING", "SYSTEM", {
                                "message": f"Hash chain broken in {log}: {reason}",
                                "log_path": log,
                            })

            # Re-process recent telemetry records
            recent_telem = read_log(TELEMETRY_LOG, 5)
            for t in recent_telem:
                detect_telemetry_anomaly(t)

            # Re-process recent commands for rate abuse
            recent_cmds = read_log(COMMAND_LOG, 20)
            sources = [c.get("source") for c in recent_cmds if c.get("source")]
            for src in set(sources):
                src_count = sources.count(src)
                if src_count > 5:
                    detect_command_rate(src)

        except Exception as e:
            log_alert("LOW", "DETECTION_ERROR", "DETECTION_ENGINE", {
                "message": f"Detection loop error: {e}"
            })

        time.sleep(5)


def run():
    """Start the detection engine as a background process."""
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    run()
    # Keep alive
    while True:
        time.sleep(1)
