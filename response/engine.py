"""
OrbitalShield - Response Engine
Automated defensive actions triggered by detection alerts.
Actions: block IPs, lock accounts, safe mode, mark data untrusted, forensic export.
"""
from typing import Tuple, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import subprocess
import threading
from config.settings import *
from comm.logger import log_event, log_alert, read_log

# ─── State ────────────────────────────────────────────────────────────────────

blocked_ips = set()
locked_accounts = set()
mission_mode = "NOMINAL"   # NOMINAL, DEGRADED, SAFE
untrusted_sources = set()
response_log = []          # human-readable response record
_lock = threading.Lock()


def _record(action: str, target: str, reason: str):
    entry = {
        "timestamp": time.time(),
        "action": action,
        "target": target,
        "reason": reason,
    }
    with _lock:
        response_log.append(entry)
        if len(response_log) > 500:
            response_log.pop(0)
    log_event("RESPONSE_ACTION", "RESPONSE_ENGINE", {
        "action": action, "target": target, "message": reason
    })
    print(f"🛡️  [{action}] {target} — {reason}")


# ─── Response Actions ─────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str = "Security policy"):
    """Block an IP at the firewall level (iptables if available, else simulate)."""
    with _lock:
        if ip in blocked_ips:
            return
        blocked_ips.add(ip)

    _record("BLOCK_IP", ip, reason)

    # Try real iptables block (will silently fail if no permission)
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        _record("IPTABLES_APPLIED", ip, "iptables DROP rule added")
    except Exception:
        _record("IPTABLES_SIMULATED", ip, "iptables not available — block simulated in memory")


def unblock_ip(ip: str):
    with _lock:
        blocked_ips.discard(ip)
    _record("UNBLOCK_IP", ip, "IP unblocked")


def lock_account(username: str, reason: str = "Security policy"):
    with _lock:
        locked_accounts.add(username)
    _record("LOCK_ACCOUNT", username, reason)
    log_alert("HIGH", "ACCOUNT_LOCKED", "RESPONSE_ENGINE", {
        "message": f"Account {username} locked: {reason}",
        "username": username,
    })


def is_account_locked(username: str) -> bool:
    with _lock:
        return username in locked_accounts


def is_ip_blocked(ip: str) -> bool:
    with _lock:
        return ip in blocked_ips


def enter_safe_mode(reason: str = "Threat detected"):
    """Transition mission to safe mode — restrict high-risk commands."""
    global mission_mode
    with _lock:
        if mission_mode == "SAFE":
            return
        mission_mode = "SAFE"
    _record("ENTER_SAFE_MODE", "MISSION", reason)
    log_alert("CRITICAL", "SAFE_MODE_ACTIVATED", "RESPONSE_ENGINE", {
        "message": f"Mission entered SAFE MODE: {reason}",
    })


def enter_degraded_mode(reason: str):
    global mission_mode
    with _lock:
        if mission_mode in ("SAFE",):
            return
        mission_mode = "DEGRADED"
    _record("ENTER_DEGRADED_MODE", "MISSION", reason)


def restore_nominal():
    global mission_mode
    with _lock:
        mission_mode = "NOMINAL"
    _record("RESTORE_NOMINAL", "MISSION", "Threat cleared, nominal operations resumed")


def get_mission_mode() -> str:
    with _lock:
        return mission_mode


def mark_source_untrusted(source_id: str, reason: str):
    with _lock:
        untrusted_sources.add(source_id)
    _record("MARK_UNTRUSTED", source_id, reason)
    log_alert("HIGH", "SOURCE_UNTRUSTED", "RESPONSE_ENGINE", {
        "message": f"Source {source_id} marked untrusted: {reason}",
    })


def is_source_untrusted(source_id: str) -> bool:
    with _lock:
        return source_id in untrusted_sources


def export_forensic_snapshot(output_path: str = "logs/forensic_snapshot.json"):
    """Export a forensic snapshot of all logs for incident investigation."""
    snapshot = {
        "generated_at": time.time(),
        "mission_mode": get_mission_mode(),
        "blocked_ips": list(blocked_ips),
        "locked_accounts": list(locked_accounts),
        "untrusted_sources": list(untrusted_sources),
        "response_log": response_log[-100:],
        "recent_alerts": read_log(ALERT_LOG, 50),
        "recent_commands": read_log(COMMAND_LOG, 50),
        "recent_events": read_log(EVENTS_LOG, 50),
        "recent_telemetry": read_log(TELEMETRY_LOG, 20),
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(snapshot, f, indent=2)
    _record("FORENSIC_EXPORT", output_path, "Snapshot exported for investigation")
    return output_path


# ─── Policy Engine ────────────────────────────────────────────────────────────

HIGH_RISK_ACTIONS = {"SET_MODE", "TOGGLE_PAYLOAD", "RESET_SUBSYSTEM"}


def evaluate_command_policy(command: dict) -> Tuple[bool, str]:
    """
    Policy gate: should this command be allowed through?
    Returns (allowed: bool, reason: str)
    """
    source = command.get("source", "UNKNOWN")
    action = command.get("action", "")

    # Blocked source?
    # (IP-based blocking handled at HTTP layer)

    # Untrusted source?
    if is_source_untrusted(source):
        return False, f"Source {source} is marked untrusted"

    # Safe mode: block high-risk commands
    mode = get_mission_mode()
    if mode == "SAFE" and action in HIGH_RISK_ACTIONS:
        return False, f"Mission in SAFE MODE — {action} blocked"

    # No token
    if not command.get("token"):
        return False, "No auth token"

    return True, "Policy OK"


# ─── Alert → Response Dispatcher ─────────────────────────────────────────────

def respond_to_alert(alert: dict):
    """
    Auto-respond to an incoming alert dict.
    This is the core response automation logic.
    """
    alert_type = alert.get("alert_type", "")
    source = alert.get("source", "UNKNOWN")
    severity = alert.get("severity", "LOW")

    if alert_type == "DOS_ATTACK":
        block_ip(source, f"DoS pattern detected: {alert.get('message', '')}")

    elif alert_type == "BRUTE_FORCE":
        username = alert.get("username", "unknown")
        lock_account(username, "Brute force detected")
        if severity == "CRITICAL":
            block_ip(source, "Repeated brute force attempts")

    elif alert_type == "COMMAND_INJECTION":
        block_ip(source, "Unauthorized command injection attempt")
        enter_degraded_mode("Command injection detected")

    elif alert_type == "REPLAY_ATTACK":
        mark_source_untrusted(source, "Replay attack detected")

    elif alert_type == "TELEMETRY_TAMPER":
        mark_source_untrusted(source, "Telemetry integrity failure")
        enter_safe_mode("Telemetry tampering detected — switching to safe mode")

    elif alert_type == "ATTACK_CHAIN_DETECTED":
        enter_safe_mode(f"Attack chain: {alert.get('message', '')}")
        export_forensic_snapshot()

    elif alert_type == "LOG_TAMPERING":
        export_forensic_snapshot("logs/forensic_log_tamper.json")
        log_alert("CRITICAL", "ACTIVE_COMPROMISE", "RESPONSE_ENGINE", {
            "message": "Log tampering detected — possible active intrusion",
        })


def get_response_state() -> dict:
    """Return current response state for dashboard."""
    with _lock:
        return {
            "mission_mode": mission_mode,
            "blocked_ips": list(blocked_ips),
            "locked_accounts": list(locked_accounts),
            "untrusted_sources": list(untrusted_sources),
            "response_log": response_log[-20:],
        }


# ─── Background Alert Watcher ─────────────────────────────────────────────────

# Tracked by timestamp, not list length/index. read_log() only returns the
# last 200 lines — once total alerts pass 200, an index-based cursor
# (previously: `alerts[_last_alert_count:]`) permanently plateaus at 200 and
# every alert after that point is silently never responded to. Timestamps
# are monotonic and immune to that truncation.
_last_seen_ts = 0.0

def alert_watcher_loop():
    """Watch the alert log and auto-respond to new alerts."""
    global _last_seen_ts
    print("🛡️  Response engine active...")
    while True:
        try:
            alerts = read_log(ALERT_LOG, 200)
            new_alerts = [a for a in alerts if a.get("_ts", 0) > _last_seen_ts]
            for alert in new_alerts:
                respond_to_alert(alert)
            if alerts:
                _last_seen_ts = max(a.get("_ts", 0) for a in alerts)
        except Exception as e:
            pass
        time.sleep(3)


def run():
    t = threading.Thread(target=alert_watcher_loop, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    run()
    while True:
        time.sleep(1)
