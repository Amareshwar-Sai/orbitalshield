"""
OrbitalShield - Structured JSON Logger
All events, telemetry, commands, and alerts are written as JSONL.

Every record is hash-chained (each line embeds the SHA-256 of the
previous line plus its own content-hash), so the log itself is
tamper-evident: editing or deleting any line breaks every hash after
it. Writes are file-locked (POSIX flock, best-effort elsewhere) so
this stays correct even when multiple processes append to the same
log file concurrently (e.g. run.py's services + a standalone
threat_emulator/attacks.py invocation).
"""

import json
import time
import os
import hashlib
from config.settings import EVENTS_LOG, TELEMETRY_LOG, COMMAND_LOG, ALERT_LOG, LOG_DIR

try:
    import fcntl
    _HAS_FLOCK = True
except ImportError:
    _HAS_FLOCK = False  # e.g. Windows — chain still works, just not cross-process-safe

GENESIS_HASH = "0" * 64


def _ensure_logs():
    os.makedirs(LOG_DIR, exist_ok=True)


def _read_last_hash(f) -> str:
    """Scan the (already-open, already-locked) file for the hash of its last record."""
    f.seek(0)
    last_hash = GENESIS_HASH
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            last_hash = rec.get("_hash", last_hash)
        except Exception:
            continue
    return last_hash


def _write(path: str, record: dict):
    _ensure_logs()
    record["_ts"] = time.time()
    with open(path, "a+") as f:
        if _HAS_FLOCK:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            prev_hash = _read_last_hash(f)
            record["_prev_hash"] = prev_hash
            payload = json.dumps(record, sort_keys=True)
            record["_hash"] = hashlib.sha256(payload.encode()).hexdigest()
            f.write(json.dumps(record) + "\n")
            f.flush()
        finally:
            if _HAS_FLOCK:
                fcntl.flock(f, fcntl.LOCK_UN)


def verify_log_chain(path: str, limit: int = 500) -> tuple:
    """
    Verify a log file's hash chain is intact within the last `limit` records.
    Returns (valid: bool, reason: str). Used by the detection engine to catch
    tampering that a timestamp-gap check alone would miss (e.g. an edited
    line with a timestamp close to its neighbors).
    """
    if not os.path.exists(path):
        return True, "No log file yet"
    with open(path) as f:
        lines = f.readlines()
    if limit:
        lines = lines[-limit:]
    expected_prev = None
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            return False, f"Corrupt/unparseable line at offset {i}"
        stored_hash = rec.get("_hash")
        stored_prev = rec.get("_prev_hash")
        check = {k: v for k, v in rec.items() if k != "_hash"}
        recomputed = hashlib.sha256(json.dumps(check, sort_keys=True).encode()).hexdigest()
        if stored_hash != recomputed:
            return False, f"Hash mismatch at offset {i} — record content altered"
        if expected_prev is not None and stored_prev != expected_prev:
            return False, f"Chain broken at offset {i} — record inserted or deleted"
        expected_prev = stored_hash
    return True, "Chain intact"


# ─── Alert hooks ─────────────────────────────────────────────────────────────
# Lets other modules (e.g. the correlation engine) react to every alert
# without comm.logger having to import them back (which would be circular,
# since detection/response import comm.logger already).

_alert_hooks = []


def register_alert_hook(fn):
    """fn(severity, alert_type, source, detail) — called after every log_alert()."""
    _alert_hooks.append(fn)


def log_event(event_type: str, source: str, detail: dict):
    _write(EVENTS_LOG, {"type": event_type, "source": source, **detail})


def log_telemetry(telemetry: dict):
    _write(TELEMETRY_LOG, telemetry)


def log_command(command: dict, status: str, reason: str = ""):
    _write(COMMAND_LOG, {**command, "status": status, "reason": reason})


def log_alert(severity: str, alert_type: str, source: str, detail: dict):
    record = {
        "severity": severity,
        "alert_type": alert_type,
        "source": source,
        **detail,
    }
    _write(ALERT_LOG, record)
    prefix = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
    print(f"{prefix} [{severity}] {alert_type} from {source}: {detail.get('message', '')}")
    for hook in _alert_hooks:
        try:
            hook(severity, alert_type, source, detail)
        except Exception:
            pass  # a broken hook must never take down alert logging itself


def read_log(path: str, limit: int = 100) -> list:
    """Read last N lines from a JSONL log file."""
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = f.readlines()
    records = []
    for line in lines[-limit:]:
        try:
            records.append(json.loads(line.strip()))
        except Exception:
            pass
    return records
