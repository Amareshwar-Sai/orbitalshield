"""
OrbitalShield - Threat Emulator
Attack simulation scripts. Run individually for targeted testing.

Usage:
    python threat_emulator/attacks.py replay
    python threat_emulator/attacks.py inject
    python threat_emulator/attacks.py dos
    python threat_emulator/attacks.py bruteforce
    python threat_emulator/attacks.py tamper
    python threat_emulator/attacks.py all
"""
from typing import Tuple, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import threading
import urllib.request
import urllib.error
from config.settings import *
from auth.integrity import sign_message, generate_token, compute_checksum


def _post(port: int, path: str, data: dict) -> Tuple[int, dict]:
    """Helper: POST JSON to a service."""
    url = f"http://{HOST}:{port}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


def _get(port: int, path: str) -> Tuple[int, dict]:
    url = f"http://{HOST}:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except Exception as e:
        return 0, {"error": str(e)}


# ─── Attack 1: Replay Attack ──────────────────────────────────────────────────

def attack_replay(rounds: int = 3):
    """
    Capture a legitimate command (with real nonce), then replay it.
    First send is allowed; all replays should be detected and blocked.
    """
    print("\n" + "="*60)
    print("🎭 ATTACK: REPLAY ATTACK")
    print("="*60)

    # Build a legitimate-looking command with a real token + nonce
    token = generate_token(GROUND_STATION_ID)
    command = {
        "command_id": "CMD-REPLAY-TEST-001",
        "source": GROUND_STATION_ID,
        "target": SATELLITE_ID,
        "action": "PING",
        "parameters": {},
        "token": token,
        "timestamp": time.time(),
    }
    command = sign_message(command)  # Adds nonce + checksum

    print(f"📦 Captured command nonce: {command['nonce'][:20]}...")

    for i in range(rounds):
        code, resp = _post(SATELLITE_PORT, "/command", command)
        if i == 0:
            print(f"  [Round 1 - Original]  HTTP {code}: {resp}")
        else:
            print(f"  [Round {i+1} - REPLAY]  HTTP {code}: {resp}  ← should be BLOCKED")
        time.sleep(0.5)

    print("✅ Replay attack scenario complete.\n")


# ─── Attack 2: Command Injection ─────────────────────────────────────────────

def attack_command_injection():
    """
    Send commands from an unauthorized source without valid credentials.
    """
    print("\n" + "="*60)
    print("💉 ATTACK: COMMAND INJECTION")
    print("="*60)

    scenarios = [
        # No token, unknown source
        {
            "command_id": "CMD-INJECT-001",
            "source": "ATTACKER_NODE_42",
            "target": SATELLITE_ID,
            "action": "SET_MODE",
            "parameters": {"mode": "EMERGENCY"},
            "timestamp": time.time(),
        },
        # Valid-looking source but no token
        {
            "command_id": "CMD-INJECT-002",
            "source": GROUND_STATION_ID,
            "target": SATELLITE_ID,
            "action": "TOGGLE_PAYLOAD",
            "parameters": {},
            "timestamp": time.time(),
            # No token field
        },
        # Tampered checksum
        {
            "command_id": "CMD-INJECT-003",
            "source": GROUND_STATION_ID,
            "target": SATELLITE_ID,
            "action": "RESET_SUBSYSTEM",
            "parameters": {"subsystem": "COMM"},
            "token": generate_token(GROUND_STATION_ID),
            "nonce": "fake-nonce-0001",
            "checksum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": time.time(),
        },
    ]

    for i, cmd in enumerate(scenarios, 1):
        code, resp = _post(SATELLITE_PORT, "/command", cmd)
        print(f"  [Injection {i}] HTTP {code}: {resp}  ← should be REJECTED")
        time.sleep(0.3)

    print("✅ Command injection scenarios complete.\n")


# ─── Attack 3: Telemetry Tampering ───────────────────────────────────────────

def attack_telemetry_tamper():
    """
    Fetch real telemetry, mutate values, break checksum.
    The detection engine should flag integrity failure.
    """
    print("\n" + "="*60)
    print("📡 ATTACK: TELEMETRY TAMPERING")
    print("="*60)

    code, telem = _get(SATELLITE_PORT, "/telemetry")
    if code != 200:
        print(f"  Could not fetch telemetry: {telem}")
        return

    print(f"  Original battery: {telem.get('battery_pct')}%")
    print(f"  Original checksum: {telem.get('checksum', 'none')[:20]}...")

    # Mutate value but keep old checksum
    telem["battery_pct"] = 99.9
    telem["temperature_c"] = -999.0  # physically impossible
    telem["mode"] = "NOMINAL"

    print(f"  Tampered battery: {telem.get('battery_pct')}%")
    print(f"  Tampered temp: {telem.get('temperature_c')}°C")
    print(f"  Checksum still: {telem.get('checksum', 'none')[:20]}... ← stale")

    # Relay the tampered packet to the ground station's real ingestion
    # endpoint. This runs through the actual verify_and_store_telemetry()
    # pipeline — the same checksum check real telemetry goes through — so
    # the resulting TELEMETRY_TAMPER alert (if any) is a genuine network
    # attack result, not a detector called on our own in-process copy of the data.
    code, resp = _post(GROUND_STATION_PORT, "/telemetry/relay", telem)
    print(f"  HTTP {code}: {resp}")
    if resp.get("integrity") == "FAILED":
        print("  🔴 Ground station rejected it — integrity check failed as expected.")
    else:
        print("  ⚪ Ground station accepted it — integrity check did not fire.")

    print("✅ Telemetry tamper scenario complete.\n")


# ─── Attack 4: Denial of Service ─────────────────────────────────────────────

def attack_dos(burst: int = 80, target_port: int = GROUND_STATION_PORT):
    """
    Flood the ground station with rapid requests.
    """
    print("\n" + "="*60)
    print("💣 ATTACK: DENIAL OF SERVICE (Flood)")
    print("="*60)
    print(f"  Sending {burst} requests to port {target_port}...")

    success = 0
    failed = 0

    def fire():
        nonlocal success, failed
        code, _ = _get(target_port, "/status")
        if code == 200:
            success += 1
        else:
            failed += 1

    threads = [threading.Thread(target=fire) for _ in range(burst)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    print(f"  Sent {burst} requests in {elapsed:.2f}s ({burst/elapsed:.0f} req/s)")
    print(f"  Success: {success}, Failed: {failed}")
    print("  (The ground station itself checks request rate on every hit it")
    print("   receives — no detector called from here. Check the dashboard")
    print("   or logs/alerts.jsonl for a live DOS_ATTACK alert.)")
    print("✅ DoS attack scenario complete.\n")


# ─── Attack 5: Brute Force Login ─────────────────────────────────────────────

def attack_bruteforce(attempts: int = 6):
    """
    Brute force the ground station login endpoint.
    """
    print("\n" + "="*60)
    print("🔑 ATTACK: BRUTE FORCE LOGIN")
    print("="*60)

    passwords = ["password123", "admin", "satellite", "ground123_wrong",
                 "orbit2025", "1234567890", "letmein"]

    for i in range(min(attempts, len(passwords))):
        code, resp = _post(GROUND_STATION_PORT, "/login", {
            "username": "ops_admin",
            "password": passwords[i],
        })
        print(f"  [Attempt {i+1}] pwd='{passwords[i]}' → HTTP {code}: {resp.get('error', resp.get('message', ''))}")
        time.sleep(0.2)

    print("✅ Brute force attack scenario complete.\n")


# ─── Attack 6: Log Tampering Simulation ──────────────────────────────────────

def attack_log_tamper():
    """
    Silently edit a real, already-written log entry on disk — no detector
    called from here at all. This models an attacker (or insider) with
    filesystem access trying to alter the evidence trail after the fact.
    The live detection engine's own hash-chain check (verify_log_chain,
    run every 5s in monitor_loop) is what's supposed to notice this
    independently — this attack just makes the edit and waits.
    """
    print("\n" + "="*60)
    print("📋 ATTACK: LOG TAMPERING (Editing Real Evidence)")
    print("="*60)

    target_log = EVENTS_LOG
    if not os.path.exists(target_log):
        print(f"  {target_log} doesn't exist yet — let the platform run a bit first.")
        return

    with open(target_log, "r") as f:
        lines = f.readlines()
    if len(lines) < 2:
        print("  Not enough log entries yet to tamper with meaningfully.")
        return

    idx = len(lines) // 2
    try:
        rec = json.loads(lines[idx])
    except Exception:
        print(f"  Could not parse line {idx} — picking another isn't worth the complexity here, skipping.")
        return

    original_message = rec.get("message", "")
    rec["message"] = original_message + " [SILENTLY TAMPERED]"
    lines[idx] = json.dumps(rec) + "\n"  # note: _hash is now stale — that's the point

    with open(target_log, "w") as f:
        f.writelines(lines)

    print(f"  ✏️  Edited entry #{idx} of {target_log} directly on disk.")
    print(f"      '{original_message}' → '{rec['message']}'")
    print("  No detector called manually. The live monitor_loop() checks every")
    print("  log's hash chain every 5s — watch logs/alerts.jsonl for a")
    print("  LOG_TAMPERING alert to appear on its own within the next few seconds.")
    print("✅ Log tamper scenario complete.\n")


# ─── All Attacks ──────────────────────────────────────────────────────────────

def run_all():
    print("\n" + "█"*60)
    print("  ORBITALSHIELD — FULL ATTACK SIMULATION SUITE")
    print("█"*60)
    time.sleep(1)
    attack_command_injection()
    time.sleep(1)
    attack_replay()
    time.sleep(1)
    attack_bruteforce()
    time.sleep(1)
    attack_dos(burst=60)
    time.sleep(1)
    attack_telemetry_tamper()
    time.sleep(1)
    attack_log_tamper()
    print("\n✅ All attack scenarios complete. Check logs/ and the dashboard.\n")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    dispatch = {
        "replay": attack_replay,
        "inject": attack_command_injection,
        "dos": attack_dos,
        "bruteforce": attack_bruteforce,
        "tamper": attack_telemetry_tamper,
        "logtamper": attack_log_tamper,
        "all": run_all,
    }
    fn = dispatch.get(cmd)
    if fn:
        fn()
    else:
        print(f"Unknown attack: {cmd}")
        print(f"Available: {list(dispatch.keys())}")
