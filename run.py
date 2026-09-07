"""
OrbitalShield - Mission Orchestrator
Starts all components: satellite, ground station, detection engine,
response engine, and dashboard API in parallel threads.

Usage:
    python run.py              # Start full platform
    python run.py --demo       # Start + run all attacks after 10s
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import threading
import time
import signal

BANNER = r"""
  ___       _     _ _       _ ____  _     _      _     _
 / _ \ _ __| |__ (_) |_ ___| / ___|| |__ (_) ___| | __| |
| | | | '__| '_ \| | __/ _ \ \___ \| '_ \| |/ _ \ |/ _` |
| |_| | |  | |_) | | ||  __/ |___) | | | | |  __/ | (_| |
 \___/|_|  |_.__/|_|\__\___|_|____/|_| |_|_|\___|_|\__,_|

  Space Mission Cyber Defense Platform
  ─────────────────────────────────────────────────────────
"""

def start_satellite():
    from simulator.satellite import run
    run()

def start_ground_station():
    time.sleep(1)  # Let satellite come up first
    from simulator.ground_station import run
    run()

def start_detection():
    time.sleep(2)
    from detection.engine import run
    t = run()
    t.join()

def start_response():
    time.sleep(2)
    from response.engine import run
    t = run()
    t.join()

def start_dashboard_api():
    time.sleep(2)
    from dashboard.api_server import run
    run()


def main():
    demo_mode = "--demo" in sys.argv

    print(BANNER)
    print("  Starting components...\n")

    # Ensure log dir
    os.makedirs("logs", exist_ok=True)

    components = [
        ("🛰️  Satellite",     start_satellite),
        ("📡 Ground Station", start_ground_station),
        ("🔍 Detection",      start_detection),
        ("🛡️  Response",      start_response),
        ("📊 Dashboard API",  start_dashboard_api),
    ]

    threads = []
    for name, fn in components:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)
        print(f"  ✓ {name} started")

    print(f"""
  ─────────────────────────────────────────────────────────
  🛰️  Satellite API:    http://127.0.0.1:9001
  📡 Ground Station:   http://127.0.0.1:9002
  📊 Dashboard API:    http://127.0.0.1:9004

  🌐 Open dashboard:  dashboard/index.html  (in your browser)
  ─────────────────────────────────────────────────────────
  """)

    if demo_mode:
        print("  ⚡ Demo mode: launching attacks in 10 seconds...")
        time.sleep(10)
        print("  ⚡ Launching attack simulation suite...\n")
        from threat_emulator.attacks import run_all
        run_all()

    print("  Platform running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Shutting down OrbitalShield. Goodbye.\n")


if __name__ == "__main__":
    main()
