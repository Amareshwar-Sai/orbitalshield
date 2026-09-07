
import os 



# OrbitalShield - Central Configuration

SATELLITE_ID = "SAT-ALPHA-01"
GROUND_STATION_ID = "GS-BANGALORE-01"
MISSION_CONTROL_ID = "MC-OPS-01"

# Ports
SATELLITE_PORT = 9001
GROUND_STATION_PORT = 9002
MISSION_CONTROL_PORT = 9003
DASHBOARD_API_PORT = 9004

# Host
HOST = "127.0.0.1"

# Security
# Security
# Reads from the environment first. The literal string below is a demo-only
# fallback so the project still runs out of the box with zero setup — it is
# NOT a real secret and is fine to have in git, but if you ever point this
# at anything beyond localhost, set ORBITALSHIELD_SECRET_KEY yourself and
# this fallback is never used.
SECRET_KEY = os.environ.get("ORBITALSHIELD_SECRET_KEY", "orbitalshield-demo-key-change-me")
TOKEN_VALIDITY_SECONDS = 300
NONCE_EXPIRY_SECONDS = 60

# Telemetry
TELEMETRY_INTERVAL_SECONDS = 2

# Thresholds for anomaly detection
BATTERY_MIN = 10.0
BATTERY_MAX = 100.0
TEMP_MIN = -40.0
TEMP_MAX = 85.0
MAX_COMMANDS_PER_MINUTE = 10
MAX_FAILED_LOGINS = 3
MAX_PACKET_RATE = 50  # per second before DoS alert

# Log paths
LOG_DIR = "logs"
EVENTS_LOG = "logs/events.jsonl"
TELEMETRY_LOG = "logs/telemetry.jsonl"
COMMAND_LOG = "logs/commands.jsonl"
ALERT_LOG = "logs/alerts.jsonl"
