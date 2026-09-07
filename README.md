# OrbitalShield 🛰️
## Space Mission Cyber Defense Platform

> Detects, correlates, and responds to cyber threats in a simulated satellite-ground mission environment.

---

## What it does

OrbitalShield simulates a complete space mission communication environment and monitors it for cyberattacks in real time. It combines:

- **Mission simulation** — a satellite emitting live telemetry + accepting commands, a ground station receiving and forwarding traffic
- **6 attack scenarios** — replay attacks, command injection, telemetry tampering, DoS, brute force, log tampering
- **Detection engine** — signature + behavioral + correlation-based detection with a correlation engine that chains multiple alerts into attack narratives
- **Response engine** — automated IP blocking, account locking, safe mode activation, forensic snapshots
- **Live dashboard** — real-time mission health, telemetry chart, alert feed, attack timeline, command history

---

## Architecture

```
orbitalshield/
├── config/           # Central settings (ports, thresholds, IDs)
├── auth/             # Token auth, HMAC signing, nonce replay protection
├── comm/             # Structured JSONL logger
├── simulator/
│   ├── satellite.py       # Satellite node (telemetry + command API)
│   └── ground_station.py  # Ground station (relay + login endpoint)
├── detection/
│   └── engine.py          # All detection logic + correlation engine
├── response/
│   └── engine.py          # Automated defensive actions + policy engine
├── threat_emulator/
│   └── attacks.py         # All 6 attack scripts
├── dashboard/
│   ├── api_server.py      # Aggregates all data for the frontend
│   └── index.html         # Live mission control UI (open in browser)
├── logs/                  # All JSONL event logs (auto-created)
└── run.py                 # Start everything
```

---

## Quick Start

### Requirements
- Python 3.10+
- No external dependencies (stdlib only)

### Run the full platform
```bash
cd orbitalshield
python run.py
```

### Run with attack simulation (demo mode)
```bash
python run.py --demo
```
Starts all services, waits 10 seconds, then fires all 6 attack scenarios automatically.

### Open the dashboard
After starting, open `dashboard/index.html` in your browser. It connects to the API at `http://127.0.0.1:9004`.

---

## Attack Scenarios

Run individual attacks while the platform is running:

```bash
# In a second terminal, from the orbitalshield/ directory:
python threat_emulator/attacks.py replay       # Replay attack
python threat_emulator/attacks.py inject       # Command injection
python threat_emulator/attacks.py dos          # Denial of service flood
python threat_emulator/attacks.py bruteforce   # Brute force login
python threat_emulator/attacks.py tamper       # Telemetry tampering
python threat_emulator/attacks.py logtamper    # Log gap injection
python threat_emulator/attacks.py all          # All scenarios
```

---

## What each attack tests

| Attack | What it simulates | Detection | Response |
|---|---|---|---|
| Replay | Reusing a captured command packet | Nonce check | Block source, mark untrusted |
| Injection | Sending commands without auth / from unknown source | Token + source validation | Block IP, degraded mode |
| DoS | Flooding the ground station with requests | Rate threshold (50 req/5s) | Block IP |
| Brute Force | Repeated failed logins | Failed login counter | Lock account, block IP |
| Telemetry Tamper | Mutating telemetry + breaking checksum | HMAC + delta checks | Safe mode, mark untrusted |
| Log Tamper | Creating timestamp gaps in logs | Gap detection | Forensic snapshot |

---

## Log files

All activity is written to `logs/` as JSONL (one JSON object per line):

| File | Contents |
|---|---|
| `logs/telemetry.jsonl` | Every telemetry reading |
| `logs/commands.jsonl` | Every command + outcome |
| `logs/alerts.jsonl` | All detection alerts |
| `logs/events.jsonl` | System events |
| `logs/forensic_snapshot.json` | Auto-exported during attack chains |

---

## Security concepts demonstrated

- Network monitoring and intrusion detection
- Token-based authentication + HMAC message integrity
- Nonce-based replay protection
- Behavioral anomaly detection (delta checks, rate analysis)
- Correlated multi-stage attack detection
- Automated incident response
- Mission-continuity safe mode policy
- Forensic evidence collection
- Domain-specific threat modeling (space systems)

---

## Ports

| Service | Port |
|---|---|
| Satellite API | 9001 |
| Ground Station API | 9002 |
| Dashboard API | 9004 |

---

## Resume bullet points

```
OrbitalShield – Space Mission Cyber Defense Platform
• Designed and built a simulated satellite-ground mission environment to study
  cybersecurity threats across telemetry, command, and ground control channels.
• Integrated custom Python detection logic to identify replay attacks, unauthorized
  command injection, telemetry tampering, DoS patterns, and brute force login attempts.
• Developed a correlation engine that chains multiple alert types into attack narratives
  (e.g., brute force → command injection → telemetry compromise = ACTIVE COMPROMISE).
• Built an automated response engine to block malicious IPs, lock compromised accounts,
  activate mission safe mode, and export forensic snapshots in real time.
• Deployed a live monitoring dashboard visualizing telemetry, attack timelines,
  command histories, and node health for mission operators.
```

---

## Future scope

- Suricata/Zeek integration for real packet-level monitoring
- ML-based anomaly detection on telemetry time series
- CCSDS-inspired message framing (AOS/TC frame structure)
- Multi-satellite simulation
- MITRE ATT&CK for Space mapping
- Cloud deployment with persistent dashboard
- Paper/writeup: "Cyber Threat Detection for Space-Ground Communication Systems"
