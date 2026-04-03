# Hydroficient
### Hotel Water Infrastructure Monitoring System with TLS Security

Built for Grand Marina Hotel. Simulates a real-time water monitoring network
using MQTT, with full TLS encryption, mutual TLS authentication, replay attack
defenses, and a live web security dashboard.

---

## What It Does

Sensors publish live pressure and flow data from three locations across the hotel.
A dashboard receives and displays the data in real time.
All communication is encrypted and authenticated using TLS certificates generated in Python.
Every message is validated for tampering, freshness, and duplicate detection before it is accepted.

---

## Security Features

- One-way TLS: Clients verify the broker using a custom Certificate Authority
- Mutual TLS (mTLS): The broker also verifies each device using unique client certificates
- HMAC signing: Every message carries a tamper-evident seal. Modified messages are rejected.
- Timestamp validation: Messages older than 30 seconds are rejected. Stops delayed replay attacks.
- Sequence counter: Each message gets a unique number. Duplicates are rejected immediately.
- Certificates generated programmatically using Python's cryptography library
- CA, server, and per-device certificates are all created locally, no third-party tools needed
- Private keys never leave the machine and are excluded from version control

---

## Project Files

| File | Description |
|------|-------------|
| `Sensor.py` | Simulates HYDROLOGIC water sensors publishing pressure and flow data |
| `Sub_dash.py` | Dashboard that subscribes and displays live sensor readings |
| `Sub_dash_DEFEND.py` | Defended subscriber with HMAC, timestamp, and sequence validation plus live dashboard |
| `dashboard_server.py` | WebSocket and HTTP server that powers the live web dashboard |
| `dashboard.html` | Orange-themed live security dashboard at localhost:8000 |
| `cert.py` | Generates CA, server, and per-device certificates for mTLS |
| `experiment_runner.py` | Runs security and performance experiments |
| `identity_test.py` | Tests mTLS identity attack scenarios |
| `defense_tester.py` | Tests replay attack defenses across all configurations |
| `mtls_benchmark.py` | Benchmarks latency between one-way TLS and mTLS |
| `mosquitto_insecure.conf` | Insecure broker config on port 1883 for comparison testing |

---

## How to Run

### Step 1: Install dependencies
```bash
brew install mosquitto
pip install paho-mqtt cryptography websockets
```

### Step 2: Generate certificates
```bash
python3 cert.py
```

### Step 3: Start the TLS broker
```bash
mosquitto -c mosquitto_tls.conf -v
```

### Step 4: Run the defended dashboard
```bash
python3 Sub_dash_DEFEND.py
```

This opens the live security dashboard at http://localhost:8000

### Step 5: Start the sensor
```bash
python3 Sensor.py
```

---

## How the Defense Works

Every incoming message goes through three checks before it is accepted:

1. HMAC verification: The message signature is recalculated and compared. Any tampering breaks the seal and the message is rejected.
2. Timestamp check: Messages older than 30 seconds are rejected. Stops delayed replay attacks.
3. Sequence counter: Each device tracks the last sequence number seen. Duplicate or out-of-order numbers are rejected. Stops immediate replay attacks.

All three defenses together achieve 100% rejection across all attack types tested.

---

## Devices

| Device ID | Location |
|-----------|----------|
| HYDROLOGIC-001 | Main Building |
| HYDROLOGIC-002 | Pool and Spa Wing |
| HYDROLOGIC-003 | Kitchen and Laundry |

---

## Running Experiments

```bash
# Eavesdropper test
python3 experiment_runner.py --mode publish --tls off --count 5
python3 experiment_runner.py --mode publish --tls on --count 5

# Latency comparison
python3 experiment_runner.py --mode latency --tls off --count 50
python3 experiment_runner.py --mode latency --tls on --count 50

# Stress test
python3 experiment_runner.py --mode stress --tls on --rate 10 --duration 30

# Identity attack tests
python3 identity_test.py --mode all

# Replay defense tests
python3 defense_tester.py --defense none --attack all
python3 defense_tester.py --defense timestamp --attack all
python3 defense_tester.py --defense counter --attack all
python3 defense_tester.py --defense all --attack all
```

---

## Technologies

- Python 3
- MQTT (Mosquitto broker)
- TLS and mTLS encryption
- HMAC-SHA256 message signing
- WebSocket (live dashboard)
- Paho MQTT library
- Cryptography library (certificate generation)
- Git and GitHub

---

## Security Note

The `certs/` folder and `cert.py` are excluded from this repository.
Run `cert.py` locally to generate your own certificates before starting the system.
