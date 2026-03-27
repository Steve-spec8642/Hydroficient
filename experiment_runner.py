import argparse
import ssl
import time
import json
import random
import threading
from datetime import datetime, timezone
from pathlib import Path
import paho.mqtt.client as mqtt

# ============================================
# TLS CONFIGURATION
# ============================================
TLS_CONFIG = {
    "ca_certs": "certs/ca.pem",
    "broker_host": "localhost",
    "broker_port": 8883,
}
INSECURE_CONFIG = {
    "broker_host": "localhost",
    "broker_port": 1883,
}

TOPIC = "grandmarina/sensors/water"


def make_client(tls=True, no_ca=False):
    """Create and configure an MQTT client"""
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    if tls:
        if no_ca:
            # Dangerous: no certificate verification
            client.tls_set(
                ca_certs=None,
                certfile=None,
                keyfile=None,
                cert_reqs=ssl.CERT_NONE,
                tls_version=ssl.PROTOCOL_TLS,
            )
            client.tls_insecure_set(True)
        else:
            ca_path = Path(TLS_CONFIG["ca_certs"])
            if not ca_path.exists():
                print(f"CA certificate not found: {ca_path}")
                print("Run TLS.py first to generate certificates!")
                return None
            client.tls_set(
                ca_certs=TLS_CONFIG["ca_certs"],
                certfile=None,
                keyfile=None,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS,
            )

    return client


def make_sensor_payload(counter):
    return json.dumps({
        "device_id": "GM-HYDROLOGIC-01",
        "location": "main-building",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counter": counter,
        "pressure_upstream": round(82 + random.uniform(-2, 2), 1),
        "pressure_downstream": round(76 + random.uniform(-2, 2), 1),
        "flow_rate": round(40 + random.uniform(-3, 3), 1),
    })


# ============================================
# MODE: PUBLISH
# ============================================
def mode_publish(tls, count):
    print("\n" + "=" * 55)
    print("  EXPERIMENT 1: EAVESDROPPER TEST")
    print(f"  Publishing {count} messages {'WITH TLS' if tls else 'WITHOUT TLS'}")
    print("=" * 55)

    client = make_client(tls=tls)
    if client is None:
        return

    host = TLS_CONFIG["broker_host"] if tls else INSECURE_CONFIG["broker_host"]
    port = TLS_CONFIG["broker_port"] if tls else INSECURE_CONFIG["broker_port"]

    try:
        client.connect(host, port)
        client.loop_start()
        time.sleep(0.5)

        for i in range(1, count + 1):
            payload = make_sensor_payload(i)
            client.publish(TOPIC, payload)
            print(f"  [{i}/{count}] Published: {payload[:60]}...")
            time.sleep(0.5)

        print(f"\n  Done! Published {count} messages on port {port}")
        if not tls:
            print("  ⚠️  These messages were sent in PLAIN TEXT - anyone could read them!")
        else:
            print("  🔒 These messages were encrypted with TLS!")

    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        client.loop_stop()
        client.disconnect()


# ============================================
# MODE: CONNECT (Certificate Test)
# ============================================
def mode_connect(tls, no_ca=False):
    print("\n" + "=" * 55)
    print("  EXPERIMENT 2: CERTIFICATE TEST")
    if no_ca:
        print("  Scenario C: No Certificate Verification (DANGEROUS)")
    else:
        print("  Scenario A: Correct Certificates")
    print("=" * 55)

    client = make_client(tls=tls, no_ca=no_ca)
    if client is None:
        return

    host = TLS_CONFIG["broker_host"] if tls else INSECURE_CONFIG["broker_host"]
    port = TLS_CONFIG["broker_port"] if tls else INSECURE_CONFIG["broker_port"]

    connected = threading.Event()
    failed = threading.Event()

    def on_connect(c, userdata, flags, reason_code, properties):
        if reason_code == 0:
            connected.set()
        else:
            failed.set()

    client.on_connect = on_connect

    try:
        client.connect(host, port)
        client.loop_start()

        if connected.wait(timeout=5):
            print(f"  Result: SUCCESS ✅")
            print(f"  Connected to broker on port {port}")
            if no_ca:
                print("  ⚠️  WARNING: Connected WITHOUT verifying the server certificate!")
                print("  ⚠️  This is dangerous - vulnerable to man-in-the-middle attacks!")
        else:
            print(f"  Result: FAILED ❌")
            print(f"  Could not connect to broker on port {port}")

    except ssl.SSLError as e:
        print(f"  Result: FAILED ❌")
        print(f"  SSL Error: {e}")
        print("  This means the certificate verification failed - connection was rejected!")
    except Exception as e:
        print(f"  Result: FAILED ❌")
        print(f"  Error: {e}")
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except:
            pass


# ============================================
# MODE: GENERATE WRONG CA
# ============================================
def mode_generate_wrong_ca():
    print("\n" + "=" * 55)
    print("  EXPERIMENT 2: Generating Wrong CA Certificate...")
    print("=" * 55)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import timedelta
        import ipaddress

        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA - Not Trusted"),
        ])
        wrong_cert = (
            x509.CertificateBuilder()
            .subject_name(wrong_name)
            .issuer_name(wrong_name)
            .public_key(wrong_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(wrong_key, hashes.SHA256())
        )

        Path("certs").mkdir(exist_ok=True)
        with open("certs/wrong-ca.pem", "wb") as f:
            f.write(wrong_cert.public_bytes(serialization.Encoding.PEM))

        print("  Created: certs/wrong-ca.pem")
        print("  This CA did NOT sign our server certificate")
        print("  Use --mode test-wrong-ca to test with it")

    except ImportError:
        print("  ERROR: cryptography library not installed")
        print("  Run: pip install cryptography")


# ============================================
# MODE: TEST WRONG CA
# ============================================
def mode_test_wrong_ca():
    print("\n" + "=" * 55)
    print("  EXPERIMENT 2: Scenario B - Wrong CA Certificate")
    print("=" * 55)

    wrong_ca = Path("certs/wrong-ca.pem")
    if not wrong_ca.exists():
        print("  ERROR: Run --mode generate-wrong-ca first!")
        return

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    try:
        client.tls_set(
            ca_certs="certs/wrong-ca.pem",
            certfile=None,
            keyfile=None,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS,
        )
        client.connect(TLS_CONFIG["broker_host"], TLS_CONFIG["broker_port"])
        client.loop_start()
        time.sleep(3)
        print("  Result: SUCCESS (unexpected!)")

    except ssl.SSLError as e:
        print(f"  Result: FAILED ❌ (Expected!)")
        print(f"  SSL Error: {e}")
        print("  The wrong CA could not verify the server certificate - connection rejected!")
        print("  This is TLS working correctly! 🔒")
    except Exception as e:
        print(f"  Result: FAILED ❌")
        print(f"  Error: {e}")
        print("  TLS correctly rejected the untrusted certificate!")
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except:
            pass


# ============================================
# MODE: LATENCY (Speed Test)
# ============================================
def mode_latency(tls, count):
    print("\n" + "=" * 55)
    print("  EXPERIMENT 3: SPEED TEST")
    print(f"  Testing latency {'WITH TLS' if tls else 'WITHOUT TLS'} ({count} messages)")
    print("=" * 55)

    host = TLS_CONFIG["broker_host"] if tls else INSECURE_CONFIG["broker_host"]
    port = TLS_CONFIG["broker_port"] if tls else INSECURE_CONFIG["broker_port"]

    latencies = []
    received = threading.Event()

    pub_client = make_client(tls=tls)
    sub_client = make_client(tls=tls)

    if pub_client is None or sub_client is None:
        return

    send_time = [0]

    def on_message(c, userdata, msg):
        latency = (time.time() - send_time[0]) * 1000
        latencies.append(latency)
        received.set()

    sub_client.on_message = on_message

    try:
        pub_client.connect(host, port)
        sub_client.connect(host, port)
        pub_client.loop_start()
        sub_client.loop_start()
        sub_client.subscribe(TOPIC)
        time.sleep(1)

        print(f"  Sending {count} messages and measuring round-trip time...")
        print()

        for i in range(1, count + 1):
            received.clear()
            send_time[0] = time.time()
            pub_client.publish(TOPIC, make_sensor_payload(i))
            received.wait(timeout=5)
            if latencies:
                print(f"  [{i:>3}/{count}] Latency: {latencies[-1]:.2f} ms")

        if latencies:
            avg = sum(latencies) / len(latencies)
            print(f"\n  {'─'*40}")
            print(f"  Messages sent:   {len(latencies)}")
            print(f"  Average latency: {avg:.2f} ms")
            print(f"  Min latency:     {min(latencies):.2f} ms")
            print(f"  Max latency:     {max(latencies):.2f} ms")
            print(f"  {'─'*40}")
            print(f"\n  📋 Record these numbers in your worksheet!")

    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        pub_client.loop_stop()
        sub_client.loop_stop()
        try:
            pub_client.disconnect()
            sub_client.disconnect()
        except:
            pass


# ============================================
# MODE: STRESS TEST
# ============================================
def mode_stress(tls, rate, duration):
    print("\n" + "=" * 55)
    print("  EXPERIMENT 4: STRESS TEST")
    print(f"  Rate: {rate} msg/sec | Duration: {duration}s | TLS: {'ON' if tls else 'OFF'}")
    print("=" * 55)

    host = TLS_CONFIG["broker_host"] if tls else INSECURE_CONFIG["broker_host"]
    port = TLS_CONFIG["broker_port"] if tls else INSECURE_CONFIG["broker_port"]

    client = make_client(tls=tls)
    if client is None:
        return

    sent = [0]
    errors = [0]
    start_time = [0]

    try:
        client.connect(host, port)
        client.loop_start()
        time.sleep(0.5)

        interval = 1.0 / rate
        start_time[0] = time.time()
        end_time = start_time[0] + duration

        print(f"  Running stress test for {duration} seconds...")

        while time.time() < end_time:
            try:
                client.publish(TOPIC, make_sensor_payload(sent[0] + 1))
                sent[0] += 1
            except Exception:
                errors[0] += 1
            time.sleep(interval)

        elapsed = time.time() - start_time[0]
        actual_rate = sent[0] / elapsed
        error_rate = errors[0] / max(sent[0], 1) * 100

        print(f"\n  {'─'*40}")
        print(f"  Messages sent:  {sent[0]}")
        print(f"  Errors:         {errors[0]}")
        print(f"  Actual rate:    {actual_rate:.1f} msg/sec")
        print(f"  Error rate:     {error_rate:.1f}%")
        print(f"  {'─'*40}")

        if error_rate < 5:
            print(f"\n  Result: SUCCESS ✅ (system handled {rate} msg/sec)")
        else:
            print(f"\n  Result: DEGRADED ⚠️ (too many errors at {rate} msg/sec)")

        print(f"\n  📋 Record this result in your worksheet!")

    except Exception as e:
        print(f"  ERROR: {e}")
        print(f"  Result: FAILED ❌")
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except:
            pass


# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hydroficient Experiment Runner")
    parser.add_argument("--mode", required=True,
                        choices=["publish", "connect", "generate-wrong-ca",
                                 "test-wrong-ca", "latency", "stress"],
                        help="Experiment mode")
    parser.add_argument("--tls", default="on", choices=["on", "off"],
                        help="Use TLS (default: on)")
    parser.add_argument("--no-ca", action="store_true",
                        help="Skip CA verification (Experiment 2 Scenario C)")
    parser.add_argument("--count", type=int, default=5,
                        help="Number of messages (default: 5)")
    parser.add_argument("--rate", type=int, default=10,
                        help="Messages per second for stress test (default: 10)")
    parser.add_argument("--duration", type=int, default=30,
                        help="Duration in seconds for stress test (default: 30)")

    args = parser.parse_args()
    tls = args.tls == "on"

    if args.mode == "publish":
        mode_publish(tls=tls, count=args.count)
    elif args.mode == "connect":
        mode_connect(tls=tls, no_ca=args.no_ca)
    elif args.mode == "generate-wrong-ca":
        mode_generate_wrong_ca()
    elif args.mode == "test-wrong-ca":
        mode_test_wrong_ca()
    elif args.mode == "latency":
        mode_latency(tls=tls, count=args.count)
    elif args.mode == "stress":
        mode_stress(tls=tls, rate=args.rate, duration=args.duration)