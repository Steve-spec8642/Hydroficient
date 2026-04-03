"""
identity_tester.py - Identity Attack Simulation Tool
"""

import paho.mqtt.client as mqtt
import ssl
import argparse
import sys
import time
import os

try:
    MQTT_CLIENT_ARGS = {"callback_api_version": mqtt.CallbackAPIVersion.VERSION1}
except AttributeError:
    MQTT_CLIENT_ARGS = {}

BROKER_HOST = "localhost"
BROKER_PORT = 8884
CA_CERT = "certs/ca.pem"
CLIENT_CERT = "certs/device-001.pem"
CLIENT_KEY = "certs/device-001-key.pem"
WRONG_CLIENT_CERT = "certs/wrong-device.pem"
WRONG_CLIENT_KEY = "certs/wrong-device-key.pem"
EXPIRED_CERT = "certs/expired-device.pem"
EXPIRED_KEY = "certs/expired-device-key.pem"

connection_result = {"connected": False, "rc": -1}

class TestResult:
    def __init__(self, name):
        self.name = name
        self.success = None
        self.error = None
        self.expected_outcome = None

    def record_success(self):
        self.success = True

    def record_failure(self, error):
        self.success = False
        self.error = str(error)

    def display(self):
        print("\n" + "=" * 60)
        print(f"TEST: {self.name}")
        print("=" * 60)
        print(f"Expected: {self.expected_outcome}")
        outcome = "CONNECTION SUCCEEDED" if self.success else "CONNECTION FAILED"
        print(f"Actual:   {outcome}")
        if self.error:
            print(f"Error:    {self.error}")
        if self.expected_outcome == "Connection rejected" and not self.success:
            print("\n>>> TEST PASSED - Connection was correctly rejected <<<")
            return True
        elif self.expected_outcome == "Connection succeeds" and self.success:
            print("\n>>> TEST PASSED - Connection succeeded as expected <<<")
            return True
        else:
            print("\n>>> TEST FAILED - Unexpected outcome! <<<")
            return False

def on_connect(client, userdata, flags, rc):
    global connection_result
    connection_result["connected"] = (rc == 0)
    connection_result["rc"] = rc

def test_correct_cert():
    print("\n" + "-" * 60)
    print("SCENARIO A: Correct Client Certificate")
    print("-" * 60)
    result = TestResult("Valid Client Certificate")
    result.expected_outcome = "Connection succeeds"
    try:
        client = mqtt.Client(client_id="test-correct-cert", **MQTT_CLIENT_ARGS)
        client.on_connect = on_connect
        client.tls_set(ca_certs=CA_CERT, certfile=CLIENT_CERT, keyfile=CLIENT_KEY, cert_reqs=ssl.CERT_REQUIRED)
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        if connection_result["connected"]:
            result.record_success()
        else:
            result.record_failure(f"rc={connection_result['rc']}")
        client.disconnect()
    except Exception as e:
        result.record_failure(e)
    return result.display()

def test_no_cert():
    print("\n" + "-" * 60)
    print("SCENARIO B: No Client Certificate")
    print("-" * 60)
    result = TestResult("No Client Certificate")
    result.expected_outcome = "Connection rejected"
    try:
        client = mqtt.Client(client_id="test-no-cert", **MQTT_CLIENT_ARGS)
        client.on_connect = on_connect
        client.tls_set(ca_certs=CA_CERT, cert_reqs=ssl.CERT_REQUIRED)
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        if connection_result["connected"]:
            result.record_success()
        else:
            result.record_failure(f"rc={connection_result['rc']}")
        client.disconnect()
    except ssl.SSLError as e:
        result.record_failure(f"SSL Error: {e}")
    except Exception as e:
        result.record_failure(e)
    return result.display()

def test_wrong_ca():
    print("\n" + "-" * 60)
    print("SCENARIO C: Certificate from Wrong CA")
    print("-" * 60)
    result = TestResult("Wrong CA Certificate")
    result.expected_outcome = "Connection rejected"
    if not os.path.exists(WRONG_CLIENT_CERT):
        print(f"\nNOTE: {WRONG_CLIENT_CERT} not found. Skipping.")
        result.record_failure("Test certificates not created - skipped")
        return result.display()
    try:
        client = mqtt.Client(client_id="test-wrong-ca", **MQTT_CLIENT_ARGS)
        client.on_connect = on_connect
        client.tls_set(ca_certs=CA_CERT, certfile=WRONG_CLIENT_CERT, keyfile=WRONG_CLIENT_KEY, cert_reqs=ssl.CERT_REQUIRED)
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        if connection_result["connected"]:
            result.record_success()
        else:
            result.record_failure(f"rc={connection_result['rc']}")
        client.disconnect()
    except ssl.SSLError as e:
        result.record_failure(f"SSL Error: {e}")
    except Exception as e:
        result.record_failure(e)
    return result.display()

def test_expired():
    print("\n" + "-" * 60)
    print("SCENARIO D: Expired Certificate")
    print("-" * 60)
    result = TestResult("Expired Certificate")
    result.expected_outcome = "Connection rejected"
    if not os.path.exists(EXPIRED_CERT):
        print(f"\nNOTE: {EXPIRED_CERT} not found. Skipping.")
        result.record_failure("Expired certificate not created - skipped")
        return result.display()
    try:
        client = mqtt.Client(client_id="test-expired", **MQTT_CLIENT_ARGS)
        client.on_connect = on_connect
        client.tls_set(ca_certs=CA_CERT, certfile=EXPIRED_CERT, keyfile=EXPIRED_KEY, cert_reqs=ssl.CERT_REQUIRED)
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        if connection_result["connected"]:
            result.record_success()
        else:
            result.record_failure(f"rc={connection_result['rc']}")
        client.disconnect()
    except ssl.SSLError as e:
        result.record_failure(f"SSL Error: {e}")
    except Exception as e:
        result.record_failure(e)
    return result.display()

def run_all_tests():
    global connection_result
    print("=" * 60)
    print("IDENTITY ATTACK SIMULATION SUITE")
    print("The Grand Marina Hotel - mTLS Testing")
    print("=" * 60)
    results = []
    connection_result = {"connected": False, "rc": -1}
    results.append(("A: Correct cert", test_correct_cert()))
    connection_result = {"connected": False, "rc": -1}
    results.append(("B: No cert", test_no_cert()))
    connection_result = {"connected": False, "rc": -1}
    results.append(("C: Wrong CA", test_wrong_ca()))
    connection_result = {"connected": False, "rc": -1}
    results.append(("D: Expired", test_expired()))
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for name, passed in results:
        print(f"  {name}: {'PASS' if passed else 'FAIL'}")
    passed_count = sum(1 for _, passed in results if passed)
    print(f"\n  Total: {passed_count}/{len(results)} tests passed")
    return all(passed for _, passed in results)

def main():
    parser = argparse.ArgumentParser(description="Identity Attack Simulation Tool")
    parser.add_argument("--mode", choices=["test-correct", "test-no-cert", "test-wrong-ca", "test-expired", "all"], default="all")
    args = parser.parse_args()
    if args.mode == "all":
        success = run_all_tests()
    elif args.mode == "test-correct":
        success = test_correct_cert()
    elif args.mode == "test-no-cert":
        success = test_no_cert()
    elif args.mode == "test-wrong-ca":
        success = test_wrong_ca()
    elif args.mode == "test-expired":
        success = test_expired()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
