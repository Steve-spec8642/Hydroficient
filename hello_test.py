import paho.mqtt.client as mqtt
import ssl
import json
from datetime import datetime

TLS_CONFIG = {
    "ca_certs": "certs/ca.pem",
    "broker_host": "localhost",
    "broker_port": 8883,
}

def on_connect(client, userdata, flags, reason_code, properties):
    print("=" * 60)
    print("  GRAND MARINA WATER MONITORING DASHBOARD")
    print(f"  Connected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    client.subscribe("hydroficient/grandmarina/#")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())

        # Calculate pressure differential
        pressure_diff = round(data["pressure_upstream"] - data["pressure_downstream"], 1)

        print("\n" + "─" * 40)
        print(f"  Location:  {data.get('location', 'unknown')}")
        print(f"  Device ID: {data.get('device_id', 'unknown')}")
        print(f"  Time:      {data.get('timestamp', 'unknown')}")
        print(f"  Count:     #{data.get('counter', '?')}")
        print("─" * 40)
        print(f"  Pressure (upstream):   {data['pressure_upstream']:>6} PSI")
        print(f"  Pressure (downstream): {data['pressure_downstream']:>6} PSI")
        print(f"  Flow rate:             {data['flow_rate']:>6} gal/min")
        print(f"  Pressure differential: {pressure_diff:>6} PSI")

    except (json.JSONDecodeError, KeyError) as e:
        print(f"\n[WARNING] Could not parse message on topic '{msg.topic}': {e}")
        print(f"  Raw payload: {msg.payload.decode()}")


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.tls_set(
    ca_certs=TLS_CONFIG["ca_certs"],
    certfile=None,
    keyfile=None,
    cert_reqs=ssl.CERT_REQUIRED,
    tls_version=ssl.PROTOCOL_TLS,
)
client.connect(TLS_CONFIG["broker_host"], TLS_CONFIG["broker_port"])
client.loop_forever()