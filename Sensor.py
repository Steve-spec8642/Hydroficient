import paho.mqtt.client as mqtt
import ssl
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

TLS_CONFIG = {
    "ca_certs": "certs/ca.pem",
    "broker_host": "localhost",
    "broker_port": 8883,
}

class WaterSensorMQTT:
    def __init__(self, device_id, location, broker="localhost", port=1883):
        self.device_id = device_id
        self.location = location
        self.counter = 0

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.tls_set(
            ca_certs=TLS_CONFIG["ca_certs"],
            certfile=None,
            keyfile=None,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS,
        )
        self.client.connect(TLS_CONFIG["broker_host"], TLS_CONFIG["broker_port"])
        self.client.loop_start()

        self.topic = f"hydroficient/grandmarina/sensors/{self.location}/readings"

        self.base_pressure_up = 82
        self.base_pressure_down = 76
        self.base_flow = 40

    def get_reading(self):
        self.counter += 1
        return {
            "device_id": self.device_id,
            "location": self.location,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "counter": self.counter,
            "pressure_upstream": round(self.base_pressure_up + random.uniform(-2, 2), 1),
            "pressure_downstream": round(self.base_pressure_down + random.uniform(-2, 2), 1),
            "flow_rate": round(self.base_flow + random.uniform(-3, 3), 1),
        }

    def publish_reading(self):
        reading = self.get_reading()
        self.client.publish(self.topic, json.dumps(reading))
        return reading

    def run_continuous(self, interval=2):
        print(f"Starting device: {self.device_id}")
        print(f"Location: {self.location}")
        print(f"Publishing to: {self.topic}")
        print(f"Interval: {interval} seconds")
        print("-" * 40)
        try:
            while True:
                reading = self.publish_reading()
                print(f"[{reading['counter']}] Pressure: {reading['pressure_upstream']}/{reading['pressure_downstream']} PSI, Flow: {reading['flow_rate']} gal/min")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nSensor stopped.")
            self.client.loop_stop()
            self.client.disconnect()

# --- Run ---
sensor = WaterSensorMQTT(device_id="GM-HYDROLOGIC-01", location="main-building")
sensor.run_continuous(interval=2)