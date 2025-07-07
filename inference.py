#inference OG
from scapy.all import sniff, TCP, IP
from datetime import datetime
from sklearn.ensemble import IsolationForest
import pickle
import json
import numpy as np

LOG_FILE = "packet_log.json"
MODEL_FILE = "anomaly_model.pkl"

# Load trained model
with open(MODEL_FILE, "rb") as f:
    model = pickle.load(f)

# ---------- Feature Extractor ----------
def extract_features(packet):
    return np.array([[
        len(packet),                                 # Total packet size
        packet[TCP].window,                          # TCP window size
        packet[TCP].dataofs,                         # TCP data offset
        int(packet[TCP].flags),                      # TCP flags as int
        len(bytes(packet[TCP].payload))              # Payload size
    ]])

# ---------- Handle incoming packets ----------
def handle_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 1883:
        payload = bytes(packet[TCP].payload)

        # Ignore handshake and control packets with no payload
        if len(payload) == 0:
            return

        features = extract_features(packet)
        prediction = model.predict(features)[0]  # -1 = anomaly

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        anomaly = (prediction == -1)

        log = {
            "timestamp": timestamp,
            "src": str(src_ip),
            "dst": str(dst_ip),
            "length": int(features[0][-1]),
            "anomaly": bool(anomaly)
        }

        print(f"[{'🔴 Anomaly' if anomaly else '🟢 Normal'}] {timestamp} | {src_ip} → {dst_ip} | Payload Length: {features[0][-1]}")

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log) + "\n")

# ---------- Start sniffing ----------
if __name__ == "__main__":
    print("🚀 MQTT Inference is running...")

    sniff(
        filter="tcp port 1883",
        prn=handle_packet,
        store=0,
        iface="wlan0"  # Change to "eth0" if using Ethernet
    )