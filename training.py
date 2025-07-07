from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import time
import pickle
import re
import signal
import sys
import json
from collections import deque
from math import log2

# File paths
LOG_FILE = "mqtt_training_packets.json"
MODEL_FILE = "anomaly_model.pkl"
SCALER_FILE = "scaler.pkl"
FEATURE_FILE = "baseline_features.npy"

# Global variables
packet_data = []
last_packet_time = time.time()
ip_window = deque(maxlen=10)
packet_timestamps = deque(maxlen=100)

def calculate_ip_entropy():
    if not ip_window:
        return 0.0
    ip_counts = {}
    for ip in ip_window:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    total = len(ip_window)
    entropy = 0.0
    for count in ip_counts.values():
        prob = count / total
        entropy -= prob * log2(prob)
    return entropy

def calculate_packet_rate(current_time):
    if not packet_timestamps:
        return 0.0
    while packet_timestamps and current_time - packet_timestamps[0] > 1:  # 1-second window
        packet_timestamps.popleft()
    return len(packet_timestamps) / 1.0  # Rate in packets per second

def encode_tcp_flags(tcp_layer):
    if not tcp_layer:
        return 0
    flags = tcp_layer.flags
    return int(flags)

def is_valid_payload(payload, topic):
    try:
        if not payload.startswith('1'):
            return False
        rest = payload[1:]
        if not rest.startswith(topic):
            return False
        value_str = rest[len(topic):]
        value = float(value_str)
        if topic == "esp32/temperature" and not (20.0 <= value <= 35.0):
            return False
        elif topic == "esp32/humidity" and not (30.0 <= value <= 80.0):
            return False
        elif topic == "esp32/pressure" and not (980.0 <= value <= 1050.0):
            return False
        elif topic == "esp32/altitude" and not (50.0 <= value <= 1500.0):
            return False
        return True
    except (ValueError, IndexError):
        return False

def extract_features(packet, payload, topic):
    global last_packet_time
    current_time = time.time()
    inter_arrival = current_time - last_packet_time
    last_packet_time = current_time

    payload_size = len(payload)
    is_valid = 1.0 if is_valid_payload(payload, topic) else 0.0

    tcp_flags = encode_tcp_flags(packet[TCP]) if packet.haslayer(TCP) else 0
    ip_window.append(packet[IP].src if packet.haslayer(IP) else "0.0.0.0")
    ip_entropy = calculate_ip_entropy()
    packet_timestamps.append(current_time)
    packet_rate = calculate_packet_rate(current_time)

    # Emphasize packet_rate by scaling it more aggressively
    packet_rate_scaled = packet_rate * 5.0  # Increased scaling factor to 5.0

    return [payload_size, inter_arrival, is_valid, tcp_flags, ip_entropy, packet_rate_scaled]

def decode_remaining_length(payload, start):
    remaining_length = 0
    multiplier = 1
    pos = start
    while True:
        if pos >= len(payload):
            return None, pos
        byte = payload[pos]
        remaining_length += (byte & 127) * multiplier
        pos += 1
        if (byte & 128) == 0:
            break
        multiplier *= 128
    return remaining_length, pos

def parse_mqtt_publish(payload):
    if len(payload) < 2:
        return None, None, 0

    message_type = (payload[0] >> 4) & 0xF
    if message_type != 3:
        return None, None, 0

    remaining_length, pos = decode_remaining_length(payload, 1)
    if remaining_length is None or pos + remaining_length > len(payload):
        return None, None, 0

    if pos + 2 > len(payload):
        return None, None, 0
    topic_length = (payload[pos] << 8) + payload[pos + 1]
    pos += 2

    if pos + topic_length > len(payload):
        return None, None, 0
    topic = payload[pos:pos + topic_length].decode('utf-8', errors='ignore')
    pos += topic_length

    payload_length = remaining_length - (2 + topic_length)
    if payload_length <= 0 or pos + payload_length > len(payload):
        return None, None, 0
    message_payload = payload[pos:pos + payload_length].decode('utf-8', errors='ignore')
    pos += payload_length

    return topic, message_payload, pos

def parse_mqtt_packet(data):
    messages = []
    pos = 0
    while pos < len(data):
        topic, payload, new_pos = parse_mqtt_publish(data[pos:])
        if topic is None or payload is None:
            break
        messages.append((topic, payload))
        pos += new_pos
    return messages

def handle_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 1883:
        raw_payload = bytes(packet[TCP].payload)
        messages = parse_mqtt_packet(raw_payload)

        for topic, payload in messages:
            if not topic.startswith("esp32/"):
                continue

            features = extract_features(packet, payload, topic)
            packet_data.append(features)

            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] {packet[IP].src} -> {packet[IP].dst} | Topic: {topic} | Payload Length: {features[0]} | Inter-Arrival: {features[1]:.2f} | Is Valid: {features[2]} | TCP Flags: {features[3]} | IP Entropy: {features[4]:.2f} | Packet Rate: {features[5]:.2f} | Payload: {payload}")

            log = {
                "timestamp": timestamp,
                "src": str(packet[IP].src),
                "dst": str(packet[IP].dst),
                "topic": topic,
                "payload_length": float(features[0]),
                "inter_arrival": float(features[1]),
                "payload": payload
            }
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(log) + "\n")

def exit_handler(sig, frame):
    print("\n💾 Ctrl+C detected! Training model on collected packets...")
    if not packet_data:
        print("❌ No packets captured. Exiting.")
        sys.exit(0)

    X = np.array(packet_data)
    print(f"Collected {len(X)} packets")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination=0.05,  # Increased to make the model more aggressive
        max_features=1,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_FILE, 'wb') as f:
        pickle.dump(scaler, f)
    np.save(FEATURE_FILE, X)
    print(f"✅ Model trained and saved to {MODEL_FILE}")
    print(f"📁 Features saved to {FEATURE_FILE}")
    print(f"📁 Scaler saved to {SCALER_FILE}")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_handler)
    print("🚀 Starting MQTT packet capture for training...")
    try:
        sniff(filter="tcp port 1883", prn=handle_packet, store=0, iface="wlan0")
    except Exception as e:
        print(f"Error during sniffing: {e}")
        exit_handler(None, None)




