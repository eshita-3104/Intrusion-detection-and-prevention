from scapy.all import sniff, IP, TCP, Raw
import numpy as np
import pickle
import time
import re
import json
from collections import deque
from math import log2
import subprocess
import os

# --- Configuration ---
# Original NIDS files
MODEL_FILE = "anomaly_model.pkl"
SCALER_FILE = "scaler.pkl"
NIDS_LOG_FILE = "mqtt_inference_packets.json" # For detailed NIDS packet analysis

# Prevention and Blocking Log
PREVENTION_LOG_FILE = "blocked_traffic_log.txt" # Logs IPs that were blocked
IP_BLOCK_DURATION_SECONDS = 300  # Block for 5 minutes (300 seconds)
BLOCKING_THRESHOLD_SCORE = -0.1 # If Isolation Forest score is below this, consider blocking

# *** MODIFICATION: Adjusted threshold based on observed system performance. ***
PACKET_RATE_FLOOD_THRESHOLD = 4 # packets/sec. Normal rate is ~1pps, observed flood rate is ~5pps.

# --- Load Model and Scaler ---
try:
    with open(MODEL_FILE, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_FILE, 'rb') as f:
        scaler = pickle.load(f)
except FileNotFoundError as e:
    print(f"Error: Could not load model/scaler file. {e}")
    print("Please ensure 'anomaly_model.pkl' and 'scaler.pkl' are in the same directory.")
    exit(1)
except Exception as e:
    print(f"Error loading model/scaler: {e}")
    exit(1)

# --- Global Variables for NIDS (from your original code) ---
last_packet_time = time.time()
ip_window = deque(maxlen=10)
packet_timestamps = deque(maxlen=100) # Window for packet rate calculation
log_buffer = []
BUFFER_SIZE = 10

# --- Global Variables for Prevention ---
# Tracks IPs currently blocked by this script: {'ip_address': {'block_time': float, 'reason': str}}
actively_blocked_ips = {}

# --- IPTables Interaction Functions ---
def run_iptables_command(command_args):
    """Helper function to run an iptables command."""
    try:
        cmd = ["sudo", "iptables"] + command_args
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        print("Error: sudo or iptables command not found. Is it installed and in PATH?")
        return False, "", "sudo/iptables not found"
    except subprocess.CalledProcessError as e:
        return False, e.stdout.strip(), e.stderr.strip()
    except Exception as e:
        return False, "", str(e)

def check_iptables_rule_exists(ip_address, port="1883", chain="INPUT", action="DROP"):
    """Checks if a specific iptables rule already exists."""
    success, _, stderr = run_iptables_command([
        "-C", chain,
        "-s", ip_address,
        "-p", "tcp",
        "--dport", str(port),
        "-j", action
    ])
    if "No chain/target/match by that name" in stderr and not success: # Rule does not exist
        return False
    return success

def add_ip_block_rule(ip_address, port="1883"):
    """Adds an iptables rule to DROP traffic from a specific IP to a port."""
    if check_iptables_rule_exists(ip_address, port=port):
        return True

    success, stdout, stderr = run_iptables_command([
        "-I", "INPUT", "1",
        "-s", ip_address,
        "-p", "tcp",
        "--dport", str(port),
        "-j", "DROP"
    ])
    if success:
        print(f"IPTables: Successfully ADDED rule to DROP traffic from {ip_address} to port {port}.")
        return True
    else:
        print(f"IPTables: FAILED to add rule for {ip_address}. Stderr: {stderr}")
        return False

def remove_ip_block_rule(ip_address, port="1883"):
    """Removes an iptables rule that DROPs traffic from a specific IP."""
    if not check_iptables_rule_exists(ip_address, port=port):
        return True

    success, stdout, stderr = run_iptables_command([
        "-D", "INPUT",
        "-s", ip_address,
        "-p", "tcp",
        "--dport", str(port),
        "-j", "DROP"
    ])
    if success:
        print(f"IPTables: Successfully REMOVED rule blocking {ip_address} for port {port}.")
        return True
    else:
        if not check_iptables_rule_exists(ip_address, port=port):
             print(f"IPTables: Rule for {ip_address} for port {port} seems to be gone after attempted removal. Stderr: {stderr}")
             return True
        print(f"IPTables: FAILED to remove rule for {ip_address}. Stderr: {stderr}")
        return False

# --- Prevention Logging Function ---
def log_blocked_action(ip_address, reason, port="1883"):
    """Logs when an IP is blocked to the prevention log file."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_message = (
        f"[{timestamp}] BLOCKED IP: {ip_address} | PORT: {port} | "
        f"REASON: {reason} | DURATION: {IP_BLOCK_DURATION_SECONDS} seconds.\n"
        f"  Packets from this IP to this port will now be dropped by the firewall.\n"
    )
    print(f"PREVENTION LOG: {log_message.strip()}")
    try:
        with open(PREVENTION_LOG_FILE, "a") as f:
            f.write(log_message)
    except Exception as e:
        print(f"Error writing to prevention log '{PREVENTION_LOG_FILE}': {e}")

def log_unblocked_action(ip_address, reason="Duration expired", port="1883"):
    """Logs when an IP is unblocked to the prevention log file."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_message = (
        f"[{timestamp}] UNBLOCKED IP: {ip_address} | PORT: {port} | "
        f"REASON: {reason}.\n"
    )
    print(f"PREVENTION LOG: {log_message.strip()}")
    try:
        with open(PREVENTION_LOG_FILE, "a") as f:
            f.write(log_message)
    except Exception as e:
        print(f"Error writing to prevention log '{PREVENTION_LOG_FILE}': {e}")


# --- NIDS Feature Extraction (Synced with training.py) ---
def calculate_ip_entropy():
    if not ip_window: return 0.0
    ip_counts = {}
    for ip in ip_window: ip_counts[ip] = ip_counts.get(ip, 0) + 1
    total = len(ip_window)
    entropy = 0.0
    for count in ip_counts.values():
        prob = count / total
        entropy -= prob * log2(prob) if prob > 0 else 0
    return entropy

def calculate_packet_rate(current_time):
    """Calculates packet rate over a 1-second sliding window. Identical to training script."""
    if not packet_timestamps:
        return 0.0
    while packet_timestamps and current_time - packet_timestamps[0] > 1:  # 1-second window
        packet_timestamps.popleft()
    return len(packet_timestamps) / 1.0  # Rate in packets per second

def encode_tcp_flags(tcp_layer):
    if not tcp_layer: return 0
    return int(tcp_layer.flags)

def is_valid_payload(payload, topic):
    try:
        if not payload.startswith('1'): return False
        rest = payload[1:]
        if not rest.startswith(topic): return False
        value_str = rest[len(topic):]
        value = float(value_str)
        if topic == "esp32/temperature" and not (20.0 <= value <= 35.0): return False
        elif topic == "esp32/humidity" and not (30.0 <= value <= 80.0): return False
        elif topic == "esp32/pressure" and not (980.0 <= value <= 1050.0): return False
        elif topic == "esp32/altitude" and not (50.0 <= value <= 1500.0): return False
        return True
    except (ValueError, IndexError, TypeError):
        return False

def extract_features(packet, payload_str, topic):
    """Extracts features, now synced with the training script's logic."""
    global last_packet_time
    current_time = time.time()
    inter_arrival = current_time - last_packet_time
    last_packet_time = current_time

    payload_size = len(payload_str)
    is_valid = 1.0 if is_valid_payload(payload_str, topic) else 0.0
    tcp_flags = encode_tcp_flags(packet[TCP]) if packet.haslayer(TCP) else 0
    ip_window.append(packet[IP].src if packet.haslayer(IP) else "0.0.0.0")
    ip_entropy = calculate_ip_entropy()

    # This part now matches training.py
    packet_timestamps.append(current_time)
    packet_rate = calculate_packet_rate(current_time)
    packet_rate_scaled = packet_rate * 5.0

    features = np.array([[payload_size, inter_arrival, is_valid, tcp_flags, ip_entropy, packet_rate_scaled]])
    return features, packet_rate # Return raw packet_rate for explicit flood check


# --- MQTT Parsing (from your original code) ---
def decode_remaining_length(payload_bytes, start):
    remaining_length = 0
    multiplier = 1
    pos = start
    while True:
        if pos >= len(payload_bytes): return None, pos
        byte = payload_bytes[pos]
        remaining_length += (byte & 127) * multiplier
        pos += 1
        if (byte & 128) == 0: break
        multiplier *= 128
        if multiplier > 128*128*128*128: return None, pos
    return remaining_length, pos

def parse_mqtt_publish(payload_bytes):
    if len(payload_bytes) < 2: return None, None, 0
    message_type = (payload_bytes[0] >> 4) & 0xF
    if message_type != 3: return None, None, 0

    remaining_length, pos = decode_remaining_length(payload_bytes, 1)
    if remaining_length is None or pos + remaining_length > len(payload_bytes): return None, None, 0

    if pos + 2 > len(payload_bytes): return None, None, 0
    topic_length = (payload_bytes[pos] << 8) + payload_bytes[pos + 1]
    pos += 2

    if pos + topic_length > len(payload_bytes): return None, None, 0
    try:
        topic = payload_bytes[pos:pos + topic_length].decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return None, None, 0
    pos += topic_length

    message_payload_length = remaining_length - (2 + topic_length)
    if message_payload_length < 0 : return None, None, 0

    message_start_pos = pos
    try:
        message_content = payload_bytes[message_start_pos : message_start_pos + message_payload_length].decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return None, None, 0
    
    _, temp_pos_after_rem_len = decode_remaining_length(payload_bytes, 1)
    length_of_rem_len_field = temp_pos_after_rem_len - 1
    total_consumed_by_this_publish = 1 + length_of_rem_len_field + remaining_length

    return topic, message_content, total_consumed_by_this_publish

def parse_mqtt_packet(raw_tcp_payload): # raw_tcp_payload is bytes
    messages = []
    current_pos = 0
    while current_pos < len(raw_tcp_payload):
        topic, message_str, consumed_bytes = parse_mqtt_publish(raw_tcp_payload[current_pos:])
        if topic is None or message_str is None or consumed_bytes == 0:
            break
        
        messages.append((topic, message_str))
        current_pos += consumed_bytes

    return messages

# --- Packet Handling and NIDS Logic ---
def manage_expired_blocks():
    """Checks for and unblocks IPs whose block duration has expired."""
    global actively_blocked_ips
    current_time = time.time()
    unblocked_due_to_expiry = []
    for ip, block_info in list(actively_blocked_ips.items()):
        if current_time - block_info['block_time'] > IP_BLOCK_DURATION_SECONDS:
            print(f"Block duration for {ip} expired. Attempting to unblock.")
            if remove_ip_block_rule(ip):
                log_unblocked_action(ip, reason="Duration expired")
                unblocked_due_to_expiry.append(ip)
            else:
                print(f"Failed to auto-unblock {ip}. Rule might have been removed manually or error.")
    
    for ip in unblocked_due_to_expiry:
        if ip in actively_blocked_ips:
            del actively_blocked_ips[ip]


def handle_packet(packet):
    global log_buffer, actively_blocked_ips

    manage_expired_blocks()

    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 1883:
        src_ip = packet[IP].src

        if src_ip in actively_blocked_ips:
            return

        if packet[TCP].payload:
            raw_payload_bytes = bytes(packet[TCP].payload)
            parsed_messages = parse_mqtt_packet(raw_payload_bytes)
            if not parsed_messages:
                return

            for topic, payload_string in parsed_messages:
                if not topic.startswith("esp32/"):
                    continue
                
                features_matrix, packet_rate = extract_features(packet, payload_string, topic)
                
                anomaly_reason = "Model Prediction"
                is_payload_struct_valid = features_matrix[0][2] == 1.0
                score = 0
                label = "⚪ Not Processed"

                # --- Anomaly Detection Logic ---
                is_flooding = packet_rate > PACKET_RATE_FLOOD_THRESHOLD

                if is_flooding:
                    label = f"🔴 Anomaly (High Packet Rate)"
                    score = -2.0 # Assign a very low score to ensure it gets blocked
                    anomaly_reason = f"High Packet Rate ({packet_rate:.1f} pkt/s) detected, potential flood attack."
                elif not is_payload_struct_valid:
                    label = "🔴 Anomaly (Invalid Payload Structure)"
                    score = -1.0 # Assign a highly anomalous score
                    anomaly_reason = "Invalid Payload Structure/Value"
                else:
                    try:
                        features_scaled = scaler.transform(features_matrix)
                        score = model.decision_function(features_scaled)[0]
                        if score <= BLOCKING_THRESHOLD_SCORE:
                            label = f"🔴 Anomaly (Score: {score:.3f})"
                            anomaly_reason = f"Anomaly Score ({score:.3f}) below threshold ({BLOCKING_THRESHOLD_SCORE})"
                        elif score <= -0.01 :
                            label = f"🟠 Warning (Score: {score:.3f})"
                            anomaly_reason = f"Suspicious Score ({score:.3f})"
                        else:
                            label = "🟢 Normal"
                    except Exception as e:
                        print(f"Error during model prediction/scaling for {src_ip}: {e}")
                        label = "⚪ Error in Processing"

                # --- NIDS Logging ---
                nids_timestamp = time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                current_nids_log_entry = {
                    "timestamp": nids_timestamp, "src": src_ip, "dst": str(packet[IP].dst),
                    "topic": topic, "score": float(score) if isinstance(score, (int, float, np.number)) else None,
                    "payload_length": float(features_matrix[0][0]),
                    "inter_arrival": float(features_matrix[0][1]),
                    "is_payload_valid_structure": bool(is_payload_struct_valid),
                    "tcp_flags": int(features_matrix[0][3]),
                    "ip_entropy": float(features_matrix[0][4]),
                    "packet_rate_scaled": float(features_matrix[0][5]),
                    "payload": payload_string, "label": label,
                    "is_anomaly_detected": bool(label.startswith("🔴"))
                }
                log_buffer.append(current_nids_log_entry)
                
                score_display = f"{score:.4f}" if isinstance(score, (float, np.number)) else "N/A"
                print(
                    f"NIDS: [{label}] {nids_timestamp} | {src_ip} → {packet[IP].dst} | Topic: {topic} | "
                    f"Score: {score_display} | PktRate: {packet_rate:.2f} | "
                    f"PayloadLen: {features_matrix[0][0]} | InterArrival: {features_matrix[0][1]:.2f} | "
                    f"ValidPayload: {is_payload_struct_valid} | "
                    f"Payload: {payload_string[:30]}{'...' if len(payload_string)>30 else ''}"
                )

                if len(log_buffer) >= BUFFER_SIZE:
                    try:
                        with open(NIDS_LOG_FILE, "a") as f:
                            for entry in log_buffer:
                                f.write(json.dumps(entry) + "\n")
                        log_buffer.clear()
                    except Exception as e:
                        print(f"Error writing to NIDS log '{NIDS_LOG_FILE}': {e}")


                # --- Prevention Logic ---
                # Block if the label indicates a clear anomaly (flooding, invalid payload, or low model score)
                should_block = label.startswith("🔴")

                if should_block and src_ip not in actively_blocked_ips:
                    print(f"Decision: Attempting to block IP {src_ip} due to: {anomaly_reason}")
                    if add_ip_block_rule(src_ip):
                        log_blocked_action(src_ip, anomaly_reason)
                        actively_blocked_ips[src_ip] = {
                            'block_time': time.time(),
                            'reason': anomaly_reason
                        }
                    else:
                        print(f"Failed to apply iptables block rule for {src_ip}.")

# --- Cleanup Function ---
def cleanup_iptables_and_logs():
    global log_buffer, actively_blocked_ips
    print("\nCleaning up...")

    if log_buffer:
        print(f"Writing remaining {len(log_buffer)} NIDS log entries...")
        try:
            with open(NIDS_LOG_FILE, "a") as f:
                for entry in log_buffer:
                    f.write(json.dumps(entry) + "\n")
            log_buffer.clear()
        except Exception as e:
            print(f"Error writing remaining NIDS logs: {e}")

    if actively_blocked_ips:
        print("Removing iptables rules added by this script session...")
        for ip, block_info in list(actively_blocked_ips.items()):
            if remove_ip_block_rule(ip):
                log_unblocked_action(ip, reason="Script shutdown/cleanup")
            else:
                log_unblocked_action(ip, reason="Script shutdown/cleanup - REMOVAL FAILED, CHECK MANUALLY")
        actively_blocked_ips.clear()
    else:
        print("No active blocks by this script session to remove.")
    
    print("Cleanup complete.")


# --- Main Execution ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script uses iptables and needs to be run as root. Please use 'sudo'.")
        exit(1)

    print(f"🚀 MQTT Inference and Prevention System is starting...")
    print(f"   NIDS Packet Log: '{NIDS_LOG_FILE}'")
    print(f"   Prevention Actions Log: '{PREVENTION_LOG_FILE}'")
    print(f"   Blocking IPs for: {IP_BLOCK_DURATION_SECONDS} seconds if score <= {BLOCKING_THRESHOLD_SCORE}, invalid payload, or packet rate > {PACKET_RATE_FLOOD_THRESHOLD} pps.")
    
    try:
        with open(PREVENTION_LOG_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] --- NIDS Prevention System Started ---\n")
    except Exception as e:
        print(f"Warning: Could not write startup message to prevention log: {e}")

    try:
        # Change 'iface' to your network interface if it's not 'wlan0'
        sniff(filter="tcp port 1883", prn=handle_packet, store=0, iface="wlan0")
    except OSError as e:
        if "No such device" in str(e) or "socket.error" in str(e):
             print(f"\nError with network interface 'wlan0': {e}")
             print("Please ensure 'wlan0' is correct and active, or specify the correct interface with the -i flag.")
        else:
            print(f"\nAn OS error occurred during sniffing: {e}")
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")
    finally:
        cleanup_iptables_and_logs()