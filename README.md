# Edge-Sentry: Realtime Anomaly Detection in IoT Networks

Edge-Sentry is a proof-of-concept project that demonstrates an internet-free anomaly detection and prevention system for IoT networks. It runs on a Raspberry Pi and is designed to monitor MQTT traffic from ESP32 devices in real-time. The system leverages an Isolation Forest machine learning model to identify and block malicious activities such as data injection and DDoS flooding attacks, providing a secure environment for small-scale IoT deployments. 
## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Hardware and Software Requirements](#hardware-and-software-requirements)
- [Installation and Setup](#installation-and-setup)
- [How It Works](#how-it-works)
- [Dashboard](#dashboard)

## Project Overview

The core of this project is to address the security vulnerabilities inherent in the lightweight MQTT protocol, which is commonly used in IoT applications. : 6, 9] IoT devices are often resource-constrained and lack robust security, making them targets for cyber-attacks. : 10] Edge-Sentry provides a localized, internet-free solution where an ESP32 publisher sends sensor data to another ESP32 acting as an Access Point and MQTT broker. : 14, 15, 16] A Raspberry Pi, connected to this network, hosts the anomaly detection model, sniffing MQTT traffic, and a Flask web dashboard for real-time monitoring and visualization. : 17, 24]

## Features

* **Real-Time Anomaly Detection**: Utilizes an Isolation Forest machine learning model to identify anomalies in MQTT traffic. The model analyzes features like:
    * Payload Size 
    * Inter-Arrival Time 
    * Payload Validity 
    * TCP Flags 
    * IP Entropy 
    * Packet Rate 
* **Real-Time Anomaly Prevention**: Implements an active prevention mechanism to block threats.
    * **Automated IP Blocking**: Dynamically adds `iptables` rules on the Raspberry Pi to block traffic from source IPs identified as anomalous. 
    * **Time-Limited Blocking**: Temporarily blocks malicious IPs to mitigate threats without permanent network disruption. 
    * **Prevention Logging**: Maintains detailed logs of all blocking and unblocking actions. 
* **Visualization and Monitoring**: A Flask-based web dashboard provides comprehensive insights into the network's security status.
    * Displays real-time packet logs with details like timestamps, source/destination IPs, topic, payload, and anomaly score. 
    * Visualizes anomaly scores over time with a line chart and the distribution of normal vs. anomalous messages with a pie chart. 
    * Includes a table of detected anomalies and a dedicated section for prevention actions. 
* **Internet-Free Operation**: The entire system is designed to run on a local, internet-free network for enhanced security.

## System Architecture

The system consists of the following components:

1.  **ESP32 Publisher**: An ESP32 device that collects sensor data and publishes it to MQTT topics (e.g., `esp32/temperature`). It is configured to simulate normal traffic, invalid payloads, and flooding attacks for testing purposes.

2.  **ESP32 Access Point (AP)**: A second ESP32 device configured to act as a Wi-Fi Access Point. It creates a local network and assigns static IP addresses to the publisher and the Raspberry Pi.

3.  **Raspberry Pi**: The central hub of the system that hosts:
    * **Mosquitto MQTT Broker**: Receives messages from the ESP32 publisher. 
    * **Anomaly Detection & Prevention Script (`inference.py`)**: Sniffs MQTT packets using Scapy, extracts features, and uses the pre-trained Isolation Forest model to detect anomalies. It also manages `iptables` for blocking malicious IPs. 
    * **Flask Web Server (`server.py`)**: Serves the web dashboard for monitoring.

The data flow is as follows: The ESP32 Publisher sends MQTT messages to the Mosquitto Broker on the Raspberry Pi via the ESP32 AP. The `inference.py` script sniffs this traffic, analyzes it for anomalies, and if a threat is detected, it blocks the source IP using `iptables`. All activity is logged and visualized on the Flask dashboard.

## Hardware and Software Requirements

### Hardware
* **ESP32 Microcontrollers (x2)**: ESP32 DevKit v1 with 4MB flash memory.
* **Raspberry Pi 4**: 4GB RAM, 32GB microSD card. 
* **Development PC**: For programming the ESP32s and Raspberry Pi.

### Software
* **For ESP32**:
    * Arduino IDE 2.3.2 with ESP32 board support.
    * Libraries: `WiFi`, `PubSubClient`. 
* **For Raspberry Pi**:
    * Raspberry Pi OS (64-bit).
    * Python 3.9+. 
    * Mosquitto MQTT broker.
    * Python Libraries: `scapy`, `numpy`, `scikit-learn`, `flask`, `pandas`, etc.
* **Web Dashboard**:
    * Tailwind CSS and Chart.js (via CDN).

## Installation and Setup

1.  **ESP32 Setup**:
    * Use the Arduino IDE to flash one ESP32 with the Access Point firmware and the other with the Publisher firmware.
    * Configure the SSID and password in the publisher code to connect to the ESP32 AP.

2.  **Raspberry Pi Setup**:
    * Install Raspberry Pi OS.
    * Install the Mosquitto MQTT broker.
    * Clone the project repository from GitHub.
    * Install the required Python libraries using `pip install -r requirements.txt`.

3.  **Running the System**:
    * Start the Mosquitto broker on the Raspberry Pi.
    * Run the anomaly detection and prevention script: `sudo python3 inference.py`.
    * Start the Flask web server: `python3 server.py`.
    * Power on the ESP32 devices.
    * Access the dashboard from a web browser on a device connected to the same network at `http://<Raspberry-Pi-IP>:5000`.

## How It Works

The system operates in two main phases:

1.  **Training**: Initially, the system collects a baseline of normal MQTT traffic from the ESP32 publisher. This data is used to train the Isolation Forest model, which learns the characteristics of normal behavior.

2.  **Inference and Prevention**: Once trained, the system continuously sniffs MQTT packets in real-time. For each packet, it extracts features and uses the trained model to calculate an anomaly score. 
    * Packets with a score below a certain threshold (e.g., <= -0.01) are flagged as anomalous.
    * Rule-based checks are also applied to detect obviously invalid payloads (e.g., containing non-numeric data) and flooding attacks (packet rate > 2 packets/sec).
    * When an anomaly is detected, the source IP is temporarily blocked using `iptables` to prevent further malicious activity.

## Dashboard

The web dashboard provides a user-friendly interface for monitoring the IoT network. It features:
* A **line chart** showing anomaly scores over time. 
* A **pie chart** illustrating the distribution of normal versus anomalous packets.
* A **packet log table** with detailed information about each MQTT packet. 
* A **blocked traffic history table** that logs all prevention actions.

The dashboard refreshes automatically, offering a live look into the security of your IoT network.
