# Edge-Sentry: Realtime Anomaly Detection in IoT Networks

Edge-Sentry is a proof-of-concept project that demonstrates an internet-free anomaly detection and prevention system for IoT networks. It runs on a Raspberry Pi and is designed to monitor MQTT traffic from ESP32 devices in real-time. [cite_start]The system leverages an Isolation Forest machine learning model to identify and block malicious activities such as data injection and DDoS flooding attacks, providing a secure environment for small-scale IoT deployments. [cite: 1, 12, 14]

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Hardware and Software Requirements](#hardware-and-software-requirements)
- [Installation and Setup](#installation-and-setup)
- [How It Works](#how-it-works)
- [Dashboard](#dashboard)

## Project Overview

[cite_start]The core of this project is to address the security vulnerabilities inherent in the lightweight MQTT protocol, which is commonly used in IoT applications. [cite: 6, 9] [cite_start]IoT devices are often resource-constrained and lack robust security, making them targets for cyber-attacks. [cite: 10] [cite_start]Edge-Sentry provides a localized, internet-free solution where an ESP32 publisher sends sensor data to another ESP32 acting as an Access Point and MQTT broker. [cite: 14, 15, 16] [cite_start]A Raspberry Pi, connected to this network, hosts the anomaly detection model, sniffing MQTT traffic, and a Flask web dashboard for real-time monitoring and visualization. [cite: 17, 24]

## Features

* [cite_start]**Real-Time Anomaly Detection**: Utilizes an Isolation Forest machine learning model to identify anomalies in MQTT traffic. [cite: 13, 62] The model analyzes features like:
    * [cite_start]Payload Size [cite: 63, 194]
    * [cite_start]Inter-Arrival Time [cite: 63, 197]
    * [cite_start]Payload Validity [cite: 63, 198]
    * [cite_start]TCP Flags [cite: 63, 199]
    * [cite_start]IP Entropy [cite: 63, 200]
    * [cite_start]Packet Rate [cite: 63, 201]
* **Real-Time Anomaly Prevention**: Implements an active prevention mechanism to block threats.
    * [cite_start]**Automated IP Blocking**: Dynamically adds `iptables` rules on the Raspberry Pi to block traffic from source IPs identified as anomalous. [cite: 71, 214]
    * [cite_start]**Time-Limited Blocking**: Temporarily blocks malicious IPs to mitigate threats without permanent network disruption. [cite: 72, 215]
    * [cite_start]**Prevention Logging**: Maintains detailed logs of all blocking and unblocking actions. [cite: 73]
* **Visualization and Monitoring**: A Flask-based web dashboard provides comprehensive insights into the network's security status.
    * [cite_start]Displays real-time packet logs with details like timestamps, source/destination IPs, topic, payload, and anomaly score. [cite: 75, 164]
    * [cite_start]Visualizes anomaly scores over time with a line chart and the distribution of normal vs. anomalous messages with a pie chart. [cite: 76, 159, 160]
    * [cite_start]Includes a table of detected anomalies and a dedicated section for prevention actions. [cite: 77, 78, 163]
* [cite_start]**Internet-Free Operation**: The entire system is designed to run on a local, internet-free network for enhanced security. [cite: 14, 51]

## System Architecture

The system consists of the following components:

1.  [cite_start]**ESP32 Publisher**: An ESP32 device that collects sensor data and publishes it to MQTT topics (e.g., `esp32/temperature`). [cite: 15, 128] [cite_start]It is configured to simulate normal traffic, invalid payloads, and flooding attacks for testing purposes. [cite: 137, 139, 140]

2.  **ESP32 Access Point (AP)**: A second ESP32 device configured to act as a Wi-Fi Access Point. [cite_start]It creates a local network and assigns static IP addresses to the publisher and the Raspberry Pi. [cite: 16, 123]

3.  **Raspberry Pi**: The central hub of the system that hosts:
    * [cite_start]**Mosquitto MQTT Broker**: Receives messages from the ESP32 publisher. [cite: 147]
    * **Anomaly Detection & Prevention Script (`inference.py`)**: Sniffs MQTT packets using Scapy, extracts features, and uses the pre-trained Isolation Forest model to detect anomalies. [cite_start]It also manages `iptables` for blocking malicious IPs. [cite: 148, 149]
    * [cite_start]**Flask Web Server (`server.py`)**: Serves the web dashboard for monitoring. [cite: 150]

[cite_start]The data flow is as follows: The ESP32 Publisher sends MQTT messages to the Mosquitto Broker on the Raspberry Pi via the ESP32 AP. [cite: 380, 381] [cite_start]The `inference.py` script sniffs this traffic, analyzes it for anomalies, and if a threat is detected, it blocks the source IP using `iptables`. [cite: 353, 357, 383] [cite_start]All activity is logged and visualized on the Flask dashboard. [cite: 361, 372]

## Hardware and Software Requirements

### Hardware
* [cite_start]**ESP32 Microcontrollers (x2)**: ESP32 DevKit v1 with 4MB flash memory. [cite: 261, 262]
* [cite_start]**Raspberry Pi 4**: 4GB RAM, 32GB microSD card. [cite: 264, 265]
* [cite_start]**Development PC**: For programming the ESP32s and Raspberry Pi. [cite: 268]

### Software
* **For ESP32**:
    * [cite_start]Arduino IDE 2.3.2 with ESP32 board support. [cite: 273]
    * [cite_start]Libraries: `WiFi`, `PubSubClient`. [cite: 274]
* **For Raspberry Pi**:
    * [cite_start]Raspberry Pi OS (64-bit). [cite: 276]
    * [cite_start]Python 3.9+. [cite: 276]
    * [cite_start]Mosquitto MQTT broker. [cite: 277]
    * [cite_start]Python Libraries: `scapy`, `numpy`, `scikit-learn`, `flask`, `pandas`, etc. [cite: 278]
* **Web Dashboard**:
    * [cite_start]Tailwind CSS and Chart.js (via CDN). [cite: 280]

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

1.  **Training**: Initially, the system collects a baseline of normal MQTT traffic from the ESP32 publisher. [cite_start]This data is used to train the Isolation Forest model, which learns the characteristics of normal behavior. [cite: 610]

2.  [cite_start]**Inference and Prevention**: Once trained, the system continuously sniffs MQTT packets in real-time. [cite: 618] [cite_start]For each packet, it extracts features and uses the trained model to calculate an anomaly score. [cite: 619, 621]
    * [cite_start]Packets with a score below a certain threshold (e.g., <= -0.01) are flagged as anomalous. [cite: 203]
    * [cite_start]Rule-based checks are also applied to detect obviously invalid payloads (e.g., containing non-numeric data) and flooding attacks (packet rate > 2 packets/sec). [cite: 204, 205]
    * [cite_start]When an anomaly is detected, the source IP is temporarily blocked using `iptables` to prevent further malicious activity. [cite: 214, 215]

## Dashboard

The web dashboard provides a user-friendly interface for monitoring the IoT network. It features:
* [cite_start]A **line chart** showing anomaly scores over time. [cite: 159]
* [cite_start]A **pie chart** illustrating the distribution of normal versus anomalous packets. [cite: 160]
* [cite_start]A **packet log table** with detailed information about each MQTT packet. [cite: 164]
* [cite_start]A **blocked traffic history table** that logs all prevention actions. [cite: 78]

[cite_start]The dashboard refreshes automatically, offering a live look into the security of your IoT network. [cite: 227]
