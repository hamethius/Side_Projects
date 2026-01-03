# Network Packet Sniffer

---

## Overview

This is a **Python-based network packet sniffer** that captures and analyzes real-time network traffic using the powerful `scapy` library. It prints detailed information about each packet, including source and destination addresses, protocols, ports, flags, and payloads.

Ideal for educational purposes, protocol analysis, or simply understanding how data flows through a network.

---

## Features

- Captures packets in **real-time**.
- Displays:
    - Source & Destination **IP and MAC addresses**
    - **Protocol** type (TCP, UDP, ICMP)
    - **Packet length**, **TTL**, **flags**, and **fragment offset**
- TCP:
    - Source & destination ports
    - Sequence and acknowledgment numbers
    - TCP flags & payload
- UDP:
    - Source & destination ports
    - Payload
- ICMP:
    - Type, code, and payload
- Supports fragmented IP packets

---

## Installation

### 1. Install Python dependencies:

```bash
pip install scapy

```

### 2. (Windows Only) Install Npcap:

- Visit [Npcap Official Website](https://nmap.org/npcap/)
- Download and install Npcap with default settings.

---

## Usage

### 1. Navigate to the project folder:

```bash
cd CodeAlpha_Network_Packet_Sniffer_Task1

```

### 2. Run the sniffer script:

```bash
python Packet_Sniffer.py

```

> The script will begin capturing packets immediately and print relevant details to the terminal.
> 

---

## Notes

- Run the script with **admin/root privileges** to allow low-level packet access:
    - **Linux/macOS:** `sudo python Packet_Sniffer.py`
    - **Windows:** Run your terminal as Administrator.
- This sniffer is for **educational and testing** use. Do not use it on networks without permission.

---
