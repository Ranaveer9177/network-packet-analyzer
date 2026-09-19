# 🔍 Network Packet Analyzer & Basic IDS (Python + Scapy)

## 📌 Overview

This project is a **Python-based network packet analyzer and basic Intrusion Detection System (IDS)** that processes `.pcap` files captured using Wireshark.

It analyzes network traffic and detects suspicious behavior such as:

* DoS (Denial of Service) attacks
* SYN flood attacks
* Port scanning (internal & external)
* High traffic anomalies
* HTTP request extraction (basic Deep Packet Inspection)

---

## 🚀 Features

### 🔎 Packet Analysis

* Reads `.pcap` files using Scapy
* Extracts:

  * Source IP
  * Destination ports
  * TCP flags (SYN, ACK)
  * Packet timestamps

---

### 🛡️ Intrusion Detection

Uses **multi-factor detection logic** to reduce false positives.

| Detection Type     | Description                              |
| ------------------ | ---------------------------------------- |
| 🔴 DoS Attack      | High packet rate + SYN activity          |
| 🔴 SYN Flood       | Many SYN packets with low port variation |
| 🔴 Internal Scan   | Multiple ports from private network      |
| 🟠 Port Scanning   | Large number of unique ports             |
| 🟠 Traffic Anomaly | High traffic with limited port diversity |

---

### 🌐 HTTP Inspection (DPI)

* Extracts HTTP payloads from packets
* Supports:

  * `GET`
  * `POST`
  * `HTTP responses`
* Displays partial payload (first 200 characters)

⚠️ Note:

* Only works for **HTTP (port 80)**
* ❌ HTTPS cannot be decrypted (encrypted)

---

### 📄 Report Generation

Generates a structured output file:

```bash
report.txt
```

Includes:

* Debug statistics per IP
* Detected alerts
* Extracted HTTP data

---

## 🧠 Detection Logic

Instead of simple thresholds, this tool uses:

* Packet rate (packets/sec)
* SYN packet count
* Port diversity
* Traffic duration

👉 This reduces false positives from high-volume services like CDNs.

---

## ⚙️ Installation

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 2. Capture traffic using Wireshark

1. Start capture
2. Generate traffic
3. Save as:

```bash
capture.pcapng
```

---

### 3. Convert to `.pcap`

```bash
editcap -F pcap capture.pcapng capture.pcap
```

---

## ▶️ Usage

```bash
python sniffer.py
```

---

## 📊 Example Output

```text
--- Analysis Report ---

[DEBUG] IP: 192.168.1.10 | Packets: 120 | Rate: 45.2 | Ports: 30 | SYN: 80

⚠️ Port Scanning from 192.168.1.10
```

---

### 🌐 HTTP Output Example

```text
HTTP Traffic Found:

IP: 192.168.1.5
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

---

## 🧪 Testing

Simulate traffic using Nmap:

```bash
nmap -p 1-1000 <target-ip>
```

Steps:

1. Capture traffic in Wireshark
2. Run analyzer
3. Verify detection

---

## 📂 Project Structure

```
project/
│── sniffer.py
│── capture.pcap
│── report.txt
│── requirements.txt
│── README.md
```

---

## ⚠️ Limitations

* Cannot decrypt HTTPS traffic
* Detection is heuristic-based (not signature-based like enterprise IDS)
* Works on offline PCAP files (not real-time)

---

## 🔮 Future Improvements

* Real-time packet sniffing
* GUI dashboard (Tkinter / PyQt)
* Machine learning-based anomaly detection
* DNS tunneling detection
* Export reports (CSV / JSON)

---

## 💼 Resume Description

> Developed a Python-based network packet analyzer using Scapy to process PCAP files and detect anomalies such as DoS attacks, SYN floods, and port scanning by analyzing packet rate, TCP flags, and port distribution. Integrated Wireshark for packet capture and implemented HTTP payload inspection.

---

## 📜 License

This project is for **educational and research purposes only**.

---

## 👨‍💻 Author

Ranaveer
Cybersecurity Enthusiast 🚀
