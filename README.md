# 🐍 Python Network Sniffer

A powerful and educational command-line network packet sniffer built with **Python** and **Scapy**. This tool captures and analyzes network traffic, presenting it in a clear, color-coded, and easy-to-understand format.

---

## ✨ Key Features

- 🖥️ **Dual Scripts**: Choose between a user-friendly version for beginners or an advanced, technical sniffer for power users.
- 🎨 **Color-Coded Output**: Easily distinguish between source IPs, destinations, and protocols at a glance.
- 📚 **Educational Focus**: The friendly version translates technical jargon (like port numbers and TCP flags) into plain English for easier learning.
- 🔧 **Deep Analysis**: The advanced version provides detailed, layer-by-layer packet breakdowns, perfect for technical analysis.
- 💻 **Cross-Platform**: Works on Windows, macOS, and Linux with the same commands.

---

## 📸 Sample Output

### `sniffer_friendly.py` – Clean & Clear Output

```
---[ New Packet ]---
-> From: 192.168.1.21:59938 (Client Port)
-> To:   8.8.8.8:443 (HTTPS)
-> Protocol: TCP
-> Purpose:  Secure Web Browsing (HTTPS)
-> Details:  SYN (Start)
```

### `sniffer_advanced.py` – Detailed Technical Breakdown

```
==================== New Packet Captured ====================
192.168.1.21:59940 -> 172.217.16.142:443 | Protocol: TCP
    L4 Info:  TCP Flags: SA | Seq: 0 | Ack: 336719113
    Payload:  b''...
--- Full Packet Breakdown ---
###[ Ethernet ]###
  dst       = 0a:1b:2c:3d:4e:5f
  src       = 01:11:22:33:44:55
  type      = IPv4
###[ IP ]###
  version   = 4
  ihl       = 5
  ...
###[ TCP ]###
  sport     = 443
  dport     = 59940
  seq       = 0
  ack       = 336719113
  flags     = SA
  ...
-----------------------------
```

---

## 🛠️ Getting Started

Follow these steps to get the sniffer running on your local machine.

### 1. Prerequisites

- Python 3.6+

### 2. Installation Steps

#### A. Clone the Repository

```bash
git clone https://github.com/YourUsername/YourRepoName.git
cd YourRepoName
```

#### B. Create a `requirements.txt` File

Create a new file named `requirements.txt` in the project directory and add:

```
scapy
colorama
```

#### C. Install Required Libraries

```bash
pip install -r requirements.txt
```

#### D. Special Requirement for Windows Users

Scapy on Windows needs a packet capture driver called **Npcap**.

- Download it from https://npcap.com/
- During installation, **select**:  
  ✅ _Install Npcap in WinPcap API-compatible Mode_

---

## ▶️ How to Run

> ⚠️ **Admin/root privileges are required**

### On **Windows**:

Right-click your terminal (Command Prompt or PowerShell) and select **"Run as administrator"**.

### On **macOS/Linux**:

Use `sudo` before each command.

#### Run the Friendly Version:

```bash
# Windows
python sniffer_friendly.py

# macOS/Linux
sudo python3 sniffer_friendly.py
```

#### Run the Advanced Version:

```bash
# Windows
python sniffer_advanced.py

# macOS/Linux
sudo python3 sniffer_advanced.py
```

> Press `Ctrl+C` to stop the sniffer at any time.

---

## ⚖️ Ethical Disclaimer

This tool is intended for **educational purposes only**, and should only be used on networks and devices that you **own** or have **explicit permission** to monitor.

❗ Unauthorized network sniffing is a **violation of privacy** and may be **illegal** in many jurisdictions.

The developer assumes **no liability** and is **not responsible** for any misuse or damage caused by this program.
