# 🐍 Python Network Sniffer

A powerful and educational suite of network sniffers built with **Python**, **Scapy**, and **PySide6**. This project includes both **command-line** and **graphical** sniffers to capture and analyze network traffic in real time with color-coded, user-friendly, and technically rich output.

---

## ✨ Key Features

- 🖥️ **Multiple Modes**: Choose between:
  - `sniffer_friendly.py` – Beginner-friendly CLI version
  - `sniffer_advanced.py` – Deep-dive CLI for technical users
  - `gui_sniffer.py` – Modern desktop GUI sniffer
- 🎨 **Color-Coded CLI Output**: Quickly understand protocols, IPs, and ports.
- 🧠 **Educational Insight**: Clear translation of ports, protocols, and TCP flags.
- 🕵️ **Deep Packet Inspection**: Advanced breakdown of headers, payloads, and metadata.
- 💻 **Cross-Platform**: Works on Windows, macOS, and Linux.

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

### `gui_sniffer.py` – GUI Sniffer with Dark Theme

> 🌌 A sleek, responsive desktop GUI sniffer with hex view, protocol color-coding, and interactive tree display.

**Key Features:**
- 📊 Real-time packet capture in a styled table
- 🧩 Interactive field-by-field inspection via expandable tree
- 🧵 Clean hex + ASCII dump for low-level analysis
- 🌙 Fully themed dark mode interface with modern UI/UX
- 🖱️ Toolbar controls: start, stop, clear

---

## 🛠️ Getting Started

### 1. Prerequisites

- Python 3.6+
- Pip
- Admin/root privileges
- **Npcap** (for Windows) – Required for packet capture

> Download Npcap from [https://npcap.com](https://npcap.com) and during installation:
> ✅ Check _“Install Npcap in WinPcap API-compatible Mode”_


### 2. Installation

#### A. Clone the Repository

```bash
git clone https://github.com/YourUsername/YourRepoName.git
cd YourRepoName
```

#### B. Create `requirements.txt`

```txt
scapy
colorama
pyside6
```

#### C. Install Dependencies

```bash
pip install -r requirements.txt
```

#### D. Windows-Specific

- Download and install [Npcap](https://npcap.com/)
- ✅ Enable _"Install Npcap in WinPcap API-compatible Mode"_

---

## ▶️ How to Run

> ⚠️ Must be run with **admin/root privileges**

### CLI Sniffers

#### Friendly Version:

```bash
# Windows
python sniffer_friendly.py

# macOS/Linux
sudo python3 sniffer_friendly.py
```

#### Advanced Version:

```bash
# Windows
python sniffer_advanced.py

# macOS/Linux
sudo python3 sniffer_advanced.py
```

### GUI Sniffer

```bash
# Windows
python gui_sniffer.py

# macOS/Linux
sudo python3 gui_sniffer.py
```

> Use `Ctrl+C` to stop CLI sniffers. GUI has start/stop buttons.

---

## 📂 Project Structure

```
📁 network-sniffer/
├── sniffer_friendly.py     # Beginner CLI sniffer
├── sniffer_advanced.py     # Advanced CLI analyzer
├── gui_sniffer.py          # GUI-based desktop sniffer
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

---

## ⚖️ Ethical Disclaimer

This project is provided for **educational purposes only**. Do **not** use it on networks you do not own or have explicit permission to monitor.

- 🚫 Unauthorized sniffing may be **illegal**
- 📜 Use responsibly and ethically

The developer assumes **no liability** for misuse.

---

## 🧠 Author & Credits

Made with 💻 by TARAK – Contributions welcome!

