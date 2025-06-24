Python Network Sniffer
A powerful and educational command-line network packet sniffer built with Python and Scapy. This tool captures and analyzes network traffic, presenting the information in a clear, color-coded, and easy-to-understand format.

This repository contains two versions of the sniffer:

sniffer_friendly.py: A user-friendly version designed for beginners, which translates technical jargon into plain English.

sniffer_advanced.py: An advanced version for deeper analysis, providing a detailed, layer-by-layer breakdown of each packet.

Features
sniffer_friendly.py (For Beginners)
Clear, Color-Coded Output: Highlights source/destination IPs, protocols, and other details for easy reading.

Plain English Translation: Translates port numbers to service names (e.g., port 443 becomes (HTTPS)) and TCP flags to descriptive text (e.g., S becomes SYN (Start)).

Friendly Purpose Summary: Provides a simple, one-line summary of what the packet is likely doing (e.g., "Secure Web Browsing" or "Asking for the address of 'google.com'").

Focus on Clarity: Hides overwhelming details by default to provide a clean and educational overview of network activity.

sniffer_advanced.py (For Power Users)
Deep Packet Breakdown: Uses Scapy's .show() method to print a complete, hierarchical view of all packet layers (Ethernet, IP, TCP/UDP, etc.).

Detailed Technical Info: Displays specific technical data like TCP sequence/acknowledgment numbers and raw packet payloads.

DNS Query Analysis: Specifically identifies and displays the domain names being requested in DNS queries.

Raw and Unfiltered: Provides a comprehensive look at the packet structure, perfect for technical analysis and debugging.

Sample Output
sniffer_friendly.py
---[ New Packet ]---
-> From: 192.168.1.21:59938 (Client Port)
-> To:   8.8.8.8:443 (HTTPS)
-> Protocol: TCP
-> Purpose:  Secure Web Browsing (HTTPS)
-> Details:  SYN (Start)

sniffer_advanced.py
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

Setup and Installation
1. Prerequisites
Python 3.6+

2. Clone the Repository
git clone https://github.com/YourUsername/YourRepoName.git
cd YourRepoName

3. Install Required Libraries
This project relies on scapy and colorama. You can install them using pip:

pip install -r requirements.txt

(You will need to create a requirements.txt file with the following content):

scapy
colorama

4. Special Requirement for Windows Users
On Windows, Scapy requires a packet capture driver. You must install Npcap.

Download the latest installer from the Npcap website.

Run the installer.

Crucially, during installation, select the option for "Install Npcap in WinPcap API-compatible Mode".

How to Run
Warning: This tool requires access to your network adapter in promiscuous mode. You must run it with administrative or root privileges.

Open your terminal (Command Prompt, PowerShell, or Terminal).

On Windows: Right-click the terminal icon and select "Run as administrator".

On macOS/Linux: Prepend the run command with sudo.

Running the friendly version:
# On Windows (in an admin terminal)
python sniffer_friendly.py

# On macOS/Linux
sudo python3 sniffer_friendly.py

Running the advanced version:
# On Windows (in an admin terminal)
python sniffer_advanced.py

# On macOS/Linux
sudo python3 sniffer_advanced.py

Press Ctrl+C to stop the sniffer at any time.

Ethical Disclaimer
This tool is intended for educational purposes only, to be used on networks and devices that you own or have explicit permission to monitor. Unauthorized sniffing of network traffic is a violation of privacy and is illegal in many jurisdictions. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
