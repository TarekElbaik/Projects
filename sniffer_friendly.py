#
# A User-Friendly Python Network Sniffer using the Scapy library.
# Final version with clear, educational labels for all ports.
#
# This script requires:
# 1. Python 3.x
# 2. The Scapy library (`pip install scapy`)
# 3. The Colorama library (`pip install colorama`)
# 4. Npcap for Windows users (installed in WinPcap compatibility mode)
#
# To run this script, you MUST execute it with administrative/root privileges.
#

import sys
import os
from scapy.all import sniff, IP, TCP, UDP, DNS
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# --- Configuration ---
PACKET_COUNT = 50 

# --- Mappings for User-Friendly Output ---

# Map common port numbers to service names
PORT_MAP = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    3389: "RDP"
}

# Translate TCP flags to human-readable format
TCP_FLAG_MAP = {
    'F': 'FIN (Finish)', 'S': 'SYN (Start)', 'R': 'RST (Reset)',
    'P': 'PSH (Push)', 'A': 'ACK (Acknowledge)', 'U': 'URG (Urgent)',
    'E': 'ECE (ECN-Echo)', 'C': 'CWR (Congestion Window Reduced)'
}

def get_service_name(port):
    """
    Returns the common service name for a well-known port,
    or a descriptive label for ephemeral/client ports.
    """
    # Check if the port is a well-known, registered service
    if port in PORT_MAP:
        return f"({PORT_MAP.get(port)})"
    # Ports below 1024 are system ports. If not in our map, they are a less common service.
    elif port < 1024:
        return "(Unknown System Port)"
    # High-numbered ports are typically used by clients as temporary (ephemeral) ports.
    else:
        return "(Client Port)"

def translate_tcp_flags(flags):
    """Translates a TCP flag string into a descriptive list."""
    if not flags:
        return "No Flags"
    
    flag_list = []
    for flag_char in str(flags):
        flag_list.append(TCP_FLAG_MAP.get(flag_char, flag_char))
    return ", ".join(flag_list)

def generate_friendly_summary(packet):
    """Creates a simple, human-readable summary of the packet's purpose."""
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        if packet.getlayer(DNS).qd:
             host = packet.getlayer(DNS).qd.qname.decode('utf-8', errors='ignore')
             return f"Asking for the address of '{host}'"

    if packet.haslayer(TCP):
        sport = packet.getlayer(TCP).sport
        dport = packet.getlayer(TCP).dport
        if 443 in (sport, dport):
            return "Secure Web Browsing (HTTPS)"
        if 80 in (sport, dport):
            return "Standard Web Browsing (HTTP)"

    if packet.haslayer(UDP):
        sport = packet.getlayer(UDP).sport
        dport = packet.getlayer(UDP).dport
        if 53 in (sport, dport):
            return "DNS Traffic" # Generic DNS for responses

    return "General network traffic"


def process_packet(packet):
    """
    This function is called for each captured packet.
    It now focuses on presenting the information in the most user-friendly way.
    """
    if not packet.haslayer(IP):
        return # Skip non-IP packets for this example

    print(f"\n{Style.BRIGHT}---[ New Packet ]---")

    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    # --- Source & Destination Info ---
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        if packet.haslayer(TCP):
            proto_layer = packet.getlayer(TCP)
            protocol = "TCP"
        else: # UDP
            proto_layer = packet.getlayer(UDP)
            protocol = "UDP"

        src_port = proto_layer.sport
        dst_port = proto_layer.dport

        print(f"-> {Fore.YELLOW}From: {src_ip}:{src_port} {get_service_name(src_port)}")
        print(f"-> {Fore.CYAN}To:   {dst_ip}:{dst_port} {get_service_name(dst_port)}")
    else:
        # For protocols without ports like ICMP
        protocol = "ICMP" if ip_layer.proto == 1 else "IP"
        print(f"-> {Fore.YELLOW}From: {src_ip}")
        print(f"-> {Fore.CYAN}To:   {dst_ip}")

    # --- Protocol & Friendly Summary ---
    print(f"-> {Fore.MAGENTA}Protocol: {protocol}")
    
    friendly_summary = generate_friendly_summary(packet)
    print(f"-> {Fore.GREEN}Purpose:  {friendly_summary}")

    # --- Deeper Technical Details (Translated) ---
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        translated_flags = translate_tcp_flags(tcp_layer.flags)
        print(f"-> {Fore.BLUE}Details:  {translated_flags}")

def main():
    """
    Main function to start the sniffing process.
    """
    print("--- Starting User-Friendly Network Sniffer ---")
    if PACKET_COUNT > 0:
        print(f"[*] Capturing the next {PACKET_COUNT} packets...")
    else:
        print("[*] Capturing packets... Press Ctrl+C to stop.")

    try:
        sniff(count=PACKET_COUNT, prn=process_packet, store=False)

    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: Permission denied.")
        print(f"{Fore.RED}Please run this script with administrative/root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}")
        sys.exit(1)
    
    print("\n\n--- Sniffing Complete ---")

if __name__ == "__main__":
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

    if not is_admin:
        print(f"{Fore.YELLOW}[!] Warning: This script may not work without administrative/root privileges.")

    main()
