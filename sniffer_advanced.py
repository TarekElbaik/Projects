#
# An enhanced Python Network Sniffer using the Scapy library.
# This version includes deeper packet analysis capabilities.
#
# This script requires:
# 1. Python 3.x
# 2. The Scapy library (`pip install scapy`)
# 3. The Colorama library (`pip install colorama`)
# 4. Npcap for Windows users (installed in WinPcap compatibility mode)
#
# To run this script, you MUST execute it with administrative/root privileges.
# On Windows: Open PowerShell/CMD "As Administrator".
# On Linux/macOS: Use `sudo python sniffer.py`.
#

import sys
import os
from scapy.all import sniff, IP, TCP, UDP, DNS
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# --- Configuration ---
PACKET_COUNT = 10 

def get_protocol_name(protocol_number):
    """
    Helper function to convert a protocol number to its common name.
    """
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocol_map.get(protocol_number, "Other")

def process_packet(packet):
    """
    This function is called for each captured packet.
    It now performs a deeper analysis of the packet's structure and content.
    """
    print(f"\n{Style.BRIGHT}==================== New Packet Captured ====================")
    
    # Check for IP layer
    if not packet.haslayer(IP):
        # If not an IP packet, we can't do much with it for this example
        print(f"{Fore.YELLOW}[-] Non-IP Packet: {packet.summary()}")
        return

    # --- Basic Info Extraction ---
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol_num = ip_layer.proto
    protocol = get_protocol_name(protocol_num)
    
    src_port = ""
    dst_port = ""

    # --- Protocol-Specific Analysis ---
    if protocol == "TCP":
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = f":{tcp_layer.sport}"
            dst_port = f":{tcp_layer.dport}"
    elif protocol == "UDP":
        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = f":{udp_layer.sport}"
            dst_port = f":{udp_layer.dport}"
    
    # --- Print High-Level Summary ---
    summary_info = (
        f"{Fore.YELLOW}{src_ip}{src_port}"
        f" -> {Fore.CYAN}{dst_ip}{dst_port}"
        f" | Protocol: {Fore.MAGENTA}{protocol}"
    )
    print(summary_info)

    # --- Deep Packet Inspection ---
    
    # Analyze TCP packets in more detail
    if protocol == "TCP":
        tcp_layer = packet.getlayer(TCP)
        # Extract TCP flags (e.g., SYN, ACK, FIN)
        tcp_flags = tcp_layer.flags
        print(f"    {Fore.BLUE}L4 Info:  TCP Flags: {tcp_flags} | Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack}")

    # Analyze DNS queries
    # Check for DNS layer, qr=0 indicates a query
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_layer = packet.getlayer(DNS)
        # qd holds the question record
        if dns_layer.qd:
            queried_host = dns_layer.qd.qname.decode('utf-8')
            query_type = dns_layer.qd.qtype
            print(f"    {Fore.GREEN}App Info: DNS Query For: '{queried_host}' (Type: {query_type})")

    # Display the raw payload if it exists
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        if len(packet.payload.payload.payload) > 0: # Accessing the raw payload
            payload_data = bytes(packet.payload.payload.payload)
            print(f"    {Fore.WHITE}Payload:  {str(payload_data[:80])}...")

    # --- Show Full Packet Structure ---
    # The .show() method provides a comprehensive, human-readable breakdown.
    print(f"{Style.DIM}--- Full Packet Breakdown ---")
    packet.show()
    print(f"{Style.DIM}-----------------------------")


def main():
    """
    Main function to start the sniffing process.
    """
    print("--- Starting Enhanced Network Sniffer ---")
    if PACKET_COUNT > 0:
        print(f"[*] Capturing the next {PACKET_COUNT} packets...")
    else:
        print("[*] Capturing packets... Press Ctrl+C to stop.")

    try:
        # To better test DNS analysis, you could filter specifically for it:
        # sniff(filter="udp port 53", count=PACKET_COUNT, prn=process_packet, store=False)
        sniff(count=PACKET_COUNT, prn=process_packet, store=False)

    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: Permission denied.")
        print(f"{Fore.RED}Please run this script with administrative/root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}")
        sys.exit(1)
    
    print("\n--- Sniffing Complete ---")


if __name__ == "__main__":
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

    if not is_admin:
        print(f"{Fore.YELLOW}[!] Warning: This script may not work without administrative/root privileges.")

    main()
