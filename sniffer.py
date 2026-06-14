#!/usr/bin/env python3
"""A minimal packet sniffer built on scapy.

Run with root privileges (raw socket access is required):
    sudo python3 sniffer.py
    sudo python3 sniffer.py -c 20 -i en0
"""

import argparse
from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def process_packet(pkt):
    """Decode one packet layer-by-layer and print a single summary line."""
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Layer 3: only handle IP packets in this minimal version.
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    length = len(pkt)

    # Layer 4: figure out the transport protocol and ports.
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        endpoints = f"{src}:{sport} -> {dst}:{dport}"
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        endpoints = f"{src}:{sport} -> {dst}:{dport}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        endpoints = f"{src} -> {dst}"
    else:
        proto = f"IP/{pkt[IP].proto}"
        endpoints = f"{src} -> {dst}"

    print(f"[{timestamp}] {proto:<8} {endpoints:<45} len={length}")


def main():
    parser = argparse.ArgumentParser(description="A minimal scapy packet sniffer.")
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: scapy picks one).",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl+C to stop).",
    )
    args = parser.parse_args()

    print("Starting capture... (press Ctrl+C to stop)")
    try:
        sniff(iface=args.interface, prn=process_packet, count=args.count, store=False)
    except PermissionError:
        print("Permission denied. Try running with sudo.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
