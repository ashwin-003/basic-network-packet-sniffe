#!/usr/bin/env python3
"""
Basic Network Packet Sniffer
=============================
Captures live network traffic and displays source/destination IPs,
protocol, ports, and payload info. Built with Scapy.

IMPORTANT:
- Must be run with administrator/root privileges (raw sockets require it).
- Only capture traffic on networks/devices you own or have explicit
  permission to monitor. Capturing traffic you don't own may be illegal.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw

# Simple counters for a summary at the end
stats = {"total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}


def get_protocol_name(packet):
    """Work out a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Other"


def process_packet(packet):
    """Callback run for every captured packet."""
    stats["total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Handle IPv4 and IPv6
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    else:
        # Not an IP packet (e.g. ARP) - skip detailed parsing
        print(f"[{timestamp}] Non-IP packet: {packet.summary()}")
        return

    proto = get_protocol_name(packet)
    stats[proto] += 1

    line = f"[{timestamp}] {proto:5} {src_ip:15} -> {dst_ip:15}"

    # Add port info for TCP/UDP
    if packet.haslayer(TCP):
        line += f"  Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
        flags = packet[TCP].flags
        line += f"  Flags: {flags}"
    elif packet.haslayer(UDP):
        line += f"  Ports: {packet[UDP].sport} -> {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        line += f"  Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

    print(line)

    # Show a snippet of the payload if present (safe, truncated, printable-only)
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        # Only show first 60 bytes, printable chars only, rest as dots
        snippet = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:60])
        print(f"           Payload ({len(payload)} bytes): {snippet}")


def print_summary():
    print("\n" + "=" * 50)
    print("Capture Summary")
    print("=" * 50)
    print(f"Total packets captured : {stats['total']}")
    print(f"TCP                    : {stats['TCP']}")
    print(f"UDP                    : {stats['UDP']}")
    print(f"ICMP                   : {stats['ICMP']}")
    print(f"Other                  : {stats['Other']}")


def main():
    parser = argparse.ArgumentParser(description="Basic Python Network Sniffer")
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: scapy auto-detects)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (default: 0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="ip",
                         help='BPF filter, e.g. "tcp", "udp port 53", "icmp" (default: "ip")')
    args = parser.parse_args()

    print("Starting packet capture...")
    print(f"Interface : {args.iface or 'default (auto)'}")
    print(f"Filter    : {args.filter}")
    print(f"Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 50)

    try:
        sniff(iface=args.iface, filter=args.filter, prn=process_packet,
              count=args.count, store=False)
    except PermissionError:
        print("\nERROR: Permission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()
