#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP
import socket
from rich.live import Live
from rich.table import Table
from rich.console import Console
from collections import defaultdict
import argparse
import signal
import subprocess
import sys

console = Console()
seen_connections = defaultdict(int)  # (src_ip, dst_ip, src_port, dst_port, direction, hostname) -> count
hostname_cache = {}

def resolve_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]

    # Try `host`
    try:
        result = subprocess.run(['host', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
        if "domain name pointer" in result.stdout:
            hostname = result.stdout.split("domain name pointer")[1].strip().strip('.')
            hostname_cache[ip] = hostname
            return hostname
    except Exception:
        pass

    # Try `nslookup`
    try:
        result = subprocess.run(['nslookup', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "name =" in line:
                hostname = line.split("name =")[1].strip().strip('.')
                hostname_cache[ip] = hostname
                return hostname
    except Exception:
        pass

    # Try `nmap -sL`
    try:
        result = subprocess.run(['nmap', '-sL', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                if len(parts) >= 5:
                    hostname = parts[4].strip('()')
                    hostname_cache[ip] = hostname
                    return hostname
    except Exception:
        pass

    hostname_cache[ip] = "Unknown"
    return "Unknown"

def is_private_ip(ip):
    return ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.")

def build_table():
    table = Table(title="🔍 Live Network Monitor", expand=True)
    table.add_column("Count", justify="right")
    table.add_column("Direction", justify="center")
    table.add_column("Source", style="cyan")
    table.add_column("→", justify="center")
    table.add_column("Destination", style="magenta")
    table.add_column("Bytes", justify="right")
    table.add_column("Host", style="green")

    for conn, count in seen_connections.items():
        src_ip, dst_ip, src_port, dst_port, direction, host, length = conn
        src = f"{src_ip}:{src_port}"
        dst = f"{dst_ip}:{dst_port}"
        table.add_row(str(count), direction, src, "→", dst, str(length), host)

    return table

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = packet.sport if TCP in packet or UDP in packet else 'N/A'
        dst_port = packet.dport if TCP in packet or UDP in packet else 'N/A'
        length = len(packet)

        direction = "OUT" if is_private_ip(src_ip) else "IN"
        remote_ip = dst_ip if direction == "OUT" else src_ip
        remote_host = resolve_hostname(remote_ip)

        conn_key = (src_ip, dst_ip, src_port, dst_port, direction, remote_host, length)
        seen_connections[conn_key] += 1

def handle_exit(sig, frame):
    console.print("\n[bold red]🛑 Stopping packet monitor.[/bold red]")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, handle_exit)

    parser = argparse.ArgumentParser(description="Network Traffic Monitor with Hostnames")
    parser.add_argument('--filter', help='BPF filter (e.g., \"tcp\", \"udp\")', default="")
    args = parser.parse_args()

    console.print("[bold yellow]Starting network monitor... Press Ctrl+C to stop[/bold yellow]")

    with Live(build_table(), refresh_per_second=2, screen=True) as live:
        def wrapped(packet):
            process_packet(packet)
            live.update(build_table())

        sniff(prn=wrapped, store=0, filter=args.filter)

if __name__ == "__main__":
    main()
