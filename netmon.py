import socket
import subprocess
import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.console import Group
import requests
import psutil

seen_in_connections = defaultdict(int)
seen_out_connections = defaultdict(int)
hostname_cache = {}
country_cache = {}

def get_all_local_ips():
    local_ips = set()
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family.name == 'AF_INET':
                local_ips.add(addr.address)
    local_ips.add("127.0.0.1")
    return local_ips

all_local_ips = get_all_local_ips()

def resolve_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = host
        return host
    except:
        hostname_cache[ip] = "-"
        return "-"

def get_country_flag(ip):
    if ip in country_cache:
        return country_cache[ip]
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=1.5)
        data = response.json()
        cc = data.get("country_code", "")
        flag = ''.join([chr(ord(c) + 127397) for c in cc]) if cc else ""
        result = f"{flag} {data.get('country_name', 'Unknown')}"
        country_cache[ip] = result
        return result
    except:
        country_cache[ip] = "Unknown"
        return "Unknown"

def is_suspicious_domain(domain):
    domain = domain.lower()
    if any(word in domain for word in ['login', 'secure', 'verify', 'update', 'account']):
        return True
    if domain.count('.') > 3 or domain.count('-') > 2:
        return True
    return False

def propose_host_name(host):
    if not host or host == "-":
        return "-"
    parts = host.lower().split('.')
    known = ['google', 'github', 'microsoft', 'amazon', 'facebook', 'youtube', 'cloudflare']
    for part in parts:
        if part in known:
            return part.capitalize()
    return parts[0].capitalize()

def build_table(connections_dict, label):
    table = Table(title=f"{label} Traffic", expand=True)
    table.add_column("Count", justify="right")
    table.add_column("Src")
    table.add_column("→")
    table.add_column("Dst")
    table.add_column("Size", justify="right")
    table.add_column("Host")
    table.add_column("Proposed")
    table.add_column("Country")

    for conn, count in list(connections_dict.items())[-25:]:
        src, dst, length, sport, dport = conn
        target_ip = dst if label == "OUT" else src
        host = resolve_hostname(target_ip)
        country = get_country_flag(target_ip)
        proposed = propose_host_name(host)
        highlight = Text(proposed, style="bold red") if is_suspicious_domain(proposed) else Text(proposed, style="green")

        table.add_row(str(count), f"{src}:{sport}", "→", f"{dst}:{dport}", str(length), host, highlight, country)

    return table

def packet_callback(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = pkt.sport if hasattr(pkt, 'sport') else 0
        dport = pkt.dport if hasattr(pkt, 'dport') else 0
        length = len(pkt)

        key = (src_ip, dst_ip, length, sport, dport)
        if src_ip in all_local_ips:
            seen_out_connections[key] += 1
        else:
            seen_in_connections[key] += 1

def sniff_packets():
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    with Live(refresh_per_second=2, screen=True) as live:
        while True:
            try:
                table_in = build_table(seen_in_connections, "IN")
                table_out = build_table(seen_out_connections, "OUT")
                combined = Group(table_in, table_out)
                live.update(combined)
                time.sleep(1)
            except KeyboardInterrupt:
                break
