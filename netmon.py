from scapy.all import sniff, IP, TCP, UDP
import socket
import argparse

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def is_private_ip(ip):
    return ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.")

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

        print(f"[{direction}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {length} bytes | Host: {remote_host} ({remote_ip})")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Monitor - CLI")
    parser.add_argument('--filter', help='BPF filter (e.g., "tcp", "udp", "port 80")', default="")
    args = parser.parse_args()

    print("🔍 Monitoring network traffic... (Ctrl+C to stop)\n")
    try:
        sniff(prn=process_packet, store=0, filter=args.filter)
    except PermissionError:
        print("❌ You need to run this script with sudo/root privileges.")
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")

if __name__ == "__main__":
    main()
