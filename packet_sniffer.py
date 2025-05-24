# packet_sniffer.py

from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n[+] Packet: {src} -> {dst} | Protocol: {proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"  TCP | Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"  UDP | Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("  ICMP Packet Detected")
        else:
            print("  Other Protocol Detected")

def start_sniffing():
    print("[*] Starting packet sniffing... Press CTRL+C to stop.")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
