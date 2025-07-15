from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = str(protocol)

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {proto_name}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload (first 50 bytes): {payload[:50]}")

print("🔍 Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=0)
