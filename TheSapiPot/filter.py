from scapy.all import *
from scapy.layers.inet import IP, TCP

def is_tcp_packet(packet: Packet) -> bool:
    return packet.haslayer(IP) and packet.haslayer(TCP)

def has_ip_address(packet: Packet, ip_address: str) -> bool:
    i = packet[IP]
    return ip_address in (i.src, i.dst)
    
# def has_port(packet: Packet, port: int) -> bool:
#     t = packet[TCP]
#     return port in (t.sport, t.dport)
