from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, TCP

def is_host(packet: Packet, ip_address: str) -> bool:
    if packet.haslayer(TCP):
        i = packet[IP]
        return ip_address in (i.src, i.dst)
    if packet.haslayer(ARP):
        i = packet[ARP]
        return ip_address in (i.pdst)
    if packet.haslayer(UDP) and packet.haslayer(IP):
        i = packet[IP]
        return ip_address in (i.pdst)
