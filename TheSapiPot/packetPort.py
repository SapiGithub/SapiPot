from scapy.all import *
from scapy.layers.inet import IP, TCP

def check_Port(packet: Packet,*ipa):
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.flags
        return flags in ["RA", "R", "FA", "F"] and not (tcp.dport in [80, 8080, 443] or tcp.sport in [80, 8080, 443])
    elif packet.haslayer(UDP):
        try:
            ip = packet[IP]
            if ip.dst == ipa[0]:
                return True
        except IndexError:
            return False