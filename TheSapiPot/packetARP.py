from scapy.all import *

def check_MTIM(packet: Packet, *ipa) -> bool:
    if packet[ARP].op == 2 and packet[ARP].pdst ==ipa[0]:
        try:
            realMacAddress = arping(packet[ARP].psrc, verbose=0)[0][0][1].hwsrc
        except IndexError:
            return False
        return realMacAddress != packet[ARP].hwsrc

    return False
