from scapy.all import *

def check_MTIM(packet: Packet) -> bool:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            realMacAddress = arping(packet[ARP].psrc, verbose=0)[0][0][1].hwsrc
        except IndexError:
            return False
        recivMacAddress =  packet[ARP].hwsrc
        if realMacAddress != recivMacAddress:
            return True
        else:
            return False

