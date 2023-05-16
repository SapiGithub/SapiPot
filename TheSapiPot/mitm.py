import os
from scapy.all import *
import argparse
from scapy.all import *

# ARP
def check_arp_spoofing(interfaces, timeout):
    results = []
    for iface in interfaces:
        try:
            my_mac = get_if_hwaddr(iface)
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has",hwsrc=my_mac,psrc="0.0.0.0",pdst="255.255.255.255"))
            ans, unans = srp(pkt, iface=iface, timeout=timeout, retry=1, verbose=0)
            for snd,rcv in ans:
                if rcv[ARP].hwsrc != my_mac:
                    result = (iface, snd[Ether].src, snd[ARP].psrc, rcv[ARP].hwsrc, rcv[ARP].psrc)
                    results.append(result)
        except Exception as e:
            return str(f"Error checking interface {iface}: {e}")
    return results

# if __name__ == "__main__":
#     results = check_arp_spoofing(['wlan0', 'eth0'], 2.0)
#     if len(results) > 0:
#         print("ARP spoofing detected on the following interfaces:")
#         for iface, mac1, ip1, mac2, ip2 in results:
#             print(f"Interface: {iface}, MAC address 1: {mac1}, IP address 1: {ip1}, MAC address 2: {mac2}, IP address 2: {ip2}")
#     else:
#         print("No ARP spoofing detected")

