from scapy.all import *

# ARP
def check_MTIM(packet: Packet) -> bool:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            realMacAddress = arping(packet[ARP].psrc, verbose=0)[0][0][1].hwsrc
        except IndexError:
            return False
        recivMacAddress =  packet[ARP].hwsrc
        if realMacAddress != recivMacAddress:
            return True


# if __name__ == "__main__":
#     results = check_arp_spoofing(['wlan0', 'eth0'], 2.0)
#     if len(results) > 0:
#         print("ARP spoofing detected on the following interfaces:")
#         for iface, mac1, ip1, mac2, ip2 in results:
#             print(f"Interface: {iface}, MAC address 1: {mac1}, IP address 1: {ip1}, MAC address 2: {mac2}, IP address 2: {ip2}")
#     else:
#         print("No ARP spoofing detected")

