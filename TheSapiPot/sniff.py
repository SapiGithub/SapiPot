from scapy.all import *
from TheSapiPot.filter import is_host

class Sniffer:
    def __init__(self, prn=None, interface=None, host_ip=None):
        self.host_ip = host_ip
        self.interface = interface
        self.prn = prn or (lambda p: f"{p.summary()}")

    def packet_filter(self, packet):
        return is_host(packet, self.host_ip)

    def run(self):
        sniff(prn=self.prn, iface=self.interface, lfilter=self.packet_filter, store=False)
