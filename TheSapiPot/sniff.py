from scapy.all import *
from TheSapiPot.filter import has_ip_address
import threading

class Sniffer:
    def __init__(self, prn=None, interface=None,host_ip=None):
        self.host_ip=host_ip
        self.interface = interface
        if prn:
            self.prn = prn
        else:
            self.prn = lambda p: f"{p.summary()}"
        
        self.protocols = ['tcp','arp','udp']
        self.thread = {}
        
    def run(self):
        for protocol in self.protocols:
            self.thread[protocol] = threading.Thread(target=self._sniff, args=(protocol,))
            self.thread[protocol].start()

    def _sniff(self,protocol):
        packet_filter = lambda p:has_ip_address(p, self.host_ip)
        sniff(prn=self.prn, iface=self.interface,lfilter=packet_filter,store=False, filter=f'{protocol}')
