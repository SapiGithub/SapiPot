from scapy.all import *
import threading

class Sniffer:
    def __init__(self, prn=None, packet_filter=None, port_list=None):
        if filter:
            self.packet_filter = packet_filter
        else:
            self.packet_filter = lambda: True
        if prn:
            self.prn = prn
        else:
            self.prn = lambda p: f"{p.summary()}"
        self.ports = port_list
        self.thread = {}
        
    def run(self):
        for port in self.ports:
            self.thread[port] = threading.Thread(target=self._sniff, args=(port,))
            self.thread[port].start()

    def _sniff(self,port):
        sniff(prn=self.prn, lfilter=self.packet_filter, store=False, filter = f'dst port {port}')
