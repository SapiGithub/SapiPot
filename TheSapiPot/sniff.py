from scapy.all import *
import threading

class Sniffer:
    def __init__(self, prn=None, interface=None, port_list=None):
        if interface:
            self.interface = interface
        else:
            self.interface = conf.iface
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
        sniff(prn=self.prn, interface=self.interface, store=False, filter = f'dst port {port}')
