import logging
import signal
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
from TheSapiPot.packetHTTP import ModelHTTP
from TheSapiPot.sniff import Sniffer
from TheSapiPot.packetARP import check_MTIM
from TheSapiPot.sniffDir import start_monitoring
from TheSapiPot.packetPort import check_Port

class HoneyPot:
    def __init__(self, host, interface, dirfile, logfile):
        self.host = host
        self.interface = interface
        self.dirfile = dirfile
        self.logfile = logfile

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
            datefmt='%y-%m-%d %H:%M:%S',
            filename=self.logfile,
            filemode='w'
        )

        self.logger = logging.getLogger(__name__)
        logging.getLogger('watchdog.observers.inotify_buffer').setLevel(logging.WARNING)
        self.logger.info(f'[*] logfile: {self.logfile}')
        self.logger.info("[*] HoneyPot Initializing....... ")

    def logging_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            if packet.haslayer(HTTPRequest) and ip.dst == self.host:
                prd = ModelHTTP(packet)
                if prd.predicts():
                    if packet.haslayer(Raw):
                        self.logger.info(f"[HTTP Attack]\n[*]Packet Summary: {packet.summary()}\n[*]Packet Payload: {packet[Raw].load.decode()}\n[*]AI Prediction: \n{prd.predicts()}\n")
                    else:
                        self.logger.info(f"[HTTP Attack]\n[*]Packet Summary: {packet.summary()}\n[*]Packet Payload: {packet[HTTPRequest].Path.decode()}\n[*]AI Prediction: \n{prd.predicts()}\n")
            elif check_Port(packet):
                self.logger.info(f"[Port Scan]\n[*]Packet Summary: {packet.summary()}\n")
        elif packet.haslayer(UDP):
            if check_Port(packet,self.host):
                self.logger.info(f"[UDP port scan]\n[*]Packet Summary: {packet.summary()}\n")
        elif packet.haslayer(ARP):
            if check_MTIM(packet):
                self.logger.info(f"[ARP SPOOF]\n[*]Packet Summary: {packet.summary()}\n")

    def run(self):
        print(f"[*] Filter: For IpAddress: {self.host}\n[*] Monitoring For Directory or File: {self.dirfile}")
        sniffer = Sniffer(prn=self.logging_packet, interface=self.interface,host_ip=self.host)
        sniffer.run()
        start_monitoring(self.dirfile,self.logger)

