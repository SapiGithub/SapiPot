import logging
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from TheSapiPot.sniff import Sniffer
from TheSapiPot.packetARP import check_MTIM
from TheSapiPot.packetHTTP import modelHTTP

class HoneyPot(object):
    def __init__(self,host,interface,logfile):
        self.host = host
        self.interface = interface
        self.logfile = logfile
        # hayperparam
        max_length = 100
        trunc_type='post'
        padding_type='post'

        # model, and data
        # self.model = tf.keras.models.load_model("/content/drive/MyDrive/Colab_Notebooks/MyModel/SentAn")
        # with open('/content/drive/MyDrive/Colab_Notebooks/tokenizer.pickle', 'rb') as handle:
        #     self.tokenizer,self.labels_len = pickle.load(handle)

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
            datefmt='%y-%m-%d %H:%M:%S',
            filename=self.logfile,
            filemode='w'
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info(f'[*] logfile: {self.logfile}')
        self.logger.info("[*] HoneyPot Initializing....... ")
    
    def logging_packet(self,packet: Packet):
        if packet.haslayer(TCP):
            ip = packet[IP]
            tcp = packet[TCP]
            flags = tcp.flags
            if (packet.haslayer(Raw) and ip.dst == self.host):
                try:
                    data = packet[Raw].load.decode()
                    # x,r = data.split('\r\n\r\n')
                    # self.logger.info(f"{packet.summary()}\n[data] {data}\n")
                    prd = modelHTTP(data)
                    self.logger.info(f"[Prediction]\n{data}\n{prd.predicts()}\n")
                except UnicodeDecodeError:
                    pass
            if (flags in ["RA" ,"R", "FA"]) and (tcp.dport != 'http' or tcp.sport != 'http'):
                self.logger.info(f"[Port Scan]\n{packet.summary()}\n")
        if packet.haslayer(scapy.ARP):
            if check_MTIM(packet):
                self.logger.info(f"{packet.summary()}\n")
            else:
                pass
            

    def run(self):
        print(f"[*] Filter: TCP For IpAddress: {self.host}")
        sniffer = Sniffer(prn=self.logging_packet, interface=self.interface,host_ip=self.host)
        sniffer.run()