from datetime import timedelta
import logging
import hashlib
import os
from scapy.all import *
from scapy.layers.inet import IP, TCP
from TheSapiPot.sniff import Sniffer
from TheSapiPot.filter import is_tcp_packet, has_ip_address
import json
# import tensorflow as tf
import random
# from tensorflow.keras.preprocessing.text import Tokenizer
# from tensorflow.keras.preprocessing.sequence import pad_sequences
import urllib.parse
import numpy as np
import pickle

class HoneyPot(object):
    def __init__(self,host,interface,ports,logfile):
        self.bind_ip = host
        self.interface = interface
        self.ports = ports
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
        self.logger.info(f'[*] ports: {self.ports}')
        self.logger.info(f'[*] logfile: {self.logfile}')
        self.logger.info("[*] HoneyPot Initializing....... ")
    
    def logging_packet(self,packet: Packet):
        ip = packet[IP]
        tcp = packet[TCP]
        flags = tcp.flags
        if (packet.haslayer(Raw)):
            data = packet[Raw].load.decode()
            self.logger.info(f"[PAYLOAD] {data} \n")
    

    def run(self):
        print(f"[*] Filter: TCP For IpAddress: {self.bind_ip}")
        packet_filter = lambda p: is_tcp_packet(p) and has_ip_address(p, self.bind_ip)
        sniffer = Sniffer(prn=self.logging_packet, interface=self.interface,port_list=self.ports)
        sniffer.run()