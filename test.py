# from scapy.all import *
# import json
# import time

# # Define the IP address range to scan
# IP_RANGE = "192.168.1.0/24"

# # Define the number of SYN packets to consider a flood
# SYN_THRESHOLD = 50

# # Define the name of the JSON file to save the syn_count dictionary to
# JSON_FILE = "syn_count.json"

# # Load the existing syn_count dictionary from the JSON file, if it exists
# try:
#     with open(JSON_FILE, "r") as f:
#         syn_count = json.load(f)
# except FileNotFoundError:
#     syn_count = {}

# # Define a function to save the syn_count dictionary to the JSON file
# def save_syn_count():
#     with open(JSON_FILE, "w") as f:
#         json.dump(syn_count, f)

# # Define a function to remove any entries from syn_count that haven't had any activity for 30 minutes
# def remove_inactive_ips():
#     now = time.time()
#     for ip in list(syn_count.keys()):
#         last_activity_time = syn_count[ip]["last_activity_time"]
#         if now - last_activity_time > 1800:
#             del syn_count[ip]
#     save_syn_count()

# # Define a function to handle incoming packets
# def handle_packet(packet):
#     if packet.haslayer(scapy.TCP) and packet[TCP].flags & scapy.TCP.SYN:
#         src_ip = packet[scapy.IP].src
#         if src_ip in syn_count:
#             syn_count[src_ip]["count"] += 1
#             syn_count[src_ip]["last_activity_time"] = time.time()
#             if syn_count[src_ip]["count"] >= SYN_THRESHOLD:
#                 print(f"SYN flood detected from {src_ip}")
#         else:
#             syn_count[src_ip] = {"count": 1, "last_activity_time": time.time()}
#     remove_inactive_ips()

# # Start the packet capture
# sniff(filter=f"src net {IP_RANGE} and tcp", prn=handle_packet)
import os
import shutil
import pyinotify

def copy_backup():
    backup_path = "backup/data.txt.bk"
    upload_path = "uploaded/data.txt"
    shutil.copyfile(backup_path, upload_path)

class EventHandler(pyinotify.ProcessEvent):
    def process_default(self, event):
        if event.mask & pyinotify.IN_DELETE:
            if event.pathname == "uploaded/data.txt":
                copy_backup()

def monitor_file():
    watch_path = "uploaded"
    mask = pyinotify.IN_DELETE
    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(watch_path, mask, rec=True)
    notifier.loop()

monitor_file()