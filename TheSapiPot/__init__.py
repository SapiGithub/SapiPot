import logging
import tensorflow as tf
import pickle
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
from TheSapiPot.packetHTTP import ModelHTTP
from TheSapiPot.sniff import Sniffer
from TheSapiPot.packetARP import check_MTIM
from TheSapiPot.sniffDir import start_monitoring
from TheSapiPot.packetPort import check_Port
import threading
import tkinter as tk
from tkinter import ttk
import asyncio
import csv
import time

class HoneyPot:
    def __init__(self, host, interface, dirfile, logfile):
        self.host = host
        self.interface = interface
        self.dirfile = dirfile
        self.logfile = logfile
        self.model = tf.keras.models.load_model("TheSapiPot/model/SentAn")
        with open('TheSapiPot/model/tokenizer_sentAn.pickle', 'rb') as handle:
            self.tokenizer,self.labels_len = pickle.load(handle)
        self.prd = ModelHTTP(model=self.model,token=self.tokenizer,label=self.labels_len)
        self.log = []

    def logging_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            ip = packet[IP]
            if packet.haslayer(HTTPRequest) and ip.dst == self.host:
                if self.prd.predicts(packet):
                    if packet.haslayer(Raw):
                        self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[HTTP Attack]", "Packet Summary": packet.summary(), "Packet Payload":packet[Raw].load.decode(), "Prediction": prd.predicts()},)
                    else:
                        self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[HTTP Attack]", "Packet Summary": packet.summary(), "Packet Payload":packet[HTTPRequest].Path.decode(), "Prediction": prd.predicts()},)
            elif check_Port(packet):
                self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[Port Scan]", "Packet Summary": packet.summary(), "Packet Payload":"", "Prediction": ["TCP Port Scan"]},)
        elif packet.haslayer(UDP):
            if check_Port(packet,self.host):
                self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[Port Scan]", "Packet Summary": packet.summary(), "Packet Payload":"", "Prediction": ["UDP Port Scan"]},)
        elif packet.haslayer(ARP):
            if check_MTIM(packet, self.host):
                self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[ARP Spoof]", "Packet Summary": packet.summary(), "Packet Payload":"", "Prediction": ["ARP Spoof Attack"]},)

    def run(self):
        sniffer = Sniffer(prn=self.logging_packet, interface=self.interface,host_ip=self.host)
        thread1 = threading.Thread(target=start_monitoring, args=(self.dirfile,self.log))
        thread2 = threading.Thread(target=sniffer.run)
        thread1.daemon = True
        thread2.daemon = True
        thread1.start()
        thread2.start()
        detach_item = []
        self.paused = False

        async def update_table():
            while True:
                if self.paused == False:
                    data = self.log
                    if data is not None:
                        for entry in data:
                            prediction_str = ", ".join(entry["Prediction"])
                            table.insert("", "end", values=(entry["Date"], entry["Attack Type"],entry["Packet Summary"],entry["Packet Payload"], prediction_str))
                self.log.clear()
                await asyncio.sleep(1)

        def save_to_file():
            with open(self.logfile, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Date", "Attack Type", "Packet Summary","Packet Payload","Prediction"])
                for row in table.get_children():
                    date,attackType,packetSummary,packetPayload, aiPrediction = table.item(row)["values"]
                    writer.writerow([date,attackType,packetSummary,packetPayload, aiPrediction])

        def toggle_prediction(event):
            item_iid = table.identify_row(event.y)
            if item_iid:
                children = table.get_children(item_iid)
                if children:
                    table.delete(children)
                else:
                    item = table.item(item_iid)
                    predictions = item["values"][4].split(", ")
                    for prediction in predictions:
                        table.insert(item_iid, "end", values=("","","","", prediction))

        def sort_column(col_idx, descending=False):
            data = [(table.set(child, col_idx), child) for child in table.get_children('')]
            data.sort(reverse=descending)
            for idx, item in enumerate(data):
                table.move(item[1], '', idx)

        def on_sort_date():
            sort_column(0)

        def on_sort_attackType():
            sort_column(1)

        def on_sort_packetSummary():
            sort_column(2)

        def on_sort_packetPayload():
            sort_column(3)

        def on_sort_aiPrediction():
            sort_column(4)
            
        def on_search():
            search_string = search_entry.get()
            for item in table.get_children():
                values = table.item(item)["values"][1]
                if not(search_string in values):
                    table.selection_set(item)
                    table.detach(item)
                    detach_item.append(item)
            if not(detach_item == []):
                show_all_button.config(style='Blue.TButton')

                # else:
                #     table.selection_remove(item)
        def show_all():
            for item in detach_item:
                table.reattach(item, "", "end")
            detach_item.clear()
            show_all_button.config(style='TButton')

        def delete_all():
            table.delete(*table.get_children())
            detach_item.clear()

        def pause_data_updates():
            # global paused
            self.paused = True

        def play_data_updates():
            # global paused
            self.paused = False

        # GUI setup
        root = tk.Tk()
        root.title("Sapi Pot: Honeypot")
        # Create an instance of Style widget
        style=ttk.Style()
        style.theme_use('clam')

        # Configure a custom style for the "Show All" button (blue color)
        style.configure("Blue.TButton", foreground="white", background="blue")
        style.configure("ShowAll.TButton", foreground="black", background="SystemButtonFace")

        # Create Treeview (Table) with three columns: Date, Payload, Prediction
        table = ttk.Treeview(root, columns=("Date", "Attack Type", "Packet Summary","Packet Payload","Prediction"), show="headings")
        table.heading("Date", text="Date", command=on_sort_date)
        table.heading("Attack Type", text="Payload", command=on_sort_attackType)
        table.heading("Packet Summary", text="Data", command=on_sort_packetSummary)
        table.heading("Packet Payload", text="Prediction", command=on_sort_packetPayload)
        table.heading("Prediction", text="Prediction", command=on_sort_aiPrediction)
        table.pack(fill=tk.BOTH, expand=True)

        # Create Entry and Search Button for filtering by Date
        search_frame = ttk.Frame(root)
        search_frame.pack(pady=10)
        search_entry = ttk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_button = ttk.Button(search_frame, text="Search", command=on_search)
        search_button.pack(side=tk.LEFT, padx=5)

        # Add a vertical scrollbar for the table
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)

        # Pack the table and scrollbar to the right and fill both horizontally and vertically
        table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Button to copy data to a file
        copy_button = ttk.Button(root, text="Copy to File", command=save_to_file)
        copy_button.pack()

        # Button to show all rows after filtering
        show_all_button = ttk.Button(root, text="Show All", command=show_all)
        show_all_button.pack()
        
        # Button to pause data updates
        pause_button = ttk.Button(root, text="Pause", command=pause_data_updates)
        pause_button.pack()

        # Button to play data updates
        play_button = ttk.Button(root, text="Play", command=play_data_updates)
        play_button.pack()

        # Button to delete all items from the table
        delete_button = ttk.Button(root, text="Delete All", command=delete_all)
        delete_button.pack()

        # Start the asyncio event loop to run the coroutine
        async def start_update():
            await update_table()

        # Run the asyncio event loop in a separate thread to keep the GUI responsive
        update_thread = threading.Thread(target=asyncio.run, args=(start_update(),))
        update_thread.daemon = True  # Make sure the thread terminates when the GUI is closed
        update_thread.start()

        # Bind the event to expand/collapse the prediction values
        table.bind("<Button-1>", toggle_prediction)

        root.mainloop()
        # thread1.join()
        # thread2.join()
