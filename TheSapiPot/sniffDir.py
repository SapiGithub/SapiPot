import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


class FolderMonitor(FileSystemEventHandler):
    def __init__(self, monitor_folder, log):
        super().__init__()
        self.monitor_folder = monitor_folder
        self.log = log
        
    def on_any_event(self, event):
        self.log.append({"Date": time.strftime("%H:%M:%S", time.localtime()),"Attack Type":"[Folder Monitor]", "Packet Summary": "", "Packet Payload":event.src_path, "Prediction": [event.event_type]},)
        # self.logger.info(f'[File Monitor]\n[*]Event Type: {event.event_type}\n[*]Target: {event.src_path}\n[*]Target Type: {self.is_directory(event.is_directory)}')

def start_monitoring(monitor_folder, log_file):
    monitor = FolderMonitor(monitor_folder, log_file)
    observer = Observer()
    observer.schedule(monitor, os.path.expanduser(monitor_folder), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
