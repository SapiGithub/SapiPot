import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FolderMonitor(FileSystemEventHandler):
    def __init__(self, monitor_folder, log_file):
        super().__init__()
        self.monitor_folder = monitor_folder
        self.logger = log_file
        self.is_directory = lambda arg: "Directory" if arg else "File"
        
    def on_any_event(self, event):
        self.logger.info(f'[File Monitor]\n[*]Event Type: {event.event_type}\n[*]Target: {event.src_path}\n[*]Target Type: {self.is_directory(event.is_directory)}')

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
