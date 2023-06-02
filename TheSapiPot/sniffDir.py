import os
import time
import shutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FolderMonitor(FileSystemEventHandler):
    def __init__(self, monitor_folder, log_file):
        super().__init__()
        self.monitor_folder = monitor_folder
        self.logger = log_file
        # self.log_file = log_file
        # self.logger = self.setup_logger()
        self.is_directory = lambda arg: "Directory" if arg else "File"


    # def setup_logger(self):
    #     logger = logging.getLogger('FolderMonitor')
    #     logger.setLevel(logging.INFO)

    #     # Create a file handler and set the log file
    #     file_handler = logging.FileHandler(self.log_file)
    #     formatter = logging.Formatter('%(asctime)s - %(message)s')
    #     file_handler.setFormatter(formatter)
    #     logger.addHandler(file_handler)

        # return logger
    def on_any_event(self, event):
        # if event.is_directory and event.src_path == os.path.expanduser(self.monitor_folder):
        self.logger.info(f'[File Monitor]\n[*]Event Type: {event.event_type}\n[*]Target: {event.src_path}\n[*]Target Type: {self.is_directory(event.is_directory)}')
    # def on_deleted(self, event):
    #     if event.is_directory and event.src_path == os.path.expanduser(self.monitor_folder):
    #         self.logger.info(f'Folder {self.monitor_folder} was deleted')


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

# desktop_path = os.path.expanduser("~/Desktop")
# folder_path = os.path.join(desktop_path, "SapiDirFile")

# logf = "wd.log"

# start_monitoring(folder_path,logf)