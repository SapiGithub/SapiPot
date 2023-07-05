import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FolderMonitor(FileSystemEventHandler):
    def __init__(self, monitor_folder, log_file):
        super().__init__()
        self.monitor_folder = monitor_folder
        self.logger = log_file

    def on_any_event(self, event):
        self.logger.info(f'[File Monitor]\n[*]Event Type: {event.event_type}\n[*]Target: {event.src_path}\n[*]Target Type: {self.is_directory(event.is_directory)}')


def start_monitoring(monitor_folder, log_file):
    monitor_folder = os.path.expanduser(monitor_folder)
    monitor = FolderMonitor(monitor_folder, log_file)

    with Observer() as observer:
        observer.schedule(monitor, monitor_folder, recursive=True)
        observer.start()

        try:
            observer.join()
        except KeyboardInterrupt:
            observer.stop()
