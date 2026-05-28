from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config


class HoneyFileEventHandler(FileSystemEventHandler):
    """
    Handles file system events for honey tokens.
    """

    def __init__(self, alert_callback: Callable[[Path, str], None]):
        super().__init__()
        self.alert_callback = alert_callback
        # Cooldown tracking to prevent duplicate events
        self._last_event_time: dict[str, float] = {}
        self._cooldown_seconds: float = 1.5

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._handle_event(event)

    def _handle_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if file_path.suffix.lower() not in config.MONITOR_EXTENSIONS:
            return

        if file_path.name not in config.HONEY_FILES:
            return

        # Cooldown check — suppress duplicate events
        now = time.time()
        key = f"{file_path}_{event.event_type}"
        last = self._last_event_time.get(key, 0.0)

        if now - last < self._cooldown_seconds:
            return

        self._last_event_time[key] = now
        self.alert_callback(file_path, event.event_type)


class HoneyMonitor:
    """
    Monitors honeypot directory for suspicious access.
    """

    def __init__(self, directory: Path, alert_callback: Callable[[Path, str], None]):
        self.directory = directory
        self.event_handler = HoneyFileEventHandler(alert_callback)
        self.observer = Observer()

    def start(self) -> None:
        self.observer.schedule(self.event_handler, str(self.directory), recursive=False)
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join()

    def run_forever(self) -> None:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()