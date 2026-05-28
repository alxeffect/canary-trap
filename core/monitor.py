from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

import config


class HoneyFileEventHandler(FileSystemEventHandler):
    """
    Handles file system events for honey tokens.
    """

    def __init__(self, alert_callback: Callable[[Path, str], None]):
        super().__init__()

        self.alert_callback = alert_callback

        # Cooldown tracking
        self._last_event_time: dict[str, float] = {}
        self._cooldown_seconds = 1.5

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

        if file_path.name not in config.HONEY_FILES:
            return

        now = time.time()

        key = str(file_path)

        last = self._last_event_time.get(key, 0)

        if now - last < self._cooldown_seconds:
            return

        self._last_event_time[key] = now

        self.alert_callback(file_path, event.event_type)


class HoneyMonitor:
    """
    Monitors honeypot files for suspicious access.
    """

    def __init__(
        self,
        directory: Path,
        alert_callback: Callable[[Path, str], None],
    ):
        self.directory = directory
        self.alert_callback = alert_callback

        self.event_handler = HoneyFileEventHandler(alert_callback)

        self.observer = Observer()

        self.running = False

        # Store last access times
        self.last_access_times: dict[Path, float] = {}

    def start(self) -> None:
        """
        Start monitoring.
        """

        self.running = True

        # Initialize access times
        for filename in config.HONEY_FILES:
            file_path = self.directory / filename

            if file_path.exists():
                self.last_access_times[file_path] = file_path.stat().st_atime

        # Start watchdog observer
        self.observer.schedule(
            self.event_handler,
            str(self.directory),
            recursive=False,
        )

        self.observer.start()

        # Start access polling thread
        threading.Thread(
            target=self._poll_file_access,
            daemon=True,
        ).start()

    def stop(self) -> None:
        """
        Stop monitoring.
        """

        self.running = False

        self.observer.stop()
        self.observer.join()

    def _poll_file_access(self) -> None:
        """
        Poll file access timestamps.
        Detect simple file opening / reading.
        """

        while self.running:

            for filename in config.HONEY_FILES:

                file_path = self.directory / filename

                if not file_path.exists():
                    continue

                try:
                    current_access = file_path.stat().st_atime

                    previous_access = self.last_access_times.get(
                        file_path,
                        current_access,
                    )

                    # Access detected
                    if current_access > previous_access:

                        self.last_access_times[file_path] = current_access

                        self.alert_callback(
                            file_path,
                            "accessed",
                        )

                except Exception:
                    continue

            time.sleep(1)

    def run_forever(self) -> None:
        """
        Keep monitor alive.
        """

        try:
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            self.stop()