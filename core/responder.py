from __future__ import annotations

import ctypes
import threading
from pathlib import Path
from typing import Callable, Optional, Tuple

import psutil
import config


def find_process_using_file(target_file: Path) -> Optional[Tuple[int, str]]:
    """
    Identify the process responsible for touching the honey file.
    Uses foreground window detection — most reliable method on Windows
    given that most editors release file handles immediately after saving.
    """

    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        pid = ctypes.c_ulong(0)
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

        if not pid.value:
            return None

        proc = psutil.Process(pid.value)
        return pid.value, proc.name()

    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        return None


def is_process_safe(process_name: str) -> bool:
    """
    Check if process is whitelisted.
    """

    return process_name.lower() in config.SAFE_PROCESSES


def kill_process(pid: int) -> bool:
    """
    Terminate suspicious process.
    """

    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        return False


def handle_alert_async(
    file_path: Path,
    event_type: str,
    on_result: Callable[[str], None],
) -> None:
    """
    Run alert handling in a separate thread so watchdog is never blocked.
    """

    def _task() -> None:
        on_result(f"[ALERT] {event_type.upper()} detected on: {file_path.name}")

        process_info = find_process_using_file(file_path)

        if not process_info:
            on_result("[INFO] Could not identify responsible process.")
            return

        pid, process_name = process_info
        on_result(f"[INFO] Process identified: {process_name} (PID {pid})")

        if is_process_safe(process_name):
            on_result(f"[INFO] Process '{process_name}' is whitelisted. No action taken.")
            return

        if config.AUTO_KILL_ENABLED:
            success = kill_process(pid)
            if success:
                on_result(f"[ACTION] Process '{process_name}' (PID {pid}) terminated successfully.")
            else:
                on_result(f"[ERROR] Failed to terminate '{process_name}' (PID {pid}).")

    thread = threading.Thread(target=_task, daemon=True)
    thread.start()