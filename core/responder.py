from __future__ import annotations

import ctypes
import platform
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional, Tuple

import psutil

import config
from core.threatintel import get_process_connections, query_ip_intel, get_all_suspicious_connections

POWERSHELL_PATH = "powershell.exe"

# Windows constant to hide console windows
CREATE_NO_WINDOW = 0x08000000

# Store disabled adapters
_DISABLED_ADAPTERS: list[str] = []


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


def analyze_network_threat(pid: int, on_result: Callable[[str], None]) -> None:
    if not config.NETWORK_MONITORING_ENABLED:
        return

    # Try specific process first
    remote_ips = get_process_connections(pid)

    # If no IPs for that process, check all suspicious connections in system
    if not remote_ips:
        on_result("[INFO] Specific process has no network. Scanning system for suspicious connections...")
        remote_ips = get_all_suspicious_connections()

    if not remote_ips:
        on_result("[NETWORK] No suspicious network connections detected in system.")
        return

    # Limit to first 3 IPs to not spam the API
    for ip in remote_ips[:3]:
        on_result(f"[NETWORK] Analyzing IP: {ip}")
        intel = query_ip_intel(ip)
        if intel and intel.get("status") == "success":
            country = intel.get("country", "N/A")
            isp = intel.get("isp", "N/A")
            on_result(f"  ↳ Alert: IP {ip} originates from {country} (ISP: {isp})")


def handle_alert_async(
    file_path: Path,
    event_type: str,
    on_result: Callable[[str], None],
    auto_kill: bool = True,
    auto_network_cut: bool = False,
) -> None:
    """
    Run alert handling in a separate thread so watchdog is never blocked.
    Foreground PID is captured immediately (before thread starts)
    to ensure we get the correct process while it's still active.
    """

    # Capture foreground process immediately — before threading delay
    process_info = find_process_using_file(file_path)

    def _task() -> None:
        on_result(f"[ALERT] {event_type.upper()} detected on: {file_path.name}")

        if not process_info:
            on_result("[INFO] Could not identify responsible process.")
            return

        pid, process_name = process_info
        on_result(f"[INFO] Process identified: {process_name} (PID {pid})")

        if is_process_safe(process_name):
            on_result(f"[INFO] Process '{process_name}' is whitelisted. No action taken.")
            return

        if auto_kill:
            # Analyze network BEFORE killing
            if config.NETWORK_MONITORING_ENABLED:
                analyze_network_threat(pid, on_result)

            success = kill_process(pid)

            if success:
                on_result(f"[ACTION] Process '{process_name}' (PID {pid}) terminated successfully.")
                if auto_network_cut:
                    on_result("[NUCLEAR] Emergency network isolation triggered.")

                    network_success = disable_network()

                    if network_success:
                        on_result("[NUCLEAR] Network adapters disabled.")
                    else:
                        on_result("[ERROR] Failed to disable network.")
            else:
                on_result(f"[ERROR] Failed to terminate '{process_name}' (PID {pid}).")

    thread = threading.Thread(target=_task, daemon=True)
    thread.start()


def disable_network() -> bool:
    """
    Block all outbound network traffic using Windows Firewall.
    Safer and more stable than disabling adapters.
    """

    if platform.system() != "Windows":
        return False

    try:

        command = (
            'New-NetFirewallRule '
            '-DisplayName "CanaryTrapBlockOutbound" '
            '-Direction Outbound '
            '-Action Block'
        )

        result = subprocess.run(
            [POWERSHELL_PATH, "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=CREATE_NO_WINDOW,
        )

        return result.returncode == 0

    except Exception:
        return False


def enable_network() -> bool:
    """
    Remove firewall rule created by Canary-Trap.
    Restore outbound traffic.
    """

    if platform.system() != "Windows":
        return False

    try:

        command = (
            'Remove-NetFirewallRule '
            '-DisplayName "CanaryTrapBlockOutbound"'
        )

        result = subprocess.run(
            [POWERSHELL_PATH, "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=CREATE_NO_WINDOW,
        )

        return result.returncode == 0

    except Exception:
        return False