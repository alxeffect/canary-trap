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
    Disable active physical network adapters
    and remember which were disabled.
    """

    global _DISABLED_ADAPTERS
    _DISABLED_ADAPTERS.clear()

    if platform.system() != "Windows":
        return False

    try:
        # Get active physical adapters
        get_command = r"""
        Get-NetAdapter |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.HardwareInterface -eq $true
        } |
        Select-Object -ExpandProperty Name
        """

        result = subprocess.run(
            [POWERSHELL_PATH, "-Command", get_command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        adapter_names = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        if not adapter_names:
            return False

        _DISABLED_ADAPTERS = adapter_names.copy()

        # Disable only detected adapters
        for adapter in adapter_names:
            disable_command = (
                f'Disable-NetAdapter -Name "{adapter}" -Confirm:$false'
            )

            subprocess.run(
                [POWERSHELL_PATH, "-Command", disable_command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )

        return True

    except Exception as e:
        print(f"[ERROR] disable_network failed: {e}")
        return False


def enable_network() -> bool:
    """
    Re-enable ONLY adapters previously disabled.
    """

    global _DISABLED_ADAPTERS

    if platform.system() != "Windows":
        return False

    if not _DISABLED_ADAPTERS:
        print("[INFO] No adapters stored for re-enable.")
        return False

    success = False

    try:
        for adapter in _DISABLED_ADAPTERS:

            enable_command = (
                f'Enable-NetAdapter -Name "{adapter}" -Confirm:$false'
            )

            result = subprocess.run(
                [POWERSHELL_PATH, "-Command", enable_command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )

            if result.returncode == 0:
                print(f"[INFO] Re-enabled adapter: {adapter}")
                success = True
            else:
                print(f"[ERROR] Failed enabling: {adapter}")
                print(result.stderr)

        _DISABLED_ADAPTERS.clear()

        return success

    except Exception as e:
        print(f"[ERROR] enable_network failed: {e}")
        return False