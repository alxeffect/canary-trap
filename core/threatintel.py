from __future__ import annotations
from typing import Dict, List
import psutil
import requests
import config


def get_process_connections(pid: int) -> List[str]:
    """
    Get remote IP addresses for a specific PID.
    """
    remote_ips: List[str] = []
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind="inet")
        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip
                if ip not in remote_ips and ip != "127.0.0.1":
                    remote_ips.append(ip)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return remote_ips


def get_all_suspicious_connections() -> List[str]:
    """
    Fallback: Get all active remote IPs from non-whitelisted processes.
    This simulates catching a background hacker/malware.
    """
    suspicious_ips = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Skip whitelisted
            if proc.info['name'].lower() in config.SAFE_PROCESSES:
                continue

            connections = proc.connections(kind="inet")
            for conn in connections:
                if conn.raddr:
                    ip = conn.raddr.ip

                    # Skip localhost and private/local networks
                    if (
                            ip.startswith("127.")
                            or ip.startswith("192.168.")
                            or ip.startswith("10.")
                            or ip.startswith("172.")
                    ):
                        continue

                    if ip not in suspicious_ips:
                        suspicious_ips.append(ip)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_ips


def query_ip_intel(ip: str) -> Dict:
    try:
        response = requests.get(f"{config.THREAT_INTEL_API}{ip}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}