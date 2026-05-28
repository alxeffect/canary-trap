"""
Canary-Trap Configuration
=========================
Central configuration module for the Canary-Trap Host IDS / Honeypot system.

This file contains:
- Project paths
- Logging configuration
- Honeypot settings
- Security policies
- Network settings
- GUI settings
"""

from pathlib import Path

# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

LOGS_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
CORE_DIR = BASE_DIR / "core"
GUI_DIR = BASE_DIR / "gui"
HONEYPOT_DIR = BASE_DIR / "honeypot_files"

# Create required directories automatically
for directory in [LOGS_DIR, DATA_DIR, HONEYPOT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# =========================================================
# HONEYPOT SETTINGS
# =========================================================

# Fake sensitive files that will be monitored
HONEY_FILES: list[str] = [
    "confidential_salaries_2024.xlsx",
    "client_database_passwords.txt",
    "admin_credentials_network.txt",
    "private_keys_backup.pem",
    "bank_transfer_instructions.pdf",
    "vpn_access_tokens.txt",
]

# Extensions that should trigger monitoring
MONITOR_EXTENSIONS: set[str] = {
    ".xlsx",
    ".txt",
    ".pdf",
    ".pem",
    ".docx",
    ".csv",
}

# Optional fake content for generated honey files
DEFAULT_HONEY_CONTENT = """
CONFIDENTIAL INTERNAL DOCUMENT
------------------------------

Username: administrator
Password: P@ssw0rd123!

WARNING:
Unauthorized access is prohibited.
"""

# =========================================================
# PROCESS WHITELIST
# =========================================================

# Critical system and trusted processes
# These processes will NEVER be terminated
SAFE_PROCESSES: set[str] = {
    # Windows core processes
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",

    # Desktop/UI
    "explorer.exe",
    "dwm.exe",
    "ctfmon.exe",

    # Consoles
    "cmd.exe",
    "powershell.exe",
    "conhost.exe",

    # Security
    "msmpeng.exe",
    "searchindexer.exe",

    # Development
    "python.exe",
    "pythonw.exe",
    "pycharm64.exe",

    # Application itself
    "canarytrap.exe",
    "canary-trap.exe",
    "canary_trap.exe",
}

# =========================================================
# NETWORK SETTINGS
# =========================================================

# Public IP intelligence API
THREAT_INTEL_API = "http://ip-api.com/json/"
#THREAT_INTEL_API = "https://ip-api.com/json/"

# File used to indicate disabled networking
NETWORK_DISABLED_FILE = BASE_DIR / "network_disabled.flag"

# Enable network monitoring
NETWORK_MONITORING_ENABLED = True

# =========================================================
# AUTO RESPONSE SETTINGS
# =========================================================

# Automatically terminate suspicious processes
AUTO_KILL_ENABLED = True

# Delay before process termination
KILL_GRACE_PERIOD = 0

# Extreme option: disable network access
AUTO_NETWORK_CUT = False

# Save forensic evidence before action
SAVE_FORENSICS = True

# =========================================================
# LOGGING SETTINGS
# =========================================================

LOG_LEVEL = "INFO"

LOG_FILE = LOGS_DIR / "canary_trap.log"
ALERT_LOG = LOGS_DIR / "alerts.log"
FORENSIC_LOG = LOGS_DIR / "forensics.log"

# Maximum log size before rotation (MB)
MAX_LOG_SIZE_MB = 10

# =========================================================
# GUI SETTINGS
# =========================================================

WINDOW_TITLE = "Canary-Trap | Host IDS"
WINDOW_SIZE = "1000x650"
REFRESH_RATE_MS = 1000
DARK_MODE = True

# =========================================================
# DEBUG SETTINGS
# =========================================================

DEBUG_MODE = False
VERBOSE_PROCESS_LOGGING = False

# =========================================================
# VERSION
# =========================================================

APP_NAME = "Canary-Trap"
VERSION = "1.0.0"