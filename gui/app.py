from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional
from datetime import datetime

import customtkinter as ctk
from tkinter import StringVar

import psutil

import config
from core.honeypot import generate_honey_files
from core.monitor import HoneyMonitor
from core.responder import (
    handle_alert_async,
    disable_network,
    enable_network,
    find_process_using_file
)


class CanaryTrapApp(ctk.CTk):
    """
    Main GUI application window.
    """

    def __init__(self) -> None:
        super().__init__()

        # =========================
        # WINDOW SETUP
        # =========================

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(config.WINDOW_TITLE)
        self.geometry(config.WINDOW_SIZE)

        # =========================
        # MONITOR STATE
        # =========================

        self.monitor: Optional[HoneyMonitor] = None
        self.monitoring_active = False

        # =========================
        # INCIDENT LOCK
        # =========================

        self.active_incidents: dict[str, float] = {}

        # =========================
        # TRACKED THREAT PROCESS
        # =========================

        self.last_detected_pid: Optional[int] = None
        self.last_detected_process: Optional[str] = None

        self.incident_cooldown = 5.0

        # =========================
        # ALERT COUNTER
        # =========================

        self.alert_count = 0

        # =========================
        # RESPONSE MODE
        # =========================

        self.response_mode = StringVar(
            value=config.DEFAULT_RESPONSE_MODE,
        )

        # =========================
        # HEADER
        # =========================

        self.header_label = ctk.CTkLabel(
            self,
            text="Canary-Trap | Host IDS",
            font=("Segoe UI", 28, "bold"),
        )

        self.header_label.pack(pady=(20, 10))

        # =========================
        # STATUS LABEL
        # =========================

        self.status_label = ctk.CTkLabel(
            self,
            text="System Status: Idle",
            font=("Segoe UI", 16),
            text_color="gray",
        )

        self.status_label.pack(pady=(0, 20))

        # =========================
        # ALERT COUNTER LABEL
        # =========================

        self.alert_counter_label = ctk.CTkLabel(
            self,
            text="Alerts detected: 0",
            font=("Segoe UI", 15, "bold"),
            text_color="#FF5555",
        )

        self.alert_counter_label.pack(pady=(0, 10))

        # =========================
        # BUTTON FRAME
        # =========================

        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=10)

        # =========================
        # RESPONSE MODE MENU
        # =========================

        self.response_mode_menu = ctk.CTkOptionMenu(
            self,
            values=config.RESPONSE_MODES,
            variable=self.response_mode,
            width=250,
            command=self.on_response_mode_changed,
        )

        self.response_mode_menu.pack(pady=(0, 15))

        # =========================
        # START BUTTON
        # =========================

        self.start_button = ctk.CTkButton(
            self.button_frame,
            text="Start Monitoring",
            width=180,
            height=40,
            command=self.start_monitoring,
        )

        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        # =========================
        # STOP BUTTON
        # =========================

        self.stop_button = ctk.CTkButton(
            self.button_frame,
            text="Stop Monitoring",
            width=180,
            height=40,
            fg_color="#8B0000",
            hover_color="#A00000",
            command=self.stop_monitoring,
        )

        self.stop_button.grid(row=0, column=1, padx=10, pady=10)

        # =========================
        # DISABLE NETWORK BUTTON
        # =========================

        self.disable_network_button = ctk.CTkButton(
            self.button_frame,
            text="Disable Network",
            width=180,
            height=40,
            fg_color="#AA5500",
            hover_color="#CC6600",
            command=self.disable_network_action,
        )

        self.disable_network_button.grid(row=1, column=0, padx=10, pady=10)

        # =========================
        # ENABLE NETWORK BUTTON
        # =========================

        self.enable_network_button = ctk.CTkButton(
            self.button_frame,
            text="Restore Network",
            width=180,
            height=40,
            fg_color="#006644",
            hover_color="#008855",
            command=self.enable_network_action,
        )

        self.enable_network_button.grid(row=1, column=1, padx=10, pady=10)

        # =========================
        # LOG BOX
        # =========================

        self.log_textbox = ctk.CTkTextbox(
            self,
            width=900,
            height=400,
            font=("Consolas", 13),
        )

        self.log_textbox.pack(padx=20, pady=20)

        # Configure log colors
        self.log_textbox.tag_config("alert", foreground="#FF5555")
        self.log_textbox.tag_config("info", foreground="#BBBBBB")
        self.log_textbox.tag_config("action", foreground="#50FA7B")
        self.log_textbox.tag_config("network", foreground="#FFB86C")
        self.log_textbox.tag_config("nuclear", foreground="#FF00FF")
        self.log_textbox.tag_config("error", foreground="#FF2222")

        self.log("[SYSTEM] Canary-Trap GUI initialized.")

    def log(self, message: str) -> None:
        """
        Append colored message to GUI log box
        and save logs to file.
        """

        def append() -> None:

            tag = "info"

            upper = message.upper()

            if "[ALERT]" in upper:
                tag = "alert"

            elif "[ACTION]" in upper:
                tag = "action"

            elif "[NETWORK]" in upper:
                tag = "network"

            elif "[NUCLEAR]" in upper:
                tag = "nuclear"

            elif "[ERROR]" in upper:
                tag = "error"

            # Timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            formatted_message = f"[{timestamp}] {message}"

            # =========================
            # GUI LOG
            # =========================

            self.log_textbox.insert(
                "end",
                f"{formatted_message}\n",
                tag,
            )

            self.log_textbox.see("end")

            # =========================
            # FILE LOG
            # =========================

            try:

                with open(
                        config.LOG_FILE,
                        "a",
                        encoding="utf-8",
                ) as log_file:

                    log_file.write(
                        f"{formatted_message}\n"
                    )

            except Exception:
                pass

        self.after(0, append)

    def alert_callback(self, file_path: Path, event_type: str) -> None:
        """
        Handle watchdog alerts.
        Prevent duplicate incidents for the same file.
        """

        import time

        now = time.time()

        file_key = file_path.name.lower()

        last_incident = self.active_incidents.get(file_key, 0)

        # Ignore duplicate incidents during cooldown
        if now - last_incident < self.incident_cooldown:
            return

        self.active_incidents[file_key] = now

        self.increment_alert_counter()

        mode = self.response_mode.get()

        # Store last detected threat process
        process_info = find_process_using_file(file_path)

        if process_info:
            pid, process_name = process_info

            self.last_detected_pid = pid
            self.last_detected_process = process_name

        auto_kill = False
        auto_network_cut = False

        if mode == "Kill Process":
            auto_kill = True

        elif mode == "Nuclear Mode":
            auto_kill = True
            auto_network_cut = True

        handle_alert_async(
            file_path=file_path,
            event_type=event_type,
            on_result=self.log,
            auto_kill=auto_kill,
            auto_network_cut=auto_network_cut,
        )

    def start_monitoring(self) -> None:
        """
        Start honeypot monitoring.
        """

        if self.monitoring_active:
            self.log("[INFO] Monitoring already active.")
            return

        generate_honey_files(
            config.HONEYPOT_DIR,
            config.HONEY_FILES,
            config.DEFAULT_HONEY_CONTENT,
        )

        self.monitor = HoneyMonitor(
            config.HONEYPOT_DIR,
            self.alert_callback,
        )

        self.monitor.start()

        self.monitoring_active = True

        self.status_label.configure(
            text="System Status: Monitoring",
            text_color="green",
        )

        self.log("[SYSTEM] Monitoring started.")

    def stop_monitoring(self) -> None:
        """
        Stop honeypot monitoring.
        """

        if not self.monitoring_active:
            self.log("[INFO] Monitoring is not active.")
            return

        if self.monitor:
            self.monitor.stop()

        self.monitoring_active = False

        self.status_label.configure(
            text="System Status: Stopped",
            text_color="red",
        )

        self.log("[SYSTEM] Monitoring stopped.")

    def disable_network_action(self) -> None:
        """
        Isolate host.
        """

        self.log("[NETWORK] Applying host isolation...")

        def task() -> None:
            success = disable_network()

            if success:
                self.log("[NETWORK] Host outbound traffic blocked.")
            else:
                self.log("[ERROR] Failed to block outbound traffic.")

        threading.Thread(target=task, daemon=True).start()

    def enable_network_action(self) -> None:
        """
        Restore host network connectivity.
        """

        self.log("[NETWORK] Restoring host network connectivity...")

        def task() -> None:
            success = enable_network()

            if success:
                self.log("[NETWORK] Host network connectivity restored.")
            else:
                self.log("[ERROR] Failed to restore host network connectivity.")

        threading.Thread(target=task, daemon=True).start()

    def increment_alert_counter(self) -> None:
        """
        Increase alert counter.
        """

        self.alert_count += 1

        self.alert_counter_label.configure(
            text=f"Alerts detected: {self.alert_count}"
        )

    def on_response_mode_changed(self, selected_mode: str) -> None:
        """
        React immediately when response mode changes.
        """

        self.log(f"[SYSTEM] Response mode changed to: {selected_mode}")

        # Only trigger active response for aggressive modes
        if selected_mode not in ["Kill Process", "Nuclear Mode"]:
            return

        # No tracked threat yet
        if not self.last_detected_pid:
            self.log("[INFO] No active threat process tracked.")
            return

        try:
            proc = psutil.Process(self.last_detected_pid)

            process_name = proc.name()

            # Skip safe processes
            if process_name.lower() in config.SAFE_PROCESSES:
                self.log(
                    f"[INFO] Process '{process_name}' is whitelisted."
                )
                return

            self.log(
                f"[ACTIVE RESPONSE] Terminating tracked threat process: "
                f"{process_name} (PID {proc.pid})"
            )

            proc.kill()

            self.log(
                f"[ACTION] Process '{process_name}' "
                f"(PID {proc.pid}) terminated immediately."
            )

            # Nuclear mode
            if selected_mode == "Nuclear Mode":

                self.log(
                    "[NUCLEAR] Emergency network isolation triggered."
                )

                success = disable_network()

                if success:
                    self.log(
                        "[NUCLEAR] Host outbound traffic blocked."
                    )

                else:
                    self.log(
                        "[ERROR] Failed to block outbound traffic."
                    )

        except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
        ):

            self.log(
                "[INFO] Tracked threat process no longer exists."
            )