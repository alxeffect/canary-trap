from pathlib import Path

import config
from core.honeypot import generate_honey_files
from core.monitor import HoneyMonitor
from core.responder import handle_alert_async


def log_message(message: str) -> None:
    print(message)


def alert_callback(file_path: Path, event_type: str) -> None:
    handle_alert_async(file_path, event_type, on_result=log_message)


def main() -> None:
    generate_honey_files(
        config.HONEYPOT_DIR,
        config.HONEY_FILES,
        config.DEFAULT_HONEY_CONTENT,
    )

    monitor = HoneyMonitor(config.HONEYPOT_DIR, alert_callback)
    monitor.start()

    print("[SYSTEM] Canary-Trap monitoring started.")
    print(f"[SYSTEM] Watching: {config.HONEYPOT_DIR}")
    print("[SYSTEM] Press Ctrl+C to stop.\n")

    monitor.run_forever()


if __name__ == "__main__":
    main()