from pathlib import Path

import ctypes

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

''' NETWORK TESTING

    #is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    #print("Is User Admin?:", is_admin)

    from core.responder import disable_network, enable_network
    import time

    # Upewnij się, że ten kod zostanie usunięty po teście!
    print("--- ROZPOCZYNAM TEST ODCIĘCIA SIECI ---")
    print("Program musi być uruchomiony jako Administrator.")

    print("\n[KROK 1] Odcinanie sieci za 5 sekund...")
    time.sleep(5)

    if disable_network():
        print("[SUKCES] Polecenie odcięcia sieci wykonane. Sprawdź ikonę sieci w Windows.")
    else:
        print("[BŁĄD] Nie udało się wykonać polecenia odcięcia sieci.")

    print("\n[KROK 2] Przywracanie sieci za 10 sekund...")
    time.sleep(17)

    if enable_network():
        print("[SUKCES] Polecenie przywrócenia sieci wykonane. Sprawdź, czy internet wrócił.")
    else:
        print("[BŁĄD] Nie udało się przywrócić sieci.")

    print("\n--- TEST ZAKOŃCZONY ---")

'''