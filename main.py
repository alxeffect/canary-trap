from gui.app import CanaryTrapApp


def main() -> None:
    app = CanaryTrapApp()
    app.mainloop()


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