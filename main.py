from __future__ import annotations

import ctypes
import sys

from gui.app import CanaryTrapApp


def is_admin() -> bool:
    """
    Check if application runs with administrator privileges.
    """

    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """
    Relaunch application with administrator privileges.
    """

    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        " ".join(sys.argv),
        None,
        1,
    )


def main() -> None:

    # Force administrator privileges
    if not is_admin():
        relaunch_as_admin()
        sys.exit()

    app = CanaryTrapApp()
    app.mainloop()


if __name__ == "__main__":
    main()