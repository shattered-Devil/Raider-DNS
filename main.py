"""Raider DNS — PySide6 desktop application entry point."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from raider_dns import __version__
from raider_dns.instance import SingleInstanceGuard
from raider_dns.storage import ConfigStore, app_data_dir
from raider_dns.ui.main_window import MainWindow
from raider_dns.ui.theme import stylesheet

_ADMIN_HANDOFF_ARGUMENT = "--admin-handoff"
_ADMIN_HANDOFF_WAIT_SECONDS = 90.0


def main() -> int:
    """Start one Raider DNS instance and coordinate safe UAC replacement."""
    is_admin_handoff = _ADMIN_HANDOFF_ARGUMENT in sys.argv[1:]
    # Do not pass the private handoff switch through to Qt or application code.
    if is_admin_handoff:
        sys.argv[:] = [arg for arg in sys.argv if arg != _ADMIN_HANDOFF_ARGUMENT]

    app = QApplication(sys.argv)
    app.setApplicationName("Raider DNS")
    app.setOrganizationName("Nima Zahedi")
    app.setApplicationVersion(__version__)
    icon_path = Path(__file__).parent / "assets" / "app_icon.svg"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    guard = SingleInstanceGuard(app_data_dir() / "raiderdns.instance.lock")
    wait_for_owner = _ADMIN_HANDOFF_WAIT_SECONDS if is_admin_handoff else 0.0
    if not guard.acquire(timeout_seconds=wait_for_owner):
        if is_admin_handoff:
            QMessageBox.critical(
                None,
                "Administrator handoff timed out",
                "The previous Raider DNS instance did not finish its safe shutdown in time. "
                "The elevated instance was not started, so duplicate tray icons and competing "
                "DNS controllers are avoided. Return to the original window and retry after "
                "its network operations or tunnel shutdown finish.",
            )
            return 2
        if not guard.request_activation():
            QMessageBox.information(
                None,
                "Raider DNS is already running",
                "A Raider DNS instance is already running, possibly hidden in the system tray. "
                "No second instance was started. Use the existing Raider DNS tray icon.",
            )
        return 0

    app.aboutToQuit.connect(guard.release)
    try:
        settings = ConfigStore().load()
        app.setStyleSheet(stylesheet(settings.get("theme", "dark")))
        window = MainWindow()
        if not guard.start_activation_server(window.activate_from_existing_instance):
            window._log("Single-instance activation endpoint could not be started; duplicate process protection remains active.", "WARNING")
        window.show()
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Raider DNS failed to start", f"An unexpected startup error occurred:\n\n{exc}")
        return 1
    finally:
        guard.release()


if __name__ == "__main__":
    raise SystemExit(main())
