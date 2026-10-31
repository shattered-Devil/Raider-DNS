"""Raider DNS — PySide6 desktop application entry point."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from raider_dns import __version__
from raider_dns.ui.main_window import MainWindow
from raider_dns.ui.theme import stylesheet
from raider_dns.storage import ConfigStore


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Raider DNS")
    app.setOrganizationName("Nima Zahedi")
    app.setApplicationVersion(__version__)
    icon_path = Path(__file__).parent / "assets" / "app_icon.svg"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    try:
        settings = ConfigStore().load()
        app.setStyleSheet(stylesheet(settings.get("theme", "dark")))
        window = MainWindow()
        window.show()
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Raider DNS failed to start", f"An unexpected startup error occurred:\n\n{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
