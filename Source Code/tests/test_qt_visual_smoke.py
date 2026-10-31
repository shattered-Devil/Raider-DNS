"""Optional real Qt paint smoke test for the Plasma Stream widget.

The test is skipped when PySide6 is not installed (for example, in a minimal
source-only CI environment). Windows CI installs requirements and executes it.
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover - environment-dependent skip
    QT_AVAILABLE = False
else:
    QT_AVAILABLE = True


@unittest.skipUnless(QT_AVAILABLE, "PySide6 is not installed; Qt render smoke test skipped")
class PlasmaQtRenderSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])
        from raider_dns.ui.main_window import ConnectionStatusVisual

        cls.visual_type = ConnectionStatusVisual

    def test_visual_renders_all_status_states_and_stops_timer_when_hidden(self) -> None:
        from PySide6.QtGui import QImage, QPainter

        widget = self.visual_type()
        widget.resize(1280, 220)
        widget.show()
        self.app.processEvents()
        self.assertTrue(widget._timer.isActive())

        for state in ("idle", "connecting", "success", "warning", "failure"):
            with self.subTest(state=state):
                widget.set_state(state)
                self.app.processEvents()
                image = QImage(1280, 220, QImage.Format.Format_ARGB32_Premultiplied)
                image.fill(Qt.GlobalColor.transparent)
                painter = QPainter(image)
                try:
                    widget.render(painter)
                finally:
                    painter.end()
                self.assertFalse(image.isNull())
                # Ensure the paint event actually produced non-transparent pixels.
                painted_pixels = sum(
                    1 for x in range(0, image.width(), 16)
                    for y in range(0, image.height(), 16)
                    if image.pixelColor(x, y).alpha() > 0
                )
                self.assertGreater(painted_pixels, 0)

        widget.hide()
        self.app.processEvents()
        self.assertFalse(widget._timer.isActive())
        widget.deleteLater()
        self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
