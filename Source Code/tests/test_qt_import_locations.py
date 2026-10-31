"""Static regression tests for PySide6 import locations."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path


class QtImportLocationTests(unittest.TestCase):
    def test_qpainterpath_is_imported_from_qtgui(self) -> None:
        source = Path(__file__).parents[1] / "raider_dns" / "ui" / "main_window.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        locations: dict[str, list[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in {"PySide6.QtCore", "PySide6.QtGui"}:
                locations[node.module] = [alias.name for alias in node.names]

        self.assertIn("QPainterPath", locations.get("PySide6.QtGui", []))
        self.assertNotIn("QPainterPath", locations.get("PySide6.QtCore", []))


if __name__ == "__main__":
    unittest.main()
