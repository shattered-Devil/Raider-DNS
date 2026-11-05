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


    def test_qt_render_smoke_uses_qpaintdevice_overload(self) -> None:
        smoke_test = Path(__file__).with_name("test_qt_visual_smoke.py")
        tree = ast.parse(smoke_test.read_text(encoding="utf-8"))
        render_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "render"
        ]
        self.assertEqual(len(render_calls), 1)
        # QWidget.render(QPaintDevice) avoids the PySide6 QPainter overload,
        # which requires the positional targetOffset argument in Qt 6.
        self.assertEqual(len(render_calls[0].args), 1)
        self.assertIsInstance(render_calls[0].args[0], ast.Name)
        self.assertEqual(render_calls[0].args[0].id, "image")

    def test_qtablewidget_base_is_imported_under_wrapper_alias(self) -> None:
        source = Path(__file__).parents[1] / "raider_dns" / "ui" / "main_window.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported_aliases = {
            alias.asname
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "PySide6.QtWidgets"
            for alias in node.names
        }
        self.assertIn("_QtQTableWidget", imported_aliases)

        wrapper = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "QTableWidget"
        )
        self.assertEqual(len(wrapper.bases), 1)
        self.assertIsInstance(wrapper.bases[0], ast.Name)
        self.assertEqual(wrapper.bases[0].id, "_QtQTableWidget")


if __name__ == "__main__":
    unittest.main()
