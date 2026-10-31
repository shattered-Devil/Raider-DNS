"""Structural regression checks for the Qt Plasma Stream visual.

These tests guard against the previously observed phase-reset and layout choices.
They do not replace a live PySide6 GUI rendering test.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "raider_dns" / "ui" / "main_window.py"


class PlasmaVisualSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.start = cls.source.index("class ConnectionStatusVisual(QWidget):")
        cls.end = cls.source.index("\n\nclass PageHeader(QWidget):", cls.start)
        cls.visual = cls.source[cls.start:cls.end]

    def test_master_animation_phase_does_not_wrap_at_one(self):
        self.assertIn("self._phase += speed", self.visual)
        self.assertNotIn("self._phase = (self._phase + speed) % 1.0", self.visual)

    def test_stream_uses_broad_ribbons_and_fine_filaments(self):
        self.assertIn("def _ribbon_path(", self.visual)
        self.assertIn("def _strand_path(", self.visual)
        self.assertIn("ribbon_specs = (", self.visual)
        self.assertIn("particle_specs = (", self.visual)

    def test_ribbons_use_independent_motion_rates(self):
        self.assertIn("phase_speed = 0.37 + index * 0.117", self.visual)
        self.assertIn("speed = 0.43 + index * 0.061", self.visual)
        self.assertIn("frequency = 0.58 + index * 0.17", self.visual)

    def test_shield_is_small_and_leaves_room_for_action_column(self):
        self.assertIn("cx = width * 0.78", self.visual)
        self.assertIn("scale = 0.88", self.visual)
        self.assertIn("self.setMinimumSize(1, 1)", self.visual)
        self.assertIn("self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)", self.visual)

    def test_particle_wrap_fades_to_avoid_a_bright_jump(self):
        self.assertIn("fade = max(0.0, min(1.0, t / 0.085, (1.0 - t) / 0.105))", self.visual)
        self.assertIn("int(228 * fade)", self.visual)

    def test_overlay_spans_full_hero_and_is_behind_content(self):
        self.assertIn("self.dns_connection_visual = ConnectionStatusVisual(hero)", self.source)
        self.assertIn("hero.installEventFilter(self.dns_connection_visual)", self.source)
        self.assertIn("hero_layout.addStretch(1)", self.source)
        self.assertIn("self.dns_connection_visual.lower()", self.source)
        self.assertIn("rect = watched.rect().adjusted(2, 2, -2, -2)", self.visual)
        self.assertNotIn("hero_layout.addWidget(self.dns_connection_visual", self.source)

    def test_stream_fades_strongly_under_left_side_text(self):
        self.assertIn("def faded_stream_gradient(peak_alpha: int", self.visual)
        self.assertIn("(0.08, 0)", self.visual)
        self.assertIn("(0.17, max(1, int(peak_alpha * 0.018)))", self.visual)
        self.assertIn("(0.38, max(3, int(peak_alpha * 0.075)))", self.visual)
        self.assertIn("core_gradient.setColorAt(0.10", self.visual)
        self.assertIn("core_gradient.setColorAt(0.22", self.visual)

    def test_animation_workload_is_bounded_for_responsiveness(self):
        self.assertIn("self._timer.setTimerType(Qt.TimerType.CoarseTimer)", self.visual)
        self.assertIn("self._timer.setInterval(40)", self.visual)
        self.assertIn("count = max(12, min(24, int(span / 32.0)))", self.visual)
        self.assertIn("(-29.0, 6.0, 15.0)", self.visual)
        self.assertIn("(28.0, 5.2, 11.0)", self.visual)
        self.assertIn("offsets = (-40.0, -33.0, -25.0, -18.0, -10.0, -3.0, 5.0, 13.0, 21.0, 29.0, 36.0)", self.visual)
        self.assertIn("count = max(12, min(24, int(span / 32.0)))", self.visual)

    def test_stream_keeps_four_ribbons_and_eleven_filaments(self):
        import ast

        tree = ast.parse(self.visual)
        values = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in {"ribbon_specs", "offsets", "particle_specs"}:
                    values[name] = ast.literal_eval(node.value)
        self.assertEqual(len(values["ribbon_specs"]), 4)
        self.assertEqual(len(values["offsets"]), 11)
        self.assertEqual(tuple(item[0] for item in values["particle_specs"]), (1, 3, 5, 7, 9))
        self.assertIn("5.5 if index in {1, 4, 7, 9} else 3.5", self.visual)
        self.assertIn("path = strand_paths[index]", self.visual)

    def test_overlay_stays_click_through_and_resizes_with_hero(self):
        self.assertIn("Qt.WidgetAttribute.WA_TransparentForMouseEvents", self.visual)
        self.assertIn("def eventFilter(self, watched: Any, event: QEvent) -> bool:", self.visual)
        self.assertIn("event.type() == QEvent.Type.Resize", self.visual)


if __name__ == "__main__":
    unittest.main()
