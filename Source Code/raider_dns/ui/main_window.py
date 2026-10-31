"""Modern PySide6 dashboard for Raider DNS."""
from __future__ import annotations

import csv
import ctypes
import ipaddress
import json
import platform
import re
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from PySide6.QtCore import (
    QEvent, Qt, QObject, QThreadPool, QSize, QMimeData, QPoint, QFileInfo, QTimer,
    QPropertyAnimation, QEasingCurve, QPointF, QRectF,
)
from PySide6.QtGui import QAction, QBrush, QColor, QCursor, QDrag, QGuiApplication, QIcon, QPainter, QPainterPath, QPen, QRadialGradient, QLinearGradient, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QScrollArea, QSizePolicy, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QFormLayout, QListWidget,
    QListWidgetItem, QFileIconProvider, QRadioButton, QButtonGroup, QMenu, QSystemTrayIcon,
    QGraphicsOpacityEffect, QSpinBox,
)

from raider_dns import __version__
from raider_dns.models import DNSProvider, PROVIDERS
from raider_dns.services.dns_probe import DNS_QUERY_TYPES, benchmark_provider_metrics, build_dns_query, probe_doh, probe_dot, probe_icmp, probe_provider, probe_tcp53, probe_udp, rank_benchmark_results
from raider_dns.services.dns_leak_test import run_external_dns_leak_test
from raider_dns.services.dns_system import WindowsDNSService, DNSOperationResult
from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController, EngineResult
from raider_dns.services.traffic_tunnel import SingBoxTunnelController, TunnelResult
from raider_dns.services.network_tools import flush_dns_cache, get_network_info, repair_network
from raider_dns.services.secure_dns import BrowserSecureDnsController, SecureDnsError
from raider_dns.storage import ActivityLogStore, BackgroundActivityLogger, ConfigStore, default_settings
from raider_dns.services.provider_cache import ProviderMetadataCache
from raider_dns.services.network_monitor import build_network_signature, classify_network_transition, describe_network_changes
from raider_dns.services.timeouts import BENCHMARK_PROBE_TIMEOUT_SECONDS, BENCHMARK_ROUNDS, MAX_CONCURRENT_NETWORK_TASKS
from raider_dns.services.health_monitor import DNSHealthStateTracker
from raider_dns.services.connectivity_diagnostics import run_connectivity_checks, suggest_repairs
from raider_dns.ui.theme import stylesheet
from raider_dns.workers import UiDispatcher, Worker


class Panel(QFrame):
    def __init__(self, parent: QWidget | None = None, hero: bool = False) -> None:
        super().__init__(parent)
        self.setProperty("panel", "hero" if hero else "true")
        self.setFrameShape(QFrame.Shape.StyledPanel)


class ConnectionStatusVisual(QWidget):
    """A full-hero plasma stream that fades beneath the heading into a DNS shield.

    This transparent child covers the entire DNS Connection hero card, is kept
    behind interactive controls, and uses low-alpha ribbons on the left to avoid
    obscuring text. Motion uses continuous phase values (not a wrapped master phase), while
    individual strands have different frequencies and velocities. This avoids
    the synchronized wave reset that made the previous version look like a loop.
    A success shield confirms the Windows configuration operation only; it does
    not independently verify that the selected resolver is reachable.
    """

    _STATE_COLORS = {
        "idle": QColor("#25c9df"),
        "connecting": QColor("#2ce9df"),
        "success": QColor("#39e89a"),
        "warning": QColor("#ffbd5c"),
        "failure": QColor("#ff5d78"),
    }
    _PLASMA_BASE = QColor("#24cfe7")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        # This is a full-card transparent overlay, not a widget inside the HBox.
        # It paints under the hero copy and action buttons so the stream can span
        # the entire DNS CONNECTION section without stealing clicks or focus.
        self.setMinimumSize(1, 1)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAutoFillBackground(False)
        self.setAccessibleName("DNS configuration visual status")
        self._state = "idle"
        self._phase = 0.0  # intentionally continuous; do not modulo-wrap this value
        self._completion = 1.0
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._timer.setInterval(40)  # 25 FPS; lower paint cost while keeping motion fluid
        self._timer.timeout.connect(self._advance_animation)
        self.setToolTip(
            "Animated DNS status. A green shield means Windows reported that the "
            "configuration operation succeeded; resolver reachability is not proven by this effect."
        )

    def sizeHint(self) -> QSize:
        return QSize(600, 140)

    def minimumSizeHint(self) -> QSize:
        return QSize(1, 1)

    def eventFilter(self, watched: Any, event: QEvent) -> bool:
        # Keep the painter locked to the complete hero card as it resizes. A
        # two-pixel inset keeps the animated glow off the rounded card border.
        if watched is self.parentWidget() and event.type() == QEvent.Type.Resize:
            rect = watched.rect().adjusted(2, 2, -2, -2)
            self.setGeometry(rect)
        return super().eventFilter(watched, event)

    @property
    def state(self) -> str:
        return self._state

    def set_state(self, state: str) -> None:
        if state not in self._STATE_COLORS:
            state = "idle"
        changed = state != self._state
        self._state = state
        if changed and state in {"success", "failure"}:
            self._completion = 0.0
        descriptions = {
            "idle": "DNS visual is ready. The stream is decorative and does not test DNS reachability.",
            "connecting": "Applying DNS settings. The plasma ribbons accelerate toward the shield.",
            "success": "DNS settings and DNS/HTTPS connectivity were independently verified after the operation.",
            "warning": "The DNS settings may have been restored or configured, but DNS/HTTPS connectivity could not be independently verified. Check the status details.",
            "failure": "The DNS configuration operation failed. The shield is red; review the displayed error details and rollback status.",
        }
        self.setToolTip(descriptions[state])
        self.setAccessibleDescription(descriptions[state])
        if self.isVisible() and not self._timer.isActive():
            self._timer.start()
        self.update()

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        if not self._timer.isActive():
            self._timer.start()

    def hideEvent(self, event: Any) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def _advance_animation(self) -> None:
        # Different state speeds make the effect energetic during a change and
        # restrained after it settles. The phase never jumps at an arbitrary loop seam.
        speed = {
            "idle": 0.0038,
            "connecting": 0.0108,
            "success": 0.0040,
            "warning": 0.0036,
            "failure": 0.0034,
        }[self._state]
        self._phase += speed
        if self._completion < 1.0:
            self._completion = min(1.0, self._completion + 0.025)
        self.update()

    @staticmethod
    def _alpha(color: QColor, value: int) -> QColor:
        result = QColor(color)
        result.setAlpha(max(0, min(255, int(value))))
        return result

    @staticmethod
    def _append_smooth(path: QPainterPath, points: list[QPointF]) -> None:
        """Append a Catmull-Rom-like cubic curve through evenly sampled points."""
        if len(points) < 2:
            return
        for i in range(len(points) - 1):
            p0 = points[i]
            p1 = points[i + 1]
            before = points[max(0, i - 1)]
            after = points[min(len(points) - 1, i + 2)]
            # Vector tangents work for both forward and reverse point order.
            c1 = QPointF(
                p0.x() + (p1.x() - before.x()) / 6.0,
                p0.y() + (p1.y() - before.y()) / 6.0,
            )
            c2 = QPointF(
                p1.x() - (after.x() - p0.x()) / 6.0,
                p1.y() - (after.y() - p0.y()) / 6.0,
            )
            path.cubicTo(c1, c2, p1)

    @staticmethod
    def _shield_path(cx: float, cy: float, scale: float = 0.88) -> QPainterPath:
        # Smaller shield silhouette leaves more negative space and feels closer
        # to the reference design than a large badge surrounded by oversized rings.
        path = QPainterPath()
        path.moveTo(cx, cy - 36 * scale)
        path.cubicTo(cx + 10 * scale, cy - 29 * scale, cx + 20 * scale, cy - 25 * scale, cx + 29 * scale, cy - 22 * scale)
        path.cubicTo(cx + 28 * scale, cy - 7 * scale, cx + 28 * scale, cy + 9 * scale, cx + 19 * scale, cy + 22 * scale)
        path.cubicTo(cx + 13 * scale, cy + 30 * scale, cx + 5 * scale, cy + 35 * scale, cx, cy + 38 * scale)
        path.cubicTo(cx - 5 * scale, cy + 35 * scale, cx - 13 * scale, cy + 30 * scale, cx - 19 * scale, cy + 22 * scale)
        path.cubicTo(cx - 28 * scale, cy + 9 * scale, cx - 28 * scale, cy - 7 * scale, cx - 29 * scale, cy - 22 * scale)
        path.cubicTo(cx - 20 * scale, cy - 25 * scale, cx - 10 * scale, cy - 29 * scale, cx, cy - 36 * scale)
        path.closeSubpath()
        return path

    def _strand_path(self, end_x: float, cy: float, offset: float, index: int) -> QPainterPath:
        """A fine filament with independent phase/speed, tapered into the shield."""
        import math

        start_x = -18.0
        span = max(1.0, end_x - start_x)
        count = max(12, min(24, int(span / 32.0)))
        points: list[QPointF] = []
        phase = self._phase * math.tau
        speed = 0.43 + index * 0.061
        frequency = 1.05 + (index % 5) * 0.19
        phase_offset = index * 1.713
        amplitude = 5.0 + (index % 4) * 2.2
        for j in range(count + 1):
            t = j / count
            x = start_x + span * t
            converge = (1.0 - t) ** 1.02
            angle = math.tau * (frequency * t - speed * self._phase) + phase_offset
            fine_angle = math.tau * ((frequency * 1.71) * t - (speed * 0.73) * self._phase) + index * 0.81
            # Gentle large-scale sway plus a finer independent ripple. Both taper
            # to the same endpoint so all strands physically meet the shield.
            sway = math.sin(angle) * amplitude * (1.0 - t) ** 0.40
            fine = math.sin(fine_angle) * 2.0 * (1.0 - t) ** 0.52
            y = cy + offset * (converge ** 0.82) + sway + fine
            points.append(QPointF(x, y))
        path = QPainterPath(points[0])
        self._append_smooth(path, points)
        return path

    def _ribbon_path(
        self, end_x: float, cy: float, offset: float, index: int,
        half_width: float, sway: float,
    ) -> tuple[QPainterPath, QPainterPath]:
        """Return a filled, tapered ribbon and its centerline for a soft halo."""
        import math

        start_x = -20.0
        span = max(1.0, end_x - start_x)
        count = max(12, min(24, int(span / 32.0)))
        top: list[QPointF] = []
        bottom: list[QPointF] = []
        center: list[QPointF] = []
        phase_speed = 0.37 + index * 0.117
        frequency = 0.58 + index * 0.17
        base_phase = index * 1.91
        for j in range(count + 1):
            t = j / count
            x = start_x + span * t
            converge = (1.0 - t)
            broad_angle = math.tau * (frequency * t - phase_speed * self._phase) + base_phase
            second_angle = math.tau * ((frequency * 1.47 + 0.21) * t - phase_speed * 0.71 * self._phase) + base_phase * 0.67
            envelope = math.sin(math.pi * t) ** 0.72 if 0.0 < t < 1.0 else 0.0
            flow = math.sin(broad_angle) * sway * envelope * (0.42 + 0.58 * converge)
            flow += math.sin(second_angle) * (sway * 0.19) * envelope
            y = cy + offset * (converge ** 0.98) + flow
            taper = 0.24 + half_width * (converge ** 0.74) * (0.78 + 0.22 * math.sin(math.pi * t))
            center.append(QPointF(x, y))
            top.append(QPointF(x, y - taper))
            bottom.append(QPointF(x, y + taper))

        ribbon = QPainterPath(top[0])
        self._append_smooth(ribbon, top)
        ribbon.lineTo(bottom[-1])
        self._append_smooth(ribbon, list(reversed(bottom)))
        ribbon.closeSubpath()
        center_path = QPainterPath(center[0])
        self._append_smooth(center_path, center)
        return ribbon, center_path

    def paintEvent(self, _event: Any) -> None:
        import math

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        width = float(self.width())
        height = float(self.height())
        # The visual now overlays the complete hero panel. Leave the shield just
        # left of the action column while allowing the stream to extend behind
        # the heading and selectors; its left half is deliberately much fainter.
        cx = width * 0.78
        cy = height * 0.50
        scale = 0.88
        state_color = QColor(self._STATE_COLORS[self._state])
        plasma_color = QColor("#ff647c") if self._state == "failure" else QColor(self._PLASMA_BASE)
        if self._state == "connecting":
            plasma_color = QColor("#35eee4")
        shield_left = cx - 29.0 * scale - 1.5

        painter.setPen(Qt.PenStyle.NoPen)
        # A long, low-opacity bloom gives the stream a shared atmosphere without
        # filling the whole hero with a foggy blob.
        aura = QRadialGradient(QPointF(cx - width * 0.18, cy), max(100.0, width * 0.38))
        aura.setColorAt(0.0, self._alpha(plasma_color, 13 if self._state != "connecting" else 22))
        aura.setColorAt(0.55, self._alpha(plasma_color, 7))
        aura.setColorAt(1.0, self._alpha(plasma_color, 0))
        painter.setBrush(QBrush(aura))
        painter.drawEllipse(QRectF(-20.0, cy - height * 0.60, width + 40.0, height * 1.20))

        # Build reusable horizontal alpha ramps. The leftmost 35-40% stays very
        # faint beneath the hero copy, then the stream gradually gains energy as
        # it travels toward the shield. The overlay is behind all interactive UI.
        def faded_stream_gradient(peak_alpha: int, final_alpha: int | None = None) -> QLinearGradient:
            end_alpha = peak_alpha if final_alpha is None else final_alpha
            gradient = QLinearGradient(-20.0, cy, max(1.0, shield_left), cy)
            stops = (
                (0.00, 0), (0.08, 0), (0.17, max(1, int(peak_alpha * 0.018))),
                (0.28, max(2, int(peak_alpha * 0.035))),
                (0.38, max(3, int(peak_alpha * 0.075))),
                (0.48, max(5, int(peak_alpha * 0.15))),
                (0.58, max(8, int(peak_alpha * 0.29))),
                (0.69, max(12, int(peak_alpha * 0.50))),
                (0.80, max(18, int(peak_alpha * 0.74))),
                (0.92, peak_alpha), (1.00, end_alpha),
            )
            for position, alpha in stops:
                gradient.setColorAt(position, self._alpha(plasma_color, alpha))
            return gradient

        halo_gradient = faded_stream_gradient(26 if self._state == "connecting" else 16)
        filament_halo_gradient = faded_stream_gradient(38 if self._state == "connecting" else 24)

        # Broad translucent ribbons establish the flowing plasma-sheet silhouette.
        # Different phase speeds prevent them from rocking in a synchronized loop.
        ribbon_specs = (
            (-29.0, 6.0, 15.0),
            (-12.0, 7.2, 12.5),
            (9.0, 6.6, 15.5),
            (28.0, 5.2, 11.0),
        )
        ribbon_alphas = (66, 82, 72, 54)
        for index, (offset, thickness, sway) in enumerate(ribbon_specs):
            ribbon, center_path = self._ribbon_path(
                shield_left, cy, offset, index, thickness, sway
            )
            # The glows use the same left-fading profile as the filled ribbons,
            # avoiding a bright wash behind "Your network, your control.".
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QBrush(halo_gradient), thickness * 3.8,
                                Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(center_path)
            painter.setPen(QPen(QBrush(filament_halo_gradient), thickness * 1.7,
                                Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(center_path)

            alpha = ribbon_alphas[index] + (18 if self._state == "connecting" else 0)
            gradient = faded_stream_gradient(alpha, min(180, alpha + 30))
            gradient.setColorAt(0.72, self._alpha(plasma_color.lighter(125), max(1, int(alpha * 0.68))))
            gradient.setColorAt(0.94, self._alpha(plasma_color.lighter(145), min(180, alpha + 30)))
            gradient.setColorAt(1.0, self._alpha(QColor("#e9ffff"), 68))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(gradient))
            painter.drawPath(ribbon)

        # Fine filaments sit above the ribbons. Their phase, frequency, amplitude
        # and speed differ, creating organic interference instead of a repeated wave.
        offsets = (-40.0, -33.0, -25.0, -18.0, -10.0, -3.0, 5.0, 13.0, 21.0, 29.0, 36.0)
        strand_paths: list[QPainterPath] = []
        for index, offset in enumerate(offsets):
            path = self._strand_path(shield_left, cy, offset, index)
            strand_paths.append(path)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QBrush(filament_halo_gradient),
                                5.5 if index in {1, 4, 7, 9} else 3.5,
                                Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(path)

            # Core filament fades almost completely under the text, then blooms
            # in the open center and converges into the shield at full brightness.
            core_gradient = QLinearGradient(-16.0, cy, max(1.0, shield_left), cy)
            core_gradient.setColorAt(0.0, self._alpha(QColor("#d8ffff"), 0))
            core_gradient.setColorAt(0.10, self._alpha(QColor("#d8ffff"), 0))
            core_gradient.setColorAt(0.22, self._alpha(QColor("#bafcff"), 2))
            core_gradient.setColorAt(0.34, self._alpha(QColor("#bafcff"), 5))
            core_gradient.setColorAt(0.46, self._alpha(QColor("#bafcff"), 14))
            core_gradient.setColorAt(0.60, self._alpha(QColor("#c8ffff"), 36))
            core_gradient.setColorAt(0.76, self._alpha(QColor("#c8ffff"), 76 if index % 3 else 98))
            core_gradient.setColorAt(0.93, self._alpha(QColor("#f0ffff"), 150))
            core_gradient.setColorAt(1.0, self._alpha(QColor("#ffffff"), 185))
            painter.setPen(QPen(QBrush(core_gradient), 0.75 if index % 3 else 1.15,
                                Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                                Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(path)

        # Moving luminous nodes use distinct velocities and phases. They travel
        # into the shield at different times, not as a synchronized row of dots.
        particle_specs = ((1, 0.12, 0.08), (3, 0.17, 0.46), (5, 0.10, 0.77),
                          (7, 0.145, 0.29), (9, 0.195, 0.61))
        for index, velocity, start in particle_specs:
            path = strand_paths[index]
            t = (self._phase * velocity * (2.8 if self._state == "connecting" else 1.0) + start) % 1.0
            point = path.pointAtPercent(t)
            before = path.pointAtPercent(max(0.0, t - (0.035 if self._state != "connecting" else 0.055)))
            # Fade each node in at the left edge and fade it into the shield at
            # the right edge; wrapping no longer creates a bright visible jump.
            fade = max(0.0, min(1.0, t / 0.085, (1.0 - t) / 0.105))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(self._alpha(plasma_color.lighter(150), int(93 * fade)), 2.0,
                                Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawLine(before, point)
            spark_radius = 7.5 if self._state != "connecting" else 10.0
            spark = QRadialGradient(point, spark_radius)
            spark.setColorAt(0.0, self._alpha(QColor("#ffffff"), int(228 * fade)))
            spark.setColorAt(0.26, self._alpha(plasma_color.lighter(150), int(172 * fade)))
            spark.setColorAt(1.0, self._alpha(plasma_color, 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(spark))
            painter.drawEllipse(QRectF(point.x() - spark_radius, point.y() - spark_radius,
                                       spark_radius * 2, spark_radius * 2))
            painter.setBrush(self._alpha(QColor("#f2ffff"), int(235 * fade)))
            painter.drawEllipse(QRectF(point.x() - 1.35, point.y() - 1.35, 2.7, 2.7))

        # Smaller, independent shield rings. Their phases differ slightly from
        # the stream and from one another, avoiding the old in-sync circular pulse.
        ring_pulses = (
            (34.0 + 1.8 * math.sin(self._phase * math.tau * 0.43 + 0.4), 26, 0.9),
            (29.0 + 1.3 * math.sin(self._phase * math.tau * 0.61 + 2.1), 64, 1.2),
            (24.0 + 0.9 * math.sin(self._phase * math.tau * 0.77 + 4.0), 42, 0.9),
        )
        for radius, alpha, pen_width in ring_pulses:
            painter.setPen(QPen(self._alpha(state_color, min(128, alpha + (25 if self._state == "connecting" else 0))),
                                pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(cx - radius, cy - radius, radius * 2, radius * 2))

        # One expanding completion ripple, then a stable shield state.
        if self._completion < 1.0 and self._state in {"success", "failure"}:
            progress = self._completion
            radius = 30.0 + 31.0 * progress
            alpha = int(190 * (1.0 - progress))
            painter.setPen(QPen(self._alpha(state_color, alpha), 2.0 * (1.0 - progress) + 0.45))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(cx - radius, cy - radius, radius * 2, radius * 2))

        # Shield glow, body and inset border. The slightly smaller silhouette keeps
        # the energy stream dominant rather than making the shield oversized.
        shield = self._shield_path(cx, cy, scale)
        painter.setPen(QPen(self._alpha(state_color, 39), 8.5, Qt.PenStyle.SolidLine,
                            Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(shield)

        shield_fill = QLinearGradient(cx - 25.0, cy - 31.0, cx + 24.0, cy + 31.0)
        shield_fill.setColorAt(0.0, self._alpha(state_color.lighter(150), 200))
        shield_fill.setColorAt(0.42, self._alpha(state_color, 155))
        shield_fill.setColorAt(1.0, self._alpha(state_color.darker(185), 235))
        painter.setBrush(QBrush(shield_fill))
        painter.setPen(QPen(self._alpha(state_color.lighter(135), 250), 1.8,
                            Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(shield)

        inset = self._shield_path(cx, cy + 0.3, scale * 0.77)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(self._alpha(QColor("#eaffff"), 102), 0.9))
        painter.drawPath(inset)

        # State glyph: tiny idle dot, lightning while applying, check on success,
        # red cross on failure. It remains visible even after the pulse settles.
        glyph_color = QColor("#f7ffff")
        glyph_pen = QPen(glyph_color, 3.2, Qt.PenStyle.SolidLine,
                         Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        painter.setPen(glyph_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        if self._state == "success":
            painter.drawLine(QPointF(cx - 10.0, cy + 0.3), QPointF(cx - 2.5, cy + 7.0))
            painter.drawLine(QPointF(cx - 2.5, cy + 7.0), QPointF(cx + 10.5, cy - 8.5))
        elif self._state == "failure":
            painter.drawLine(QPointF(cx - 8.0, cy - 8.0), QPointF(cx + 8.0, cy + 8.0))
            painter.drawLine(QPointF(cx + 8.0, cy - 8.0), QPointF(cx - 8.0, cy + 8.0))
        elif self._state == "connecting":
            bolt = QPainterPath()
            bolt.moveTo(cx + 2.5, cy - 14.0)
            bolt.lineTo(cx - 6.5, cy + 0.5)
            bolt.lineTo(cx - 0.7, cy + 0.5)
            bolt.lineTo(cx - 3.0, cy + 13.0)
            bolt.lineTo(cx + 7.5, cy - 3.5)
            bolt.lineTo(cx + 1.0, cy - 3.5)
            bolt.closeSubpath()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glyph_color)
            painter.drawPath(bolt)
        else:
            painter.setPen(QPen(glyph_color, 2.0))
            painter.drawEllipse(QPointF(cx, cy), 3.8, 3.8)
        painter.end()


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 4)
        layout.setSpacing(5)
        title_label = QLabel(title)
        title_label.setObjectName("Heading")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("Muted")
        subtitle_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)




class ProviderDragHandle(QLabel):
    """Small explicit drag handle for reordering provider cards."""
    MIME_TYPE = "application/x-raiderdns-provider-id"

    def __init__(self, provider_id: str, parent: QWidget | None = None) -> None:
        super().__init__("⠿", parent)
        self.provider_id = provider_id
        self._drag_start: QPoint | None = None
        self.setToolTip("Drag to rearrange DNS providers")
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(24, 34)
        self.setStyleSheet("font-size:20px;color:#6f849e;")

    def mousePressEvent(self, event: Any) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: Any) -> None:
        if self._drag_start is None or not (event.buttons() & Qt.MouseButton.LeftButton):
            return
        if (event.position().toPoint() - self._drag_start).manhattanLength() < QApplication.startDragDistance():
            return
        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(self.MIME_TYPE, self.provider_id.encode("utf-8"))
        drag.setMimeData(mime)
        self.setCursor(Qt.CursorShape.ClosedHandCursor)
        drag.exec(Qt.DropAction.MoveAction)
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        self._drag_start = None


class ProviderCard(Panel):
    """Provider card accepts drops from the drag handle of another card."""
    def __init__(self, provider_id: str, owner: "MainWindow") -> None:
        super().__init__()
        self.provider_id = provider_id
        self.owner = owner
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: Any) -> None:
        if event.mimeData().hasFormat(ProviderDragHandle.MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event: Any) -> None:
        if event.mimeData().hasFormat(ProviderDragHandle.MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: Any) -> None:
        try:
            source_id = bytes(event.mimeData().data(ProviderDragHandle.MIME_TYPE)).decode("utf-8")
        except (UnicodeDecodeError, TypeError):
            event.ignore()
            return
        if source_id and source_id != self.provider_id:
            self.owner._move_provider_before(source_id, self.provider_id)
            event.acceptProposedAction()
        else:
            event.ignore()


def _valid_web_url(value: str, schemes: set[str]) -> bool:
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme.casefold() in schemes and bool(parsed.hostname)
    except (ValueError, TypeError):
        return False


def make_label(text: str, object_name: str | None = None) -> QLabel:
    label = QLabel(text)
    # Prefer plain text for any value that might include external/system data.
    label.setTextFormat(Qt.TextFormat.PlainText)
    if object_name:
        label.setObjectName(object_name)
    return label


def make_panel_layout(panel: QFrame, margins: tuple[int, int, int, int] = (18, 18, 18, 18), spacing: int = 12) -> QVBoxLayout:
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(*margins)
    layout.setSpacing(spacing)
    return layout


def scroll_page(content: QWidget) -> QScrollArea:
    """Wrap content in a theme-aware scroll area with a stable page surface."""
    scroll = QScrollArea()
    scroll.setObjectName("PageScrollArea")
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    content.setObjectName("PageContent")
    content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
    scroll.setWidget(content)
    return scroll


class DelayedToolTipController(QObject):
    """Application-owned delayed tooltip popups with a short fade-in."""

    _TIP_PROPERTY = "_raider_dns_delayed_tooltip"

    def __init__(self, owner: QWidget, delay_ms: int = 750) -> None:
        super().__init__(owner)
        self.owner = owner
        self.delay_ms = max(300, min(1500, int(delay_ms)))
        self._target: QWidget | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(self.delay_ms)
        self._timer.timeout.connect(self._show_target)
        self.popup = QFrame(owner, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowDoesNotAcceptFocus)
        self.popup.setObjectName("RaiderSoftTooltip")
        self.popup.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.popup.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.popup.setMaximumWidth(380)
        self.popup_layout = QVBoxLayout(self.popup)
        self.popup_layout.setContentsMargins(12, 8, 12, 8)
        self.popup_layout.setSpacing(0)
        self.popup_label = QLabel(self.popup)
        self.popup_label.setWordWrap(True)
        self.popup_label.setMaximumWidth(354)
        self.popup_layout.addWidget(self.popup_label)
        self._effect = QGraphicsOpacityEffect(self.popup)
        self.popup.setGraphicsEffect(self._effect)
        self._fade: QPropertyAnimation | None = None
        self._style_popup()
        self.popup.hide()

    def set_delay(self, delay_ms: int) -> None:
        self.delay_ms = max(300, min(1500, int(delay_ms)))
        self._timer.setInterval(self.delay_ms)

    def _style_popup(self) -> None:
        host = self.owner.centralWidget() if hasattr(self.owner, "centralWidget") else None
        dark = host.property("raiderDarkTheme") if host is not None else True
        if dark is None:
            dark = True
        bg, fg, border = ("#172536", "#f2f7ff", "#40556e") if dark else ("#ffffff", "#1b2a41", "#cbd7e5")
        self.popup.setStyleSheet(
            f"QFrame#RaiderSoftTooltip{{background:{bg};color:{fg};border:1px solid {border};border-radius:9px;}}"
            f"QLabel{{background:transparent;color:{fg};font-size:12px;padding:0;}}"
        )

    @staticmethod
    def _auto_description(widget: QWidget) -> str:
        if isinstance(widget, QPushButton):
            text = widget.text().strip().replace("→", "").strip()
            if not text:
                return "Activate this control."
            lower = text.casefold()
            exact = {
                "apply selected dns": "Apply the selected DNS provider to the chosen network adapter.",
                "restore automatic dns": "Restore DNS server assignment to automatic DHCP configuration.",
                "flush dns cache": "Clear the local Windows DNS resolver cache.",
                "restart as administrator": "Restart Raider DNS with Windows administrator permissions.",
                "refresh ip information": "Refresh local network addresses and, when requested, public IP information.",
                "run dns benchmark": "Benchmark configured DNS providers using fresh network measurements.",
                "run external test": "Send one-time test queries to an external DNS leak testing service.",
                "run all tests": "Run the selected resolver reachability tests.",
                "export csv": "Export the visible activity or benchmark information to a CSV file.",
                "clear history": "Clear the locally stored activity history after confirmation.",
            }
            if lower in exact:
                return exact[lower]
            if lower == "select":
                return "Select this DNS provider for the next apply operation."
            if lower in {"create dns provider", "＋  create dns provider"}:
                return "Add a custom DNS resolver to the provider catalogue."
            return f"{text.rstrip('.')} — open or run this action."
        return ""

    def register_tree(self, root: QWidget) -> None:
        widgets = [root, *root.findChildren(QWidget)]
        for widget in widgets:
            if widget is self.popup or widget.property("_raider_dns_tip_filter_installed"):
                continue
            existing = widget.toolTip().strip()
            tip = existing or self._auto_description(widget)
            if tip:
                widget.setProperty(self._TIP_PROPERTY, tip)
                widget.setToolTip("")  # disable Qt's immediate native tooltip; controller owns timing
            widget.setProperty("_raider_dns_tip_filter_installed", True)
            widget.installEventFilter(self)

    def eventFilter(self, watched: Any, event: QEvent) -> bool:
        if isinstance(watched, QWidget) and watched is not self.popup:
            event_type = event.type()
            if event_type == QEvent.Type.Enter:
                live_text = watched.toolTip().strip()
                if live_text:
                    watched.setProperty(self._TIP_PROPERTY, live_text)
                    watched.setToolTip("")
                text = str(watched.property(self._TIP_PROPERTY) or "").strip()
                if text:
                    self._target = watched
                    self._timer.start(self.delay_ms)
            elif event_type in (QEvent.Type.Leave, QEvent.Type.MouseButtonPress, QEvent.Type.Hide):
                if self._target is watched:
                    self._timer.stop()
                    self._target = None
                    self.popup.hide()
        return super().eventFilter(watched, event)

    def _show_target(self) -> None:
        target = self._target
        if target is None or not target.isVisible() or not self.owner.isVisible():
            return
        text = str(target.property(self._TIP_PROPERTY) or "").strip()
        if not text:
            return
        self._style_popup()
        self.popup_label.setText(text)
        self.popup.adjustSize()
        pos = target.mapToGlobal(QPoint(0, target.height() + 7))
        screen = QGuiApplication.screenAt(pos) or QGuiApplication.primaryScreen()
        if screen is not None:
            bounds = screen.availableGeometry()
            x = max(bounds.left() + 8, min(pos.x(), bounds.right() - self.popup.width() - 8))
            y = pos.y()
            if y + self.popup.height() > bounds.bottom() - 8:
                y = target.mapToGlobal(QPoint(0, -self.popup.height() - 7)).y()
            y = max(bounds.top() + 8, min(y, bounds.bottom() - self.popup.height() - 8))
            pos = QPoint(x, y)
        self.popup.move(pos)
        self.popup.show()
        self.popup.raise_()
        if self._fade is not None:
            self._fade.stop()
            self._fade.deleteLater()
        self._effect.setOpacity(0.0)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self.popup)
        self._fade.setDuration(150)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade.start()


class AppNotificationToast(QFrame):
    """Non-modal in-app toast; notifications remain readable without blocking the UI."""

    _COLORS = {
        "info": ("#27bcd0", "#17333c"),
        "success": ("#40d99d", "#17392f"),
        "warning": ("#ffc66d", "#3d301d"),
        "error": ("#ff7186", "#42232d"),
    }

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("AppNotificationToast")
        self.setFixedWidth(380)
        self.setMinimumHeight(82)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._kind = "info"
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 11, 12, 11)
        layout.setSpacing(10)
        self.kind_icon = QLabel("i")
        self.kind_icon.setFixedSize(28, 28)
        self.kind_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.kind_icon.setStyleSheet("font-size:16px;font-weight:900;border-radius:14px;")
        layout.addWidget(self.kind_icon, 0, Qt.AlignmentFlag.AlignTop)
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(3)
        self.title_label = QLabel("Raider DNS")
        self.title_label.setStyleSheet("font-size:13px;font-weight:800;background:transparent;")
        self.message_label = QLabel("")
        self.message_label.setWordWrap(True)
        self.message_label.setStyleSheet("font-size:12px;background:transparent;")
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.message_label)
        layout.addLayout(text_layout, 1)
        self.close_button = QPushButton("×")
        self.close_button.setObjectName("IconButton")
        self.close_button.clicked.connect(self._fade_out)
        layout.addWidget(self.close_button, 0, Qt.AlignmentFlag.AlignTop)
        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)
        self._animation: QPropertyAnimation | None = None
        self._timeout = QTimer(self)
        self._timeout.setSingleShot(True)
        self._timeout.timeout.connect(self._fade_out)
        self.hide()

    def _apply_style(self) -> None:
        accent, bg = self._COLORS.get(self._kind, self._COLORS["info"])
        dark = bool(self.parentWidget().property("raiderDarkTheme")) if self.parentWidget() else True
        text = "#edf5ff" if dark else "#203249"
        border = accent
        self.setStyleSheet(
            f"QFrame#AppNotificationToast{{background:{bg if dark else '#ffffff'};border:1px solid {border};border-radius:12px;}}"
            f"QLabel{{color:{text};}}"
        )
        self.kind_icon.setStyleSheet(f"background:{accent};color:#07151c;font-size:16px;font-weight:900;border-radius:14px;")

    def present(self, title: str, message: str, kind: str = "info", duration_ms: int = 4600) -> None:
        self._kind = kind if kind in self._COLORS else "info"
        symbols = {"info": "i", "success": "✓", "warning": "!", "error": "×"}
        self.kind_icon.setText(symbols[self._kind])
        self.title_label.setText(title[:100])
        self.message_label.setText(message[:320])
        self._apply_style()
        self.adjustSize()
        self.setFixedWidth(380)
        self._reposition()
        self._timeout.stop()
        if self._animation is not None:
            self._animation.stop()
            self._animation.deleteLater()
        self._opacity.setOpacity(0.0)
        self.show()
        self.raise_()
        self._animation = QPropertyAnimation(self._opacity, b"opacity", self)
        self._animation.setDuration(190)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.start()
        self._timeout.start(max(1800, int(duration_ms)))

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        self.move(max(8, parent.width() - self.width() - 20), 18)

    def _fade_out(self) -> None:
        self._timeout.stop()
        if not self.isVisible():
            return
        if self._animation is not None:
            self._animation.stop()
            self._animation.deleteLater()
        self._animation = QPropertyAnimation(self._opacity, b"opacity", self)
        self._animation.setDuration(160)
        self._animation.setStartValue(self._opacity.opacity())
        self._animation.setEndValue(0.0)
        self._animation.setEasingCurve(QEasingCurve.Type.InCubic)
        self._animation.finished.connect(self.hide)
        self._animation.start()


class BenchmarkLatencyChart(QWidget):
    """Lightweight custom latency chart; no extra charting dependency is required."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._results: list[dict[str, Any]] = []
        self._theme = "dark"
        self.setMinimumHeight(170)
        self.setMaximumHeight(310)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def set_results(self, results: list[dict[str, Any]], theme: str = "dark") -> None:
        self._results = [dict(row) for row in results]
        self._theme = theme
        self.update()

    def paintEvent(self, event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        dark = self._theme != "light"
        text_color = QColor("#dce8f8" if dark else "#243850")
        muted_color = QColor("#94a8c1" if dark else "#64768a")
        bar_color = QColor("#28d2c1" if dark else "#078b80")
        track_color = QColor("#243247" if dark else "#e3eaf2")
        rect = self.rect().adjusted(8, 8, -8, -8)
        rows = [row for row in self._results if isinstance(row.get("query_median_ms"), (int, float)) and row.get("query_median_ms") is not None]
        rows.sort(key=lambda row: (float(row["query_median_ms"]), str(row.get("provider_name", "")).casefold()))
        rows = rows[:8]
        if not rows:
            painter.setPen(muted_color)
            painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), "Run a benchmark with DNS query latency enabled to display resolver timings.")
            painter.end()
            return
        label_width = min(155, max(95, int(rect.width() * 0.23)))
        value_width = 76
        chart_left = rect.left() + label_width
        chart_right = rect.right() - value_width
        chart_width = max(60, chart_right - chart_left)
        max_value = max(float(row["query_median_ms"]) for row in rows) or 1.0
        row_height = max(18, min(30, int(rect.height() / len(rows))))
        painter.setFont(QFont("Segoe UI", 9))
        for index, row in enumerate(rows):
            y = rect.top() + index * row_height
            if y + row_height > rect.bottom() + 1:
                break
            painter.setPen(text_color)
            name = str(row.get("provider_name", "Resolver"))
            painter.drawText(rect.left(), y, label_width - 9, row_height, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), name[:22])
            track = QRectF(chart_left, y + row_height * 0.26, chart_width, max(6, row_height * 0.48))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(track_color)
            painter.drawRoundedRect(track, 4, 4)
            ratio = max(0.025, min(1.0, float(row["query_median_ms"]) / max_value))
            bar = QRectF(track.left(), track.top(), max(3.0, track.width() * ratio), track.height())
            painter.setBrush(bar_color)
            painter.drawRoundedRect(bar, 4, 4)
            painter.setPen(muted_color)
            painter.drawText(chart_right + 8, y, value_width, row_height, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), f"{row['query_median_ms']} ms")
        painter.end()


class MainWindow(QMainWindow):
    NAV_ITEMS = [
        ("Dashboard", "▦", "dashboard"),
        ("Connections", "⌁", "connections"),
        ("DNS Providers", "◉", "providers"),
        ("DNS Security Center", "◇", "security"),
        ("Benchmark Lab", "⌁", "benchmark"),
        ("Profiles", "▤", "profiles"),
        ("Diagnostics", "⌘", "diagnostics"),
        ("Activity Log", "▤", "activity"),
        ("Settings", "⚙", "settings"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.store = ConfigStore()
        self.settings: dict[str, Any] = self.store.load()
        # Prefer the user's valid explicit engine path. If it is empty or stale,
        # discover the engine installed by the Raider DNS installer. DNSCrypt stays
        # opt-in; finding an executable never changes Windows DNS by itself.
        settings_changed = False
        configured_binary = str(self.settings.get("dnscrypt_proxy_path", "") or "").strip()
        configured_binary_path = Path(configured_binary) if configured_binary else None
        if configured_binary_path is None or not configured_binary_path.is_file():
            bundled_binary = DNSCryptProxyController.discover_bundled_binary()
            if bundled_binary is not None:
                self.settings["dnscrypt_proxy_path"] = str(bundled_binary)
                settings_changed = self.settings["dnscrypt_proxy_path"] != configured_binary
        # Generate the privacy-restricted config once for installations with an
        # available engine. Never overwrite an existing config or modify adapters.
        config_text = str(self.settings.get("dnscrypt_config_path", "") or "").strip()
        engine_text = str(self.settings.get("dnscrypt_proxy_path", "") or "").strip()
        if engine_text and Path(engine_text).is_file() and not config_text:
            try:
                self.settings["dnscrypt_config_path"] = str(DNSCryptProxyController.generate_config())
                settings_changed = True
            except (OSError, ValueError):
                # The user can regenerate the config from the Connections screen.
                pass
        if settings_changed:
            try:
                self.store.save(self.settings)
            except OSError:
                # Settings persistence problems must not prevent the app from opening.
                pass
        self.activity_store = ActivityLogStore(limit=int(self.settings.get("activity_log_limit", 1000)))
        self._activity_records = self.activity_store.load()
        self._activity_writer = None
        self.system_dns = WindowsDNSService()
        self.dnscrypt_controller = DNSCryptProxyController(Path(self.settings["dnscrypt_proxy_path"]) if self.settings.get("dnscrypt_proxy_path") else None, Path(self.settings["dnscrypt_config_path"]) if self.settings.get("dnscrypt_config_path") else None)
        self.singbox_controller = SingBoxTunnelController()
        self.thread_pool = QThreadPool(self)
        # Use an application-owned pool so unrelated Qt work cannot consume or
        # change Raider DNS worker capacity. Extra jobs queue instead of spawning
        # unbounded network/socket activity.
        self.thread_pool.setMaxThreadCount(MAX_CONCURRENT_NETWORK_TASKS)
        self.thread_pool.setExpiryTimeout(30_000)
        self._dispatcher = UiDispatcher(self)
        self._activity_writer = BackgroundActivityLogger(self.activity_store, on_error=self._queue_activity_log_error)
        self._provider_metadata_cache = ProviderMetadataCache()
        self._ui_animations: dict[str, QPropertyAnimation] = {}
        self._network_state_signature: tuple[Any, ...] | None = None
        self._suppress_next_dns_change_notification = False
        self._pending_post_apply_refresh = False
        self._system_state_refresh_in_flight = False
        self._dns_operation_in_flight = False
        self._doh_inventory_in_flight = False
        self._doh_inventory_last_refresh = 0.0
        self._shutdown_started = False
        self._close_tunnel_shutdown_pending = False
        self._close_tunnel_shutdown_complete = False
        self._close_timer_states: dict[str, bool] = {}
        self._network_change_timer = QTimer(self)
        poll_interval_ms = int(self.settings.get("network_poll_interval_seconds", 20)) * 1000
        self._network_change_timer.setInterval(max(10_000, min(60_000, poll_interval_ms)))
        self._network_change_timer.timeout.connect(self._poll_network_changes)
        self._health_timer = QTimer(self)
        self._health_timer.timeout.connect(self._run_health_check)
        self._singbox_monitor_timer = QTimer(self)
        self._singbox_monitor_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._singbox_monitor_timer.setInterval(2500)
        self._singbox_monitor_timer.timeout.connect(self._monitor_singbox_process)
        self._health_check_in_flight = False
        self._health_state_tracker = DNSHealthStateTracker()
        self._health_last_result: dict[str, Any] | None = None
        self._health_state_provider_id: str | None = None
        self._health_probe_provider_id: str | None = None
        self._health_generation = 0
        self._health_probe_generation = 0
        self._health_active_probe_generation: int | None = None
        self._activity_table_initialized = False
        self._activity_table_dirty = True
        self._activity_table_refresh_timer = QTimer(self)
        self._activity_table_refresh_timer.setSingleShot(True)
        self._activity_table_refresh_timer.setInterval(180)
        self._activity_table_refresh_timer.timeout.connect(self._refresh_activity_table)
        self._recent_activity_labels: list[QLabel] = []
        self._workers: set[Worker] = set()
        self._nav_buttons: dict[str, QPushButton] = {}
        self._activity: list[str] = [
            f"{row.get('timestamp', '')[11:19] or row.get('timestamp', '')}  {row.get('action', '')}"
            for row in reversed(self._activity_records[-5:])
        ]
        self._tray_icon: QSystemTrayIcon | None = None
        self._exit_requested = False
        self._minimized_to_tray = False
        self._adapter_dns: list[dict[str, Any]] = []
        self._adapters: list[str] = []
        self._probe_row_by_id: dict[str, int] = {}
        self._provider_cards: list[tuple[QWidget, DNSProvider]] = []
        self._favorite_controls: dict[str, QPushButton] = {}
        self._icon_provider = QFileIconProvider()

        self.setWindowTitle("Raider DNS")
        self.setMinimumSize(QSize(1050, 700))
        self.resize(int(self.settings.get("window_width", 1320)), int(self.settings.get("window_height", 860)))
        self.setStyleSheet(stylesheet(self.settings.get("theme", "dark")))
        self._build_shell()
        self._build_pages()
        self.centralWidget().setProperty("raiderDarkTheme", self.settings.get("theme", "dark") != "light")
        self._notification_toast = AppNotificationToast(self.centralWidget())
        self._tooltip_controller = DelayedToolTipController(self, int(self.settings.get("tooltip_delay_ms", 750)))
        self._tooltip_controller.register_tree(self)
        self._setup_tray()
        self._navigate("dashboard")
        self._update_provider_metrics()
        self._apply_saved_window_state()
        self._refresh_system_state()
        self._network_change_timer.start()
        self._configure_health_monitor(run_now=True)
        # Private addresses are read locally at startup; public IP lookup is user-triggered.
        self._refresh_network_info(include_public=False)
        self._log("Raider DNS started.")
        if self.singbox_controller.has_recovery_record:
            QTimer.singleShot(350, self._recover_previous_singbox_session)

    def _recover_previous_singbox_session(self) -> None:
        """Recover only a sing-box TUN process recorded by the previous app session."""
        if self._shutdown_started or not self.singbox_controller.has_recovery_record:
            return
        if hasattr(self, "singbox_status_label"):
            self.singbox_status_label.setText("Checking previous sing-box session and TUN cleanup…")
        self.statusBar().showMessage("Checking for an interrupted sing-box tunnel session…")
        self._run_background(
            lambda: self.singbox_controller.recover_previous_session(timeout=8.0),
            self._previous_singbox_recovery_finished,
            lambda error: self._previous_singbox_recovery_finished(
                TunnelResult(False, "Previous sing-box recovery check failed", error)
            ),
        )

    def _previous_singbox_recovery_finished(self, result: Any) -> None:
        if not isinstance(result, TunnelResult):
            result = TunnelResult(False, "Unexpected recovery result", str(result))
        if result.message == "No previous sing-box session requires recovery.":
            return
        self._log(f"Previous sing-box session recovery: {result.message}.", "INFO" if result.success else "WARNING", result.details)
        if hasattr(self, "singbox_status_label"):
            prefix = "Recovery completed · " if result.success else "Recovery required · "
            self.singbox_status_label.setText(prefix + result.message + ("\n" + result.details if result.details else ""))
        if not result.success:
            self.statusBar().showMessage("Previous sing-box session needs attention", 12000)
            QMessageBox.warning(
                self,
                "Previous tunnel needs attention",
                result.message + ("\n\n" + result.details if result.details else "")
                + "\n\nRaider DNS did not force-kill the process or remove unrelated network adapters. Review Diagnostics before starting another TUN tunnel.",
            )
            return
        details = result.details.casefold()
        if "no adapter, route, or driver was removed" in details or "no automatic network adapter/route cleanup" in details:
            self.statusBar().showMessage("Previous sing-box process is gone; check network adapter and route status", 15000)
            QMessageBox.warning(
                self,
                "Previous tunnel process is no longer running",
                result.message + "\n\n" + result.details
                + "\n\nOpen Diagnostics and verify that your physical network adapter and default route are healthy. Raider DNS intentionally does not delete unknown VPN/TUN adapters automatically.",
            )
        else:
            self.statusBar().showMessage("Previous sing-box session was stopped gracefully", 9000)
            self._show_app_notification("Tunnel recovery completed", "The previous sing-box process was stopped using the graceful Windows shutdown path.", "success")

    def _pause_close_background_timers(self) -> None:
        """Pause periodic UI/network jobs while the TUN driver is shutting down."""
        timers = {
            "network": getattr(self, "_network_change_timer", None),
            "health": getattr(self, "_health_timer", None),
            "activity": getattr(self, "_activity_table_refresh_timer", None),
            "singbox": getattr(self, "_singbox_monitor_timer", None),
        }
        self._close_timer_states = {}
        for name, timer in timers.items():
            if timer is not None:
                self._close_timer_states[name] = timer.isActive()
                timer.stop()
        visual = getattr(self, "dns_connection_visual", None)
        if visual is not None and hasattr(visual, "_timer"):
            self._close_timer_states["plasma"] = visual._timer.isActive()
            visual._timer.stop()
        central = self.centralWidget()
        if central is not None:
            central.setEnabled(False)

    def _resume_after_cancelled_close(self) -> None:
        """Restore periodic work and controls when graceful tunnel stop fails."""
        central = self.centralWidget()
        if central is not None:
            central.setEnabled(True)
        network_timer = getattr(self, "_network_change_timer", None)
        if network_timer is not None and self._close_timer_states.get("network"):
            network_timer.start()
        health_timer = getattr(self, "_health_timer", None)
        if health_timer is not None and self._close_timer_states.get("health"):
            health_timer.start()
        activity_timer = getattr(self, "_activity_table_refresh_timer", None)
        if activity_timer is not None and self._close_timer_states.get("activity"):
            activity_timer.start()
        singbox_timer = getattr(self, "_singbox_monitor_timer", None)
        if singbox_timer is not None and self._close_timer_states.get("singbox") and self.singbox_controller.is_running:
            singbox_timer.start()
        visual = getattr(self, "dns_connection_visual", None)
        if visual is not None and self._close_timer_states.get("plasma") and visual.isVisible():
            visual._timer.start()
        self._close_timer_states = {}

    def _finish_close_after_tunnel_shutdown(self, result: Any) -> None:
        self._close_tunnel_shutdown_pending = False
        if not isinstance(result, TunnelResult):
            result = TunnelResult(False, "Unexpected sing-box shutdown result", str(result))
        if not result.success:
            self._resume_after_cancelled_close()
            self._log(f"Tunnel shutdown blocked application close: {result.message}.", "ERROR", result.details)
            if hasattr(self, "singbox_status_label"):
                self.singbox_status_label.setText("Shutdown not confirmed · " + result.message)
            QMessageBox.warning(
                self,
                "Tunnel shutdown not confirmed",
                result.message + ("\n\n" + result.details if result.details else "")
                + "\n\nRaider DNS will remain open. Retry Stop tunnel or use Diagnostics; the app will not force-kill a live TUN process.",
            )
            return

        details_lower = result.details.casefold()
        needs_manual_network_review = (
            "no adapter, route, or driver was removed" in details_lower
            or "no broad adapter/driver cleanup was attempted" in details_lower
            or "check the tun adapter" in details_lower
        )
        if needs_manual_network_review:
            answer = QMessageBox.question(
                self,
                "Tunnel stopped — verify network state",
                result.message + ("\n\n" + result.details if result.details else "")
                + "\n\nThe sing-box process is no longer running, but Raider DNS cannot safely identify and remove leftover routes belonging to this session. Keep Raider DNS open to run Diagnostics and inspect the physical adapter and default route?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._close_tunnel_shutdown_complete = False
                self._resume_after_cancelled_close()
                self.statusBar().showMessage("Review Diagnostics before closing Raider DNS.", 10000)
                return

        self._close_tunnel_shutdown_complete = True
        self._log(f"Tunnel shutdown before app exit: {result.message}.", "INFO", result.details)
        self.statusBar().showMessage("Tunnel stopped cleanly. Closing Raider DNS…", 4000)
        QTimer.singleShot(0, self.close)

    def _setup_tray(self) -> None:
        """Create an optional tray controller without making it a startup requirement."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._log("System tray unavailable; minimizing will use the normal taskbar behavior.")
            return
        icon = self.windowIcon()
        if icon.isNull():
            icon = QIcon(str(Path(__file__).resolve().parents[2] / "assets" / "app_icon.svg"))
        self._tray_icon = QSystemTrayIcon(icon, self)
        self._tray_icon.setToolTip(f"Raider DNS {__version__}")
        menu = QMenu(self)
        open_action = QAction("Open Raider DNS", self)
        open_action.triggered.connect(self._restore_from_tray)
        menu.addAction(open_action)
        self._tray_toggle_action = QAction("Hide window", self)
        self._tray_toggle_action.triggered.connect(self._toggle_tray_window)
        menu.addAction(self._tray_toggle_action)
        menu.addSeparator()
        exit_action = QAction("Exit Raider DNS", self)
        exit_action.triggered.connect(self._exit_application)
        menu.addAction(exit_action)
        self._tray_icon.setContextMenu(menu)
        self._tray_icon.activated.connect(self._tray_activated)
        self._tray_icon.show()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _toggle_tray_window(self) -> None:
        if self.isVisible():
            self.hide()
            self._minimized_to_tray = True
            if hasattr(self, "_tray_toggle_action"):
                self._tray_toggle_action.setText("Show window")
            self._log("Hid Raider DNS to the system tray.")
        else:
            self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
        self.show()
        self.raise_()
        self.activateWindow()
        self._minimized_to_tray = False
        if hasattr(self, "_tray_toggle_action"):
            self._tray_toggle_action.setText("Hide window")
        self._log("Restored Raider DNS from the system tray.")

    def _exit_application(self) -> None:
        self._log("Exited Raider DNS from the system tray.")
        self._exit_requested = True
        if self._tray_icon:
            self._tray_icon.hide()
        self.close()

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange and self.isMinimized() and self.settings.get("minimize_to_tray", True) and self._tray_icon:
            self.hide()
            self._minimized_to_tray = True
            if hasattr(self, "_tray_toggle_action"):
                self._tray_toggle_action.setText("Show window")
            self._tray_icon.showMessage("Raider DNS", "The application is still running in the system tray.", QSystemTrayIcon.MessageIcon.Information, 2500)
            self._log("Minimized Raider DNS to the system tray.")

    # ---- Shell / navigation -------------------------------------------------
    def _build_shell(self) -> None:
        root = QWidget()
        root.setObjectName("Root")
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(222)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(16, 22, 16, 16)
        side_layout.setSpacing(8)

        brand_row = QHBoxLayout()
        brand_mark = QLabel("◈")
        brand_mark.setObjectName("BrandMark")
        brand_mark.setFixedWidth(30)
        brand = QLabel("Raider DNS")
        brand.setObjectName("Brand")
        brand_row.addWidget(brand_mark)
        brand_row.addWidget(brand)
        brand_row.addStretch(1)
        side_layout.addLayout(brand_row)
        side_layout.addWidget(make_label("NETWORK CONTROL CENTER", "TinyCaps"))
        side_layout.addSpacing(22)
        side_layout.addWidget(make_label("WORKSPACE", "TinyCaps"))

        for title, icon, key in self.NAV_ITEMS:
            button = QPushButton(f"{icon}    {title}")
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda checked=False, k=key: self._navigate(k))
            side_layout.addWidget(button)
            self._nav_buttons[key] = button

        side_layout.addStretch(1)
        build_panel = Panel()
        build_layout = make_panel_layout(build_panel, (12, 12, 12, 12), 7)
        build_layout.addWidget(make_label("BUILD", "TinyCaps"))
        build_layout.addWidget(make_label(f"Raider DNS  {__version__}", "Heading"))
        build_layout.addWidget(make_label("PySide6 edition", "Muted"))
        side_layout.addWidget(build_panel)
        side_layout.addWidget(make_label("Made for Windows", "Muted"))

        main_area = QWidget()
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        topbar = QFrame()
        topbar.setObjectName("TopBar")
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(26, 17, 24, 17)
        top_layout.setSpacing(12)
        title_area = QVBoxLayout()
        title_area.setSpacing(3)
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("PageTitle")
        self.page_subtitle = QLabel("A clear view of your DNS connection.")
        self.page_subtitle.setObjectName("Subtitle")
        title_area.addWidget(self.page_title)
        title_area.addWidget(self.page_subtitle)
        top_layout.addLayout(title_area)
        top_layout.addStretch(1)
        self.environment_pill = QLabel("WINDOWS DNS")
        self.environment_pill.setObjectName("StatusPill" if self.system_dns.is_windows() else "WarningPill")
        top_layout.addWidget(self.environment_pill)
        self.admin_button = QPushButton("Restart as administrator")
        self.admin_button.setObjectName("PrimaryButton")
        self.admin_button.setToolTip("Restart Raider DNS with elevated Windows permissions for system DNS and network repair operations.")
        self.admin_button.clicked.connect(self._relaunch_as_admin)
        self.admin_button.setVisible(self.system_dns.is_windows() and not self.system_dns.is_admin())
        top_layout.addWidget(self.admin_button)
        self.theme_button = QPushButton("☼" if self.settings.get("theme") == "dark" else "☾")
        self.theme_button.setObjectName("IconButton")
        self.theme_button.setToolTip("Switch light/dark theme")
        self.theme_button.clicked.connect(self._toggle_theme)
        top_layout.addWidget(self.theme_button)
        main_layout.addWidget(topbar)

        self.pages = QStackedWidget()
        self.pages.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.pages, 1)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(main_area, 1)
        self.setCentralWidget(root)

        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("QStatusBar{background:transparent;color:#8292a9;border-top:1px solid palette(mid);padding:3px 8px;}")

    def _build_pages(self) -> None:
        self.dashboard_page = self._build_dashboard()
        self.providers_page = self._build_providers_page()
        self.connections_page = self._build_connections_page()
        self.profiles_page = self._build_profiles_page()
        self.security_page = self._build_security_page()
        self.benchmark_page = self._build_benchmark_page()
        self.diagnostics_page = self._build_diagnostics_page()
        self.settings_page = self._build_settings_page()
        self.activity_page = self._build_activity_page()
        self._page_by_key = {
            "dashboard": self.dashboard_page,
            "providers": self.providers_page,
            "security": self.security_page,
            "benchmark": self.benchmark_page,
            "connections": self.connections_page,
            "profiles": self.profiles_page,
            "diagnostics": self.diagnostics_page,
            "activity": self.activity_page,
            "settings": self.settings_page,
        }
        for page in self._page_by_key.values():
            self.pages.addWidget(page)

    def _navigate(self, key: str) -> None:
        page = self._page_by_key.get(key)
        if page is None:
            return
        self.pages.setCurrentWidget(page)
        if key == "dashboard":
            self._animate_opacity(page, "dashboard-entry", start_opacity=0.86, duration=260)
        for nav_key, button in self._nav_buttons.items():
            button.setChecked(nav_key == key)
        titles = {
            "dashboard": ("Dashboard", "A clear view of your DNS connection."),
            "providers": ("DNS Providers", "Compare resolvers, create custom providers, and drag to reorder."),
            "security": ("DNS Security Center", "Audit configured DNS, encrypted DNS settings, resolver responses and optional leak-test results."),
            "benchmark": ("Advanced DNS Benchmark Lab", "Measure resolver latency and reliability with configurable query targets, rounds and timeouts."),
            "connections": ("Secure DNS Connection", "Configure system DNS encryption and inclusive or exclusive browser DoH scope."),
            "profiles": ("DNS Profiles", "Save reusable DNS configurations for different networks."),
            "diagnostics": ("Diagnostics", "Measure resolver reachability and inspect the current DNS setup."),
            "activity": ("Activity Log", "A searchable, persistent history of Raider DNS operations."),
            "settings": ("Settings", "Tune the app, manage backups, and review system requirements."),
        }
        self.page_title.setText(titles[key][0])
        self.page_subtitle.setText(titles[key][1])
        if key == "profiles":
            self._refresh_profiles()
        if key == "providers":
            self._filter_provider_cards()
        if key == "connections":
            self._refresh_connection_summary()
        if key == "activity" and (self._activity_table_dirty or not self._activity_table_initialized):
            self._refresh_activity_table()
        if key == "security":
            self._refresh_security_snapshot()

    # ---- Dashboard ----------------------------------------------------------
    def _build_dashboard(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(17)

        hero = Panel(hero=True)
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(24, 22, 24, 22)
        hero_layout.setSpacing(20)
        hero_copy = QVBoxLayout()
        hero_copy.setSpacing(8)
        hero_copy.addWidget(make_label("DNS CONNECTION", "TinyCaps"))
        hero_title = QLabel("Your network,\nyour control.")
        hero_title.setStyleSheet("font-size:29px;font-weight:800;line-height:1.2;")
        hero_title.setWordWrap(True)
        hero_copy.addWidget(hero_title)
        hero_description = make_label("Choose a resolver, apply it to a network adapter, and check its reachability.", "Muted")
        hero_description.setWordWrap(True)
        hero_copy.addWidget(hero_description)
        mode_row = QHBoxLayout()
        mode_row.addWidget(make_label("Connection mode", "Muted"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Standard DNS", "standard")
        self.mode_combo.addItem("Windows DNS-over-HTTPS", "doh")
        self.mode_combo.addItem("Windows DNS-over-TLS", "dot")
        self.mode_combo.addItem("Local DNSCrypt Proxy", "dnscrypt")
        self.mode_combo.setMinimumWidth(205)
        initial_mode_index = self.mode_combo.findData(self.settings.get("dns_mode", "standard"))
        self.mode_combo.setCurrentIndex(initial_mode_index if initial_mode_index >= 0 else 0)
        self.mode_combo.currentIndexChanged.connect(self._mode_changed)
        mode_row.addWidget(self.mode_combo)
        mode_row.addSpacing(10)
        mode_row.addWidget(make_label("DNS provider", "Muted"))
        self.dashboard_provider_combo = QComboBox()
        self.dashboard_provider_combo.setMinimumWidth(190)
        for provider in self._all_providers():
            self.dashboard_provider_combo.addItem(provider.name, provider.id)
        selected_provider_index = self.dashboard_provider_combo.findData(self.settings.get("selected_provider", "cloudflare"))
        self.dashboard_provider_combo.setCurrentIndex(selected_provider_index if selected_provider_index >= 0 else 0)
        self.dashboard_provider_combo.currentIndexChanged.connect(self._dashboard_provider_changed)
        mode_row.addWidget(self.dashboard_provider_combo)
        mode_row.addStretch(1)
        hero_copy.addLayout(mode_row)
        hero_layout.addLayout(hero_copy, 0)
        # This flexible gap preserves the familiar layout; the visual itself is
        # a full-card overlay and is no longer clipped to this middle column.
        hero_layout.addStretch(1)

        action_column = QVBoxLayout()
        action_column.setSpacing(9)
        self.connection_badge = QLabel("●  Checking system…")
        self.connection_badge.setObjectName("WarningPill")
        self.connection_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_badge.setMinimumWidth(205)
        action_column.addWidget(self.connection_badge)
        self.apply_button = QPushButton("Apply selected DNS  →")
        self.apply_button.setObjectName("PrimaryButton")
        self.apply_button.setMinimumHeight(43)
        self.apply_button.clicked.connect(self._apply_selected_provider)
        action_column.addWidget(self.apply_button)
        self.restore_previous_button = QPushButton("Restore Previous DNS Settings")
        self.restore_previous_button.setObjectName("PrimaryButton")
        self.restore_previous_button.setToolTip("Restore the exact DNS configuration captured before Raider DNS last changed this adapter.")
        self.restore_previous_button.clicked.connect(self._restore_previous_dns_settings)
        self.restore_previous_button.setEnabled(False)
        action_column.addWidget(self.restore_previous_button)
        self.restore_button = QPushButton("Restore automatic DNS")
        self.restore_button.clicked.connect(self._restore_automatic_dns)
        action_column.addWidget(self.restore_button)
        self.flush_dashboard_button = QPushButton("Flush DNS cache")
        self.flush_dashboard_button.clicked.connect(self._flush_dns_cache)
        action_column.addWidget(self.flush_dashboard_button)
        action_column.addStretch(1)
        hero_layout.addLayout(action_column)

        # Paint the stream over the hero surface but behind every label, combo
        # and action button. This lets the energy reach beneath the left heading
        # while preserving clickability and foreground contrast.
        self.dns_connection_visual = ConnectionStatusVisual(hero)
        self.dns_connection_visual.setGeometry(hero.rect().adjusted(2, 2, -2, -2))
        hero.installEventFilter(self.dns_connection_visual)
        self.dns_connection_visual.lower()
        layout.addWidget(hero)

        selector_row = QHBoxLayout()
        selector_row.addWidget(make_label("Active network adapter", "Heading"))
        selector_row.addStretch(1)
        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(275)
        self.adapter_combo.addItem("Detecting adapters…", "")
        self.adapter_combo.currentIndexChanged.connect(self._adapter_changed)
        selector_row.addWidget(self.adapter_combo)
        refresh_adapter_button = QPushButton("↻")
        refresh_adapter_button.setObjectName("IconButton")
        refresh_adapter_button.setToolTip("Refresh network adapters")
        refresh_adapter_button.clicked.connect(self._refresh_system_state)
        selector_row.addWidget(refresh_adapter_button)
        layout.addLayout(selector_row)

        metric_grid = QGridLayout()
        metric_grid.setHorizontalSpacing(12)
        metric_grid.setVerticalSpacing(12)
        metric_grid.setColumnStretch(0, 1)
        metric_grid.setColumnStretch(1, 1)

        connection_panel = Panel()
        connection_layout = make_panel_layout(connection_panel, (18, 16, 18, 16), 7)
        connection_layout.addWidget(make_label("CONNECTION", "TinyCaps"))
        self.metric_connection_status = make_label("Checking…", "Metric")
        self.metric_connection_status.setWordWrap(True)
        connection_layout.addWidget(self.metric_connection_status)
        self.metric_connection_details = make_label("Inspecting active network adapters", "Muted")
        self.metric_connection_details.setWordWrap(True)
        connection_layout.addWidget(self.metric_connection_details)

        security_panel = Panel()
        security_layout = make_panel_layout(security_panel, (18, 16, 18, 16), 7)
        security_layout.addWidget(make_label("DNS SECURITY", "TinyCaps"))
        self.metric_security_status = make_label("Checking configuration…", "Metric")
        self.metric_security_status.setWordWrap(True)
        security_layout.addWidget(self.metric_security_status)
        self.metric_security_details = make_label("Configured mode is not proof of actual resolver use", "Muted")
        self.metric_security_details.setWordWrap(True)
        security_layout.addWidget(self.metric_security_details)

        latency_panel = Panel()
        latency_layout = make_panel_layout(latency_panel, (18, 16, 18, 16), 7)
        latency_layout.addWidget(make_label("DNS QUERY LATENCY", "TinyCaps"))
        self.metric_dns_latency = make_label("Not tested", "Metric")
        self.metric_dns_latency.setWordWrap(True)
        latency_layout.addWidget(self.metric_dns_latency)
        self.metric_dns_latency_details = make_label("Run a benchmark to measure real DNS queries", "Muted")
        self.metric_dns_latency_details.setWordWrap(True)
        latency_layout.addWidget(self.metric_dns_latency_details)

        health_panel = Panel()
        health_layout = make_panel_layout(health_panel, (18, 16, 18, 16), 7)
        health_layout.addWidget(make_label("DNS HEALTH", "TinyCaps"))
        self.metric_dns_health = make_label("Not tested", "Metric")
        self.metric_dns_health.setWordWrap(True)
        health_layout.addWidget(self.metric_dns_health)
        self.metric_dns_health_details = make_label("No current DNS query benchmark", "Muted")
        self.metric_dns_health_details.setWordWrap(True)
        health_layout.addWidget(self.metric_dns_health_details)

        metric_grid.addWidget(connection_panel, 0, 0)
        metric_grid.addWidget(security_panel, 0, 1)
        metric_grid.addWidget(latency_panel, 1, 0)
        metric_grid.addWidget(health_panel, 1, 1)
        layout.addLayout(metric_grid)

        ip_panel = Panel()
        ip_layout = make_panel_layout(ip_panel, (16, 14, 16, 14), 8)
        ip_header = QHBoxLayout()
        ip_header.addWidget(make_label("NETWORK ADDRESSES", "TinyCaps"))
        ip_header.addStretch(1)
        self.ip_refresh_button = QPushButton("Refresh IP information")
        self.ip_refresh_button.clicked.connect(lambda: self._refresh_network_info(include_public=True))
        ip_header.addWidget(self.ip_refresh_button)
        ip_layout.addLayout(ip_header)
        ip_grid = QGridLayout()
        ip_grid.setHorizontalSpacing(18)
        ip_grid.setVerticalSpacing(8)
        ip_grid.addWidget(make_label("Private IPv4", "Muted"), 0, 0)
        self.private_ipv4_label = make_label("Checking…", "Heading")
        self.private_ipv4_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ip_grid.addWidget(self.private_ipv4_label, 1, 0)
        ip_grid.addWidget(make_label("Private IPv6", "Muted"), 0, 1)
        self.private_ipv6_label = make_label("Checking…", "Heading")
        self.private_ipv6_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ip_grid.addWidget(self.private_ipv6_label, 1, 1)
        ip_grid.addWidget(make_label("Public IP", "Muted"), 0, 2)
        self.public_ip_label = make_label("Checking…", "Heading")
        self.public_ip_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ip_grid.addWidget(self.public_ip_label, 1, 2)
        self.ip_info_time_label = make_label("Public IP lookup uses an external HTTPS service.", "Muted")
        ip_layout.addLayout(ip_grid)
        ip_layout.addWidget(self.ip_info_time_label)
        layout.addWidget(ip_panel)

        lower_row = QHBoxLayout()
        lower_row.setSpacing(12)
        quick_panel = Panel()
        quick_layout = make_panel_layout(quick_panel)
        title_row = QHBoxLayout()
        title_row.addWidget(make_label("Quick select", "Heading"))
        title_row.addStretch(1)
        title_row.addWidget(make_label("POPULAR RESOLVERS", "TinyCaps"))
        quick_layout.addLayout(title_row)
        self.quick_provider_layout = QVBoxLayout()
        self.quick_provider_layout.setSpacing(7)
        quick_layout.addLayout(self.quick_provider_layout)
        for provider_id in ("cloudflare", "quad9", "google", "adguard"):
            provider = self._provider(provider_id)
            if not provider:
                continue
            row = QHBoxLayout()
            dot = QLabel("●")
            dot.setObjectName("Accent")
            name_column = QVBoxLayout()
            name_column.setSpacing(2)
            name_column.addWidget(make_label(provider.name))
            name_column.addWidget(make_label(f"{provider.primary}  ·  {provider.secondary}", "Muted"))
            select = QPushButton("Select")
            select.setMaximumWidth(75)
            select.clicked.connect(lambda checked=False, pid=provider.id: self._select_provider(pid))
            row.addWidget(dot)
            row.addLayout(name_column, 1)
            row.addWidget(select)
            self.quick_provider_layout.addLayout(row)
        self.quick_provider_layout.addStretch(1)

        activity_panel = Panel()
        activity_layout = make_panel_layout(activity_panel)
        activity_header = QHBoxLayout()
        activity_header.addWidget(make_label("Recent activity", "Heading"))
        activity_header.addStretch(1)
        activity_header.addWidget(make_label("LIVE SESSION", "TinyCaps"))
        activity_layout.addLayout(activity_header)
        self.activity_list = QVBoxLayout()
        self.activity_list.setSpacing(9)
        activity_layout.addLayout(self.activity_list)
        self._recent_activity_labels = []
        initial_activity = self._activity[:5]
        if initial_activity:
            for entry in initial_activity:
                label = make_label("•  " + entry, "Muted")
                label.setWordWrap(True)
                self._recent_activity_labels.append(label)
                self.activity_list.addWidget(label)
        else:
            label = make_label("No actions yet. System checks will appear here.", "Muted")
            label.setWordWrap(True)
            self._recent_activity_labels.append(label)
            self.activity_list.addWidget(label)
        lower_row.addWidget(quick_panel, 3)
        lower_row.addWidget(activity_panel, 2)
        layout.addLayout(lower_row)
        layout.addWidget(self._build_fastest_dns_panel())
        layout.addStretch(1)
        return scroll_page(content)

    def _build_fastest_dns_panel(self) -> QWidget:
        panel = Panel()
        layout = make_panel_layout(panel)
        header = QHBoxLayout()
        header.addWidget(make_label("Fastest DNS finder", "Heading"))
        header.addStretch(1)
        self.fastest_button = QPushButton("Run DNS benchmark")
        self.fastest_button.setObjectName("PrimaryButton")
        self.fastest_button.clicked.connect(self._run_fastest_dns)
        header.addWidget(self.fastest_button)
        advanced_button = QPushButton("Advanced Lab")
        advanced_button.setToolTip("Open the advanced benchmark lab to choose query targets, sample count and timeouts.")
        advanced_button.clicked.connect(lambda: self._navigate("benchmark"))
        header.addWidget(advanced_button)
        layout.addLayout(header)

        controls = QHBoxLayout()
        controls.addWidget(make_label("Measurements", "Muted"))
        self.fastest_measurement_checks: dict[str, QCheckBox] = {}
        for key, title in (("median", "Median ICMP ping"), ("tcp", "TCP/53 connect"), ("query", "DNS query latency")):
            check = QCheckBox(title)
            check.setChecked(True)
            check.stateChanged.connect(lambda _state, metric=key: self._fastest_measurement_changed(metric))
            self.fastest_measurement_checks[key] = check
            controls.addWidget(check)
        controls.addStretch(1)
        layout.addLayout(controls)

        note = make_label(
            "By default, results are ranked by actual DNS query latency. Click a measurement column header to rank by that metric. DNS query time is the primary comparison; ICMP ping and TCP/53 connection time are separate diagnostics.",
            "Muted",
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.fastest_summary = make_label("No benchmark run yet.", "Muted")
        layout.addWidget(self.fastest_summary)

        self.fastest_sort_metric = "query"
        self.fastest_sort_ascending = True
        self._fastest_sort_clicked = False
        self._fastest_completed_measurements: set[str] = set()
        self._fastest_results: list[dict[str, Any]] = []
        self._fastest_pending = 0
        self.fastest_table = QTableWidget(0, 7)
        self.fastest_table.setHorizontalHeaderLabels([
            "RANK", "PROVIDER", "MEDIAN ICMP", "TCP/53 CONNECT", "DNS QUERY LATENCY", "QUERY SUCCESS", "RESULT"
        ])
        self.fastest_table.horizontalHeaderItem(2).setToolTip("Median ICMP ping round-trip time when available. If the ping output is not parseable, process elapsed time is used.")
        self.fastest_table.horizontalHeaderItem(3).setToolTip("Median time to establish a TCP connection to the resolver on port 53; this is not a DNS query.")
        self.fastest_table.horizontalHeaderItem(4).setToolTip("Primary ranking metric: median elapsed time for an actual UDP DNS query and response.")
        self.fastest_table.setToolTip("Click a measurement column heading to rank providers by that metric.")
        self.fastest_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fastest_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fastest_table.setAlternatingRowColors(True)
        self.fastest_table.verticalHeader().setVisible(False)
        header_view = self.fastest_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in (2, 3, 4, 5):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        header_view.sectionClicked.connect(self._sort_fastest_by_column)
        self.fastest_table.setMinimumHeight(250)
        self.fastest_table.setMaximumHeight(390)
        layout.addWidget(self.fastest_table)
        return panel

    # ---- Providers ----------------------------------------------------------
    def _all_providers(self) -> list[DNSProvider]:
        custom_rows = self.settings.get("custom_providers", [])
        overrides = self.settings.get("provider_overrides", {})
        disabled = self.settings.get("disabled_builtin_providers", [])
        try:
            signature = json.dumps({"custom": custom_rows, "overrides": overrides, "disabled": disabled}, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            signature = repr((custom_rows, overrides, disabled))

        def build_catalog() -> list[DNSProvider]:
            providers: list[DNSProvider] = []
            override_rows = overrides if isinstance(overrides, dict) else {}
            disabled_ids = set(disabled) if isinstance(disabled, list) else set()
            for builtin in PROVIDERS:
                if builtin.id in disabled_ids:
                    continue
                raw = override_rows.get(builtin.id, {})
                if not isinstance(raw, dict):
                    raw = {}
                try:
                    providers.append(DNSProvider(
                        id=builtin.id,
                        name=str(raw.get("name", builtin.name)),
                        description=str(raw.get("description", builtin.description)),
                        primary=str(raw.get("primary", builtin.primary)),
                        secondary=str(raw.get("secondary", builtin.secondary)),
                        category=str(raw.get("category", builtin.category)),
                        doh_url=raw.get("doh_url", builtin.doh_url),
                        dot_hostname=raw.get("dot_hostname", builtin.dot_hostname),
                        website=str(raw.get("website", builtin.website)),
                    ))
                except (KeyError, TypeError, ValueError):
                    providers.append(builtin)
            rows = custom_rows if isinstance(custom_rows, list) else []
            for raw in rows:
                if not isinstance(raw, dict):
                    continue
                try:
                    providers.append(DNSProvider(
                        id=str(raw["id"]), name=str(raw["name"]), description=str(raw.get("description", "Custom DNS provider")),
                        primary=str(raw["primary"]), secondary=str(raw.get("secondary", "")),
                        category=str(raw.get("category", "Custom")), doh_url=raw.get("doh_url"),
                        dot_hostname=raw.get("dot_hostname"), website=str(raw.get("website", "")),
                    ))
                except (KeyError, TypeError, ValueError):
                    continue
            return providers

        # Only stable provider metadata is cached. Latency/probe data is never
        # read from or written to this catalog cache.
        return self._provider_metadata_cache.get(signature, build_catalog)

    def _provider(self, provider_id: str | None) -> DNSProvider | None:
        if not provider_id:
            return None
        return next((provider for provider in self._all_providers() if provider.id == provider_id), None)

    def _build_providers_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        header_row = QHBoxLayout()
        header_row.addWidget(PageHeader("Resolver catalogue", "Manage built-in and custom DNS resolvers. Drag the grip on any card to change display order."), 1)
        create_button = QPushButton("＋  Create DNS provider")
        create_button.setObjectName("PrimaryButton")
        create_button.clicked.connect(self._create_provider_dialog)
        header_row.addWidget(create_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)

        filter_row = QHBoxLayout()
        self.provider_search = QLineEdit()
        self.provider_search.setPlaceholderText("Search providers, category, or DNS address…")
        self.provider_search.textChanged.connect(self._filter_provider_cards)
        filter_row.addWidget(self.provider_search, 1)
        self.favorite_filter = QCheckBox("Favorites only")
        self.favorite_filter.stateChanged.connect(self._filter_provider_cards)
        filter_row.addWidget(self.favorite_filter)
        layout.addLayout(filter_row)

        self.providers_container = QWidget()
        self.providers_layout = QVBoxLayout(self.providers_container)
        self.providers_layout.setContentsMargins(0, 0, 0, 0)
        self.providers_layout.setSpacing(11)
        self._rebuild_provider_cards()
        layout.addWidget(scroll_page(self.providers_container), 1)
        return content

    def _rebuild_provider_cards(self) -> None:
        if not hasattr(self, "providers_layout"):
            return
        while self.providers_layout.count():
            item = self.providers_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self._provider_cards.clear()
        self._favorite_controls.clear()
        for provider in self._all_providers():
            card = ProviderCard(provider.id, self)
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(13, 13, 15, 13)
            card_layout.setSpacing(10)

            drag_handle = ProviderDragHandle(provider.id)
            card_layout.addWidget(drag_handle)
            icon = QLabel("◈")
            icon.setObjectName("Accent")
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon.setFixedSize(42, 42)
            icon.setStyleSheet("font-size:23px;background:rgba(40,190,170,0.10);border:1px solid rgba(40,190,170,0.22);border-radius:12px;")
            card_layout.addWidget(icon)

            detail = QVBoxLayout()
            detail.setSpacing(5)
            top_line = QHBoxLayout()
            top_line.addWidget(make_label(provider.name, "Heading"))
            category = QLabel(provider.category)
            category.setObjectName("StatusPill" if provider.supports_doh else "WarningPill")
            top_line.addWidget(category)
            top_line.addStretch(1)
            if provider.id.startswith("custom-"):
                custom_pill = QLabel("CUSTOM")
                custom_pill.setObjectName("StatusPill")
                top_line.addWidget(custom_pill)
            detail.addLayout(top_line)
            desc = make_label(provider.description, "Muted")
            desc.setWordWrap(True)
            detail.addWidget(desc)
            transport = []
            if provider.supports_doh:
                transport.append("DoH endpoint configured")
            if provider.dot_hostname:
                transport.append("DoT hostname configured")
            if not transport:
                transport.append("Standard DNS available")
            detail.addWidget(make_label(f"{provider.primary}" + (f"  ·  {provider.secondary}" if provider.secondary else "") + "     |     " + " · ".join(transport), "Muted"))
            card_layout.addLayout(detail, 1)

            action_column = QVBoxLayout()
            action_column.setSpacing(6)
            action_row = QHBoxLayout()
            favorite_button = QPushButton("★" if provider.id in self.settings.get("favorites", []) else "☆")
            favorite_button.setObjectName("IconButton")
            favorite_button.setToolTip("Toggle favorite")
            favorite_button.clicked.connect(lambda checked=False, pid=provider.id, b=favorite_button: self._toggle_favorite(pid, b))
            action_row.addWidget(favorite_button)
            if provider.id.startswith("custom-"):
                remove_button = QPushButton("Remove")
                remove_button.setToolTip("Remove this custom DNS provider")
                remove_button.clicked.connect(lambda checked=False, pid=provider.id: self._delete_custom_provider(pid))
                action_row.addWidget(remove_button)
            action_column.addLayout(action_row)
            select_button = QPushButton("Selected" if provider.id == self.settings.get("selected_provider") else "Select")
            select_button.setObjectName("PrimaryButton" if provider.id == self.settings.get("selected_provider") else "SelectProviderButton")
            select_button.setProperty("providerId", provider.id)
            select_button.clicked.connect(lambda checked=False, pid=provider.id: self._select_provider(pid))
            action_column.addWidget(select_button)
            card_layout.addLayout(action_column)

            self._favorite_controls[provider.id] = favorite_button
            self.providers_layout.addWidget(card)
            self._provider_cards.append((card, provider))
            if hasattr(self, "_tooltip_controller"):
                self._tooltip_controller.register_tree(card)
            self._register_provider_context_menu(card, provider.id)
        self.providers_layout.addStretch(1)
        self._reorder_provider_cards()
        self._filter_provider_cards()

    def _create_provider_dialog(self) -> None:
        self._provider_editor_dialog()

    def _edit_custom_provider(self, provider_id: str) -> None:
        # Kept as a local call-site alias; built-in providers can also be edited
        # through an override record without mutating the code-defined catalogue.
        self._provider_editor_dialog(provider_id)

    def _provider_editor_dialog(self, provider_id: str | None = None) -> None:
        editing = self._provider(provider_id) if provider_id else None
        if provider_id and editing is None:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(("Modify DNS provider" if provider_id and editing else "Create DNS provider"))
        dialog.setMinimumWidth(520)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(12)
        layout.addWidget(make_label("DNS provider details", "Heading"))
        hint = make_label("Edit every catalogue field below. System DoH requires a valid HTTPS endpoint; DoT metadata is saved but is not applied by the Windows system-DNS integration in this release.", "Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        form = QFormLayout()
        form.setSpacing(10)
        name_edit = QLineEdit(editing.name if editing else ""); name_edit.setPlaceholderText("e.g. Home DNS")
        primary_edit = QLineEdit(editing.primary if editing else ""); primary_edit.setPlaceholderText("e.g. 1.1.1.1")
        secondary_edit = QLineEdit(editing.secondary if editing else ""); secondary_edit.setPlaceholderText("Optional secondary IPv4 address")
        category_edit = QLineEdit(editing.category if editing else "Custom")
        description_edit = QLineEdit(editing.description if editing else ""); description_edit.setPlaceholderText("Short description")
        doh_edit = QLineEdit(editing.doh_url or "" if editing else ""); doh_edit.setPlaceholderText("https://resolver.example/dns-query")
        dot_edit = QLineEdit(editing.dot_hostname or "" if editing else ""); dot_edit.setPlaceholderText("resolver.example")
        website_edit = QLineEdit(editing.website or "" if editing else ""); website_edit.setPlaceholderText("https://provider.example/")
        form.addRow("Name *", name_edit)
        form.addRow("Primary IPv4 *", primary_edit)
        form.addRow("Secondary IPv4", secondary_edit)
        form.addRow("Category", category_edit)
        form.addRow("Description", description_edit)
        form.addRow("DoH endpoint (HTTPS)", doh_edit)
        form.addRow("DoT hostname", dot_edit)
        form.addRow("Website", website_edit)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        name = name_edit.text().strip()[:80]
        primary = primary_edit.text().strip()
        secondary = secondary_edit.text().strip()
        doh_url = doh_edit.text().strip() or None
        website = website_edit.text().strip() or None
        dot_hostname = dot_edit.text().strip() or None
        if not name or not primary:
            QMessageBox.warning(self, "Missing required field", "Provider name and primary IPv4 address are required.")
            return
        if any(provider.name.casefold() == name.casefold() and provider.id != provider_id for provider in self._all_providers()):
            QMessageBox.warning(self, "Duplicate provider", "A provider with this name already exists.")
            return
        try:
            if ipaddress.ip_address(primary).version != 4:
                raise ValueError("Primary DNS must be an IPv4 address.")
            if secondary and ipaddress.ip_address(secondary).version != 4:
                raise ValueError("Secondary DNS must be an IPv4 address.")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid DNS address", str(exc))
            return
        if doh_url and not _valid_web_url(doh_url, {"https"}):
            QMessageBox.warning(self, "Invalid DoH endpoint", "DoH endpoints must be a valid HTTPS URL.")
            return
        if website and not _valid_web_url(website, {"http", "https"}):
            QMessageBox.warning(self, "Invalid website", "Website must start with https:// or http:// and include a hostname.")
            return
        if dot_hostname and (len(dot_hostname) > 253 or any(ch.isspace() for ch in dot_hostname) or any(ch in dot_hostname for ch in "/\\?#@[]")):
            QMessageBox.warning(self, "Invalid DoT hostname", "Enter a hostname only, without a scheme, path, port or whitespace.")
            return
        if editing:
            updated = {
                "id": editing.id,
                "name": name,
                "description": description_edit.text().strip()[:240] or "DNS provider",
                "primary": primary,
                "secondary": secondary,
                "category": category_edit.text().strip()[:60] or "General",
                "doh_url": doh_url,
                "dot_hostname": dot_hostname,
                "website": website or "",
            }
            if provider_id.startswith("custom-"):
                self.settings["custom_providers"] = [updated if row.get("id") == provider_id else row for row in self.settings.get("custom_providers", [])]
                action = f"Modified custom DNS provider: {name}."
            else:
                overrides = dict(self.settings.get("provider_overrides", {}))
                overrides[provider_id] = updated
                self.settings["provider_overrides"] = overrides
                action = f"Modified built-in DNS provider: {name}."
        else:
            slug = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:35] or "provider"
            new_provider_id = f"custom-{slug}-{uuid.uuid4().hex[:8]}"
            self.settings.setdefault("custom_providers", []).append({
                "id": new_provider_id,
                "name": name,
                "description": description_edit.text().strip()[:240] or "Custom DNS provider",
                "primary": primary,
                "secondary": secondary,
                "category": category_edit.text().strip()[:60] or "Custom",
                "doh_url": doh_url,
                "dot_hostname": dot_hostname,
                "website": website,
            })
            self.settings.setdefault("provider_order", []).append(new_provider_id)
            action = f"Created custom DNS provider: {name}."
        self._save_settings()
        self._provider_metadata_cache.clear()
        self._rebuild_provider_cards()
        self._refresh_provider_selector_options()
        self._update_provider_metrics()
        self._update_provider_selection_controls()
        self._log(action)
        if not editing:
            QMessageBox.information(self, "Provider created", f"{name} was added to the DNS provider catalogue.")

    def _register_provider_context_menu(self, card: QWidget, provider_id: str) -> None:
        for widget in [card, *card.findChildren(QWidget)]:
            widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            widget.customContextMenuRequested.connect(
                lambda point, pid=provider_id, target=widget: self._show_provider_context_menu(pid, target.mapToGlobal(point))
            )

    def _show_provider_context_menu(self, provider_id: str, global_position: QPoint) -> None:
        provider = self._provider(provider_id)
        if provider is None:
            return
        menu = QMenu(self)
        delete_action = menu.addAction("Delete DNS")
        modify_action = menu.addAction("Modify DNS")
        menu.addSeparator()
        favorites = set(self.settings.get("favorites", []))
        favorite_action = menu.addAction("Remove from favorites" if provider_id in favorites else "Favorite DNS")
        delete_action.setEnabled(len(self._all_providers()) > 1)
        delete_action.setToolTip("Permanently remove this provider from the Raider DNS catalogue after confirmation.")
        modify_action.setToolTip("Edit the name, addresses, category, description, encryption endpoints and website.")
        chosen = menu.exec(global_position)
        if chosen is delete_action:
            self._delete_provider(provider_id)
        elif chosen is modify_action:
            self._provider_editor_dialog(provider_id)
        elif chosen is favorite_action:
            button = self._favorite_controls.get(provider_id)
            if button is not None:
                self._toggle_favorite(provider_id, button)
            else:
                current = list(self.settings.get("favorites", []))
                if provider_id in current:
                    current.remove(provider_id)
                else:
                    current.append(provider_id)
                self.settings["favorites"] = current
                self._save_settings()
                self._log(f"Updated favorite state for {provider.name}.")
                self._update_favorite_controls()

    def _delete_custom_provider(self, provider_id: str) -> None:
        # Compatibility alias for the remove button on custom-provider cards.
        self._delete_provider(provider_id)

    def _delete_provider(self, provider_id: str) -> None:
        provider = self._provider(provider_id)
        if not provider:
            return
        if len(self._all_providers()) <= 1:
            QMessageBox.warning(self, "Keep one DNS provider", "Raider DNS needs at least one provider in its catalogue. Add another provider before deleting this one.")
            return
        answer = QMessageBox.question(
            self,
            "Permanently delete DNS provider?",
            f"Permanently remove {provider.name} from the Raider DNS provider list?\n\n"
            "This cannot be undone from this screen. Saved profiles will retain their server addresses but lose the provider link. "
            "The Windows DNS configuration already applied to an adapter will not be changed automatically.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        if provider_id.startswith("custom-"):
            self.settings["custom_providers"] = [row for row in self.settings.get("custom_providers", []) if row.get("id") != provider_id]
        else:
            disabled = list(self.settings.get("disabled_builtin_providers", []))
            if provider_id not in disabled:
                disabled.append(provider_id)
            self.settings["disabled_builtin_providers"] = disabled
            overrides = dict(self.settings.get("provider_overrides", {}))
            overrides.pop(provider_id, None)
            self.settings["provider_overrides"] = overrides

        self._provider_metadata_cache.clear()
        self.settings["provider_order"] = [item for item in self.settings.get("provider_order", []) if item != provider_id]
        self.settings["favorites"] = [item for item in self.settings.get("favorites", []) if item != provider_id]
        for profile in self.settings.get("profiles", []):
            if profile.get("provider_id") == provider_id:
                profile["provider_id"] = None
                profile["doh_url"] = None
        remaining = self._all_providers()
        replacement = remaining[0].id
        if self.settings.get("selected_provider") == provider_id:
            self.settings["selected_provider"] = replacement
        if self.settings.get("fallback_provider") == provider_id:
            self.settings["fallback_provider"] = next((item.id for item in remaining if item.id != replacement), replacement)
        if self.settings.get("connection_dns_provider") == provider_id:
            self.settings["connection_dns_provider"] = self.settings.get("selected_provider", replacement)
        self.settings["provider_order"] = [item.id for item in remaining]
        self._save_settings()
        self._rebuild_provider_cards()
        self._refresh_provider_selector_options()
        self._update_provider_metrics()
        self._update_favorite_controls()
        self._update_provider_selection_controls()
        self._refresh_profiles()
        self._log(f"Permanently removed DNS provider from the catalogue: {provider.name}.", "WARNING")
        self._show_app_notification("DNS provider deleted", f"{provider.name} was removed from your provider catalogue.", "warning")

    def _refresh_provider_selector_options(self) -> None:
        provider_rows = self._all_providers()
        for combo_name, setting_key in (("dashboard_provider_combo", "selected_provider"), ("fallback_provider_combo", "fallback_provider"), ("connection_dns_provider_combo", "connection_dns_provider")):
            combo = getattr(self, combo_name, None)
            if combo is None:
                continue
            selected = self.settings.get(setting_key, "cloudflare")
            combo.blockSignals(True)
            combo.clear()
            for provider in provider_rows:
                combo.addItem(provider.name, provider.id)
            idx = combo.findData(selected)
            combo.setCurrentIndex(idx if idx >= 0 else 0)
            combo.blockSignals(False)

    def _filter_provider_cards(self, *_args: Any) -> None:
        if not hasattr(self, "provider_search"):
            return
        query = self.provider_search.text().strip().casefold()
        favorites_only = self.favorite_filter.isChecked()
        favorites = set(self.settings.get("favorites", []))
        for card, provider in self._provider_cards:
            haystack = " ".join([provider.name, provider.description, provider.category, provider.primary, provider.secondary, provider.doh_url or "", provider.dot_hostname or ""]).casefold()
            card.setVisible((not query or query in haystack) and (not favorites_only or provider.id in favorites))

    def _toggle_favorite(self, provider_id: str, button: QPushButton) -> None:
        favorites = list(self.settings.get("favorites", []))
        if provider_id in favorites:
            favorites.remove(provider_id)
        else:
            favorites.append(provider_id)
        self.settings["favorites"] = favorites
        button.setText("★" if provider_id in favorites else "☆")
        self._save_settings()
        self._log(f"{'Added' if provider_id in favorites else 'Removed'} {self._provider(provider_id).name if self._provider(provider_id) else provider_id} {'to' if provider_id in favorites else 'from'} favorites.")
        self._filter_provider_cards()

    def _update_favorite_controls(self) -> None:
        favorites = set(self.settings.get("favorites", []))
        for provider_id, button in self._favorite_controls.items():
            button.setText("★" if provider_id in favorites else "☆")

    def _move_provider_before(self, source_id: str, target_id: str) -> None:
        order = [provider.id for provider in self._all_providers()]
        saved_order = [item for item in self.settings.get("provider_order", []) if item in order]
        saved_order += [item for item in order if item not in saved_order]
        if source_id not in saved_order or target_id not in saved_order or source_id == target_id:
            return
        saved_order.remove(source_id)
        saved_order.insert(saved_order.index(target_id), source_id)
        self.settings["provider_order"] = saved_order
        self.settings["favorites"] = [item for item in saved_order if item in set(self.settings.get("favorites", []))]
        self._save_settings()
        self._reorder_provider_cards()
        self._log(f"Reordered DNS providers: {self._provider(source_id).name if self._provider(source_id) else source_id}.")

    def _reorder_provider_cards(self) -> None:
        if not hasattr(self, "providers_layout"):
            return
        all_ids = [provider.id for provider in self._all_providers()]
        saved = [item for item in self.settings.get("provider_order", []) if item in all_ids]
        saved.extend(item for item in all_ids if item not in saved)
        self.settings["provider_order"] = saved
        by_id = {provider.id: (card, provider) for card, provider in self._provider_cards}
        for card, _provider in self._provider_cards:
            self.providers_layout.removeWidget(card)
        for index, provider_id in enumerate(saved):
            row = by_id.get(provider_id)
            if row:
                self.providers_layout.insertWidget(index, row[0])

    def _dashboard_provider_changed(self, *_args: Any) -> None:
        if not hasattr(self, "dashboard_provider_combo"):
            return
        provider_id = self.dashboard_provider_combo.currentData()
        if provider_id:
            self._select_provider(str(provider_id))

    def _select_provider(self, provider_id: str) -> None:
        provider = self._provider(provider_id)
        if not provider:
            return
        prior_provider_id = str(self.settings.get("selected_provider", ""))
        self.settings["selected_provider"] = provider_id
        if hasattr(self, "dashboard_provider_combo"):
            self.dashboard_provider_combo.blockSignals(True)
            selected_index = self.dashboard_provider_combo.findData(provider_id)
            if selected_index >= 0:
                self.dashboard_provider_combo.setCurrentIndex(selected_index)
            self.dashboard_provider_combo.blockSignals(False)
        if not provider.supports_doh and self.settings.get("dns_mode") == "doh":
            self.settings["dns_mode"] = "standard"
            self.mode_combo.setCurrentIndex(0)
        self._save_settings()
        self._update_provider_metrics()
        self._animate_opacity(self.metric_security_status, "provider-selection", start_opacity=0.35, duration=260)
        self.statusBar().showMessage(f"Selected {provider.name}", 3000)
        self._log(f"Selected resolver: {provider.name}.")
        self._update_provider_selection_controls()
        if self.settings.get("health_monitor_enabled", False) and prior_provider_id != provider_id:
            self._health_generation += 1
            self._health_state_tracker.reset()
            self._health_last_result = None
            self._health_state_provider_id = provider_id
            self._update_health_display(None)
            if not self._health_check_in_flight:
                QTimer.singleShot(100, self._run_health_check)
        self._navigate("dashboard")

    def _update_provider_selection_controls(self) -> None:
        """Refresh provider-card selection state after selecting/importing settings."""
        selected_id = str(self.settings.get("selected_provider", "cloudflare"))
        for card, provider in self._provider_cards:
            for button in card.findChildren(QPushButton):
                if button.property("providerId") is not None:
                    is_selected = provider.id == selected_id
                    button.setText("Selected" if is_selected else "Select")
                    button.setObjectName("PrimaryButton" if is_selected else "SelectProviderButton")
                    button.style().unpolish(button)
                    button.style().polish(button)

    # ---- Secure DNS connection ---------------------------------------------
    def _build_connections_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 26)
        layout.setSpacing(15)
        layout.addWidget(PageHeader(
            "Secure DNS Connection",
            "Configure Standard DNS, native DoH/DoT, a local DNSCrypt proxy, or an external full-traffic TUN engine.",
        ))

        # Premium / full-card hero, with the animated stream painted under the
        # copy and controls. The result badge is a configuration status, not a
        # guarantee that all resolver traffic is encrypted.
        hero = Panel(hero=True)
        hero.setMinimumHeight(204)
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(24, 21, 23, 20)
        hero_layout.setSpacing(18)
        hero_text = QVBoxLayout()
        hero_text.setSpacing(7)
        hero_text.addWidget(make_label("SECURE DNS CONNECTION", "TinyCaps"))
        hero_text.addWidget(make_label("Your DNS. Your rules.", "Heading"))
        self.connection_status_label = make_label("Ready to configure", "Metric")
        hero_text.addWidget(self.connection_status_label)
        self.connection_status_detail = make_label(
            "Choose a resolver and encryption method. System DNS and browser DNS scope are separate settings.", "Muted"
        )
        self.connection_status_detail.setWordWrap(True)
        hero_text.addWidget(self.connection_status_detail)

        # Keep provider selection inside the hero, as in the chosen Premium
        # full-card concept, rather than inserting an unrelated full-width card.
        provider_row = QHBoxLayout()
        provider_row.setSpacing(8)
        provider_row.addWidget(make_label("DNS provider", "Muted"))
        self.connection_dns_provider_combo = QComboBox()
        self.connection_dns_provider_combo.setMinimumWidth(250)
        self.connection_dns_provider_combo.setMaximumWidth(360)
        self.connection_dns_provider_combo.setToolTip("Choose the provider to use when applying system DNS or browser DoH.")
        for provider in self._all_providers():
            self.connection_dns_provider_combo.addItem(provider.name, provider.id)
        conn_provider_idx = self.connection_dns_provider_combo.findData(self.settings.get("connection_dns_provider", self.settings.get("selected_provider", "cloudflare")))
        if conn_provider_idx < 0:
            conn_provider_idx = self.connection_dns_provider_combo.findData(self.settings.get("selected_provider", "cloudflare"))
        self.connection_dns_provider_combo.setCurrentIndex(max(0, conn_provider_idx))
        self.connection_dns_provider_combo.currentIndexChanged.connect(self._connection_dns_provider_changed)
        provider_row.addWidget(self.connection_dns_provider_combo)
        provider_row.addStretch(1)
        hero_text.addLayout(provider_row)
        hero_layout.addLayout(hero_text, 1)

        action_column = QVBoxLayout()
        action_column.setSpacing(8)
        self.connection_status_pill = QLabel("●  READY")
        self.connection_status_pill.setObjectName("StatusPill")
        self.connection_status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_column.addWidget(self.connection_status_pill)
        self.connection_apply_button = QPushButton("Apply selected DNS  →")
        self.connection_apply_button.setObjectName("PrimaryButton")
        self.connection_apply_button.setMinimumWidth(190)
        self.connection_apply_button.clicked.connect(self._apply_connection_dns)
        action_column.addWidget(self.connection_apply_button)
        self.connection_restore_previous_button = QPushButton("Restore Previous DNS Settings")
        self.connection_restore_previous_button.setObjectName("PrimaryButton")
        self.connection_restore_previous_button.setToolTip("Restore the saved adapter DNS configuration from before Raider DNS changed it.")
        self.connection_restore_previous_button.clicked.connect(self._restore_previous_dns_settings)
        self.connection_restore_previous_button.setEnabled(False)
        action_column.addWidget(self.connection_restore_previous_button)
        restore_system_button = QPushButton("Restore automatic DNS")
        restore_system_button.clicked.connect(self._restore_automatic_dns)
        action_column.addWidget(restore_system_button)
        hero_layout.addLayout(action_column)
        self.connection_visual = ConnectionStatusVisual(hero)
        self.connection_visual.setGeometry(hero.rect().adjusted(2, 2, -2, -2))
        hero.installEventFilter(self.connection_visual)
        self.connection_visual.lower()
        self.connection_visual.set_state("idle")
        layout.addWidget(hero)

        # Provider selection is inside the hero; applying remains an explicit action.

        encryption_panel = Panel()
        encryption_layout = make_panel_layout(encryption_panel, (18, 16, 18, 17), 11)
        encryption_layout.addWidget(make_label("DNS encryption", "Heading"))
        encryption_layout.addWidget(make_label(
            "Select the transport Raider DNS can configure and test. Encrypted DNS protects name lookups; it does not tunnel general application traffic.", "Muted"
        ))
        methods_grid = QGridLayout()
        methods_grid.setContentsMargins(0, 4, 0, 0)
        methods_grid.setHorizontalSpacing(10)
        methods_grid.setVerticalSpacing(10)
        for column in range(5):
            methods_grid.setColumnStretch(column, 1)
        self.connection_method_group = QButtonGroup(self)
        self.connection_method_buttons: dict[str, QRadioButton] = {}
        self.connection_method_cards: dict[str, QFrame] = {}
        method_specs = [
            ("standard", "Standard DNS", "Uses ordinary DNS requests without transport encryption."),
            ("windows_doh", "DNS over HTTPS", "Uses Windows DNS Client DoH for the selected adapter."),
            ("browser_doh", "Browser DoH", "Configure native DoH for supported browsers only."),
            ("dot", "DNS over TLS", "Uses native Windows DoT with authenticated TLS hostname and no plaintext fallback."),
            ("dnscrypt", "DNSCrypt Proxy", "Uses the official dnscrypt-proxy engine on local loopback."),
        ]
        for index, (mode_id, title, description) in enumerate(method_specs):
            card = Panel()
            card.setMinimumHeight(108)
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            card.setProperty("connectionModeCard", "true")
            self.connection_method_cards[mode_id] = card
            card_layout = make_panel_layout(card, (13, 12, 13, 12), 7)
            radio = QRadioButton(title)
            radio.setObjectName("EncryptionChoice")
            self.connection_method_group.addButton(radio)
            radio.setProperty("connectionMethod", mode_id)
            self.connection_method_buttons[mode_id] = radio
            radio.toggled.connect(lambda checked, m=mode_id: self._connection_method_changed(m) if checked else None)
            card_layout.addWidget(radio)
            desc = make_label(description, "Muted")
            desc.setWordWrap(True)
            card_layout.addWidget(desc)
            methods_grid.addWidget(card, 0, index)
        encryption_layout.addLayout(methods_grid)
        layout.addWidget(encryption_panel)

        # DNSCrypt uses the upstream DNSCrypt Proxy engine. The Windows installer
        # can install a hash-verified engine copy; manual paths remain supported.
        self.dnscrypt_panel = Panel()
        dc_layout = make_panel_layout(self.dnscrypt_panel, (18, 16, 18, 17), 10)
        dc_layout.addWidget(make_label("DNSCrypt local proxy", "Heading"))
        dc_note = make_label(
            "The installer can include the official dnscrypt-proxy v2.1.20 engine (recommended and selected by default). If it was omitted, select the executable manually or rerun setup and add DNSCrypt Proxy. The generated configuration uses a signed resolver list, requires DNSSEC-capable no-log resolvers, enables post-quantum DNSCrypt when supported, caching and latency-aware selection, disables DoH/ODoH fallback, and leaves query logging off. UDP/TCP port 53 must be available on both 127.0.0.1 and ::1. Plain DNS bootstrap is used only for resolver-list metadata; user queries go to selected DNSCrypt resolvers.", "Muted"
        )
        dc_note.setWordWrap(True)
        dc_layout.addWidget(dc_note)
        dc_form = QGridLayout()
        dc_form.setHorizontalSpacing(8); dc_form.setVerticalSpacing(8)
        dc_form.addWidget(make_label("Resolver policy", "Muted"), 0, 0)
        self.dnscrypt_resolver_policy_label = make_label("Automatic · signed DNSCrypt resolvers with DNSSEC + no-log requirements", "Subheading")
        self.dnscrypt_resolver_policy_label.setWordWrap(True)
        dc_form.addWidget(self.dnscrypt_resolver_policy_label, 0, 1, 1, 2)
        dc_form.addWidget(make_label("dnscrypt-proxy.exe", "Muted"), 1, 0)
        self.dnscrypt_proxy_path_edit = QLineEdit(str(self.settings.get("dnscrypt_proxy_path", "")))
        self.dnscrypt_proxy_path_edit.setPlaceholderText("Installed automatically, or browse to dnscrypt-proxy.exe")
        dc_form.addWidget(self.dnscrypt_proxy_path_edit, 1, 1)
        dc_browse = QPushButton("Browse…"); dc_browse.clicked.connect(self._browse_dnscrypt_executable)
        dc_form.addWidget(dc_browse, 1, 2)
        dc_form.addWidget(make_label("Generated config", "Muted"), 2, 0)
        self.dnscrypt_config_path_edit = QLineEdit(str(self.settings.get("dnscrypt_config_path", str(DNSCryptProxyController.default_config_path()))))
        dc_form.addWidget(self.dnscrypt_config_path_edit, 2, 1)
        dc_generate = QPushButton("Generate secure config")
        dc_generate.clicked.connect(self._generate_dnscrypt_config)
        dc_form.addWidget(dc_generate, 2, 2)
        dc_layout.addLayout(dc_form)
        dc_actions = QHBoxLayout()
        self.dnscrypt_stop_button = QPushButton("Restore automatic DNS and stop proxy")
        self.dnscrypt_stop_button.clicked.connect(self._stop_dnscrypt_proxy)
        dc_actions.addWidget(self.dnscrypt_stop_button)
        dc_actions.addStretch(1)
        dc_layout.addLayout(dc_actions)
        self.dnscrypt_panel.setVisible(False)
        layout.addWidget(self.dnscrypt_panel)

        # Full application/device traffic uses an external TUN engine. It is
        # intentionally separate from the DNS-only transport modes above.
        self.traffic_tunnel_panel = Panel()
        tunnel_layout = make_panel_layout(self.traffic_tunnel_panel, (18, 16, 18, 17), 10)
        tunnel_layout.addWidget(make_label("Full Application Traffic Tunneling", "Heading"))
        tunnel_note = make_label(
            "Routes general IP traffic for the whole device through a sing-box TUN configuration, not just DNS. Requires the official sing-box executable and your own valid JSON proxy configuration with a TUN inbound (auto_route=true, strict_route=true) and a non-direct default proxy outbound. Administrator rights are required. This is not a VPN-provider service and no remote server is included. Configure DNS routing inside sing-box as well; this panel does not by itself guarantee DNS leak protection.", "Muted"
        )
        tunnel_note.setWordWrap(True)
        tunnel_layout.addWidget(tunnel_note)
        tunnel_form = QGridLayout(); tunnel_form.setHorizontalSpacing(8); tunnel_form.setVerticalSpacing(8)
        tunnel_form.addWidget(make_label("sing-box executable", "Muted"), 0, 0)
        self.singbox_path_edit = QLineEdit(str(self.settings.get("singbox_path", "")))
        self.singbox_path_edit.setPlaceholderText("Choose sing-box.exe")
        tunnel_form.addWidget(self.singbox_path_edit, 0, 1)
        singbox_browse = QPushButton("Browse…"); singbox_browse.clicked.connect(self._browse_singbox_executable)
        tunnel_form.addWidget(singbox_browse, 0, 2)
        tunnel_form.addWidget(make_label("TUN JSON config", "Muted"), 1, 0)
        self.singbox_config_path_edit = QLineEdit(str(self.settings.get("singbox_config_path", "")))
        self.singbox_config_path_edit.setPlaceholderText("Choose your sing-box config.json")
        tunnel_form.addWidget(self.singbox_config_path_edit, 1, 1)
        singbox_config_browse = QPushButton("Browse…"); singbox_config_browse.clicked.connect(self._browse_singbox_config)
        tunnel_form.addWidget(singbox_config_browse, 1, 2)
        tunnel_layout.addLayout(tunnel_form)
        self.singbox_status_label = make_label("Tunnel stopped · not connected", "Muted")
        self.singbox_status_label.setWordWrap(True)
        tunnel_layout.addWidget(self.singbox_status_label)
        tunnel_actions = QHBoxLayout()
        self.singbox_validate_button = QPushButton("Validate configuration")
        self.singbox_validate_button.clicked.connect(self._validate_singbox_config)
        self.singbox_start_button = QPushButton("Start full traffic tunnel")
        self.singbox_start_button.setObjectName("PrimaryButton")
        self.singbox_start_button.clicked.connect(self._start_singbox_tunnel)
        self.singbox_stop_button = QPushButton("Stop tunnel")
        self.singbox_stop_button.clicked.connect(self._stop_singbox_tunnel)
        tunnel_actions.addWidget(self.singbox_validate_button)
        tunnel_actions.addWidget(self.singbox_start_button)
        tunnel_actions.addWidget(self.singbox_stop_button)
        tunnel_layout.addLayout(tunnel_actions)
        layout.addWidget(self.traffic_tunnel_panel)

        scope_panel = Panel()
        scope_layout = make_panel_layout(scope_panel, (18, 16, 18, 17), 10)
        scope_header = QHBoxLayout()
        scope_header.addWidget(make_label("DNS-only scope · Inclusive / Exclusive", "Heading"), 1)
        self.dns_scope_mode_combo = QComboBox()
        self.dns_scope_mode_combo.addItem("Inclusive — selected browsers only", "inclusive")
        self.dns_scope_mode_combo.addItem("Exclusive — all except selected", "exclusive")
        scope_idx = self.dns_scope_mode_combo.findData(self.settings.get("dns_scope_mode", "inclusive"))
        self.dns_scope_mode_combo.setCurrentIndex(scope_idx if scope_idx >= 0 else 0)
        self.dns_scope_mode_combo.currentIndexChanged.connect(self._dns_scope_mode_changed)
        scope_header.addWidget(self.dns_scope_mode_combo)
        scope_layout.addLayout(scope_header)
        self.dns_scope_description = make_label(
            "Inclusive mode applies the chosen provider's DoH only to checked supported browsers. Other apps and browser DNS settings remain untouched.", "Muted"
        )
        self.dns_scope_description.setWordWrap(True)
        scope_layout.addWidget(self.dns_scope_description)
        browser_toolbar = QHBoxLayout()
        browser_toolbar.addWidget(make_label("Supported browsers", "Subheading"), 1)
        detect_browsers_button = QPushButton("Detect installed browsers")
        detect_browsers_button.clicked.connect(self._refresh_dns_scope_browsers)
        browser_toolbar.addWidget(detect_browsers_button)
        add_browser_button = QPushButton("Add browser executable…")
        add_browser_button.clicked.connect(self._add_dns_scope_browser)
        browser_toolbar.addWidget(add_browser_button)
        scope_layout.addLayout(browser_toolbar)
        self.dns_scope_browser_list = QListWidget()
        self.dns_scope_browser_list.setMinimumHeight(105)
        self.dns_scope_browser_list.setMaximumHeight(175)
        self.dns_scope_browser_list.setSpacing(2)
        self.dns_scope_browser_list.itemChanged.connect(self._dns_scope_targets_changed)
        scope_layout.addWidget(self.dns_scope_browser_list)
        scope_note = make_label(
            "Browser scope changes native DoH settings for supported browsers only. It does not intercept DNS from arbitrary Windows applications or encapsulate general traffic.", "WarningPill"
        )
        scope_note.setWordWrap(True)
        scope_layout.addWidget(scope_note)
        scope_actions = QHBoxLayout()
        self.apply_dns_scope_button = QPushButton("Apply secure DNS scope")
        self.apply_dns_scope_button.setObjectName("PrimaryButton")
        self.apply_dns_scope_button.clicked.connect(self._apply_browser_dns_scope)
        restore_browser_dns_button = QPushButton("Restore browser DNS settings")
        restore_browser_dns_button.clicked.connect(self._restore_browser_dns_scope)
        scope_actions.addWidget(self.apply_dns_scope_button)
        scope_actions.addWidget(restore_browser_dns_button)
        scope_actions.addStretch(1)
        scope_layout.addLayout(scope_actions)
        layout.addWidget(scope_panel)
        self.dns_scope_panel = scope_panel

        advanced = Panel()
        advanced_layout = make_panel_layout(advanced, (14, 12, 14, 12), 8)
        self.connection_advanced_toggle = QPushButton("Advanced settings     ▾")
        self.connection_advanced_toggle.setObjectName("AdvancedToggle")
        self.connection_advanced_toggle.setCheckable(True)
        advanced_layout.addWidget(self.connection_advanced_toggle)
        self.connection_advanced_details = QWidget()
        details_layout = QVBoxLayout(self.connection_advanced_details)
        details_layout.setContentsMargins(5, 6, 5, 4)
        details_layout.setSpacing(6)
        self.connection_details_label = make_label(
            "System DNS changes use the Windows DNS Client and may require administrator permission. Browser DoH uses supported browser-native settings and a provider HTTPS endpoint. Select a mode to reveal only its relevant controls.", "Muted"
        )
        self.connection_details_label.setWordWrap(True)
        details_layout.addWidget(self.connection_details_label)
        self.connection_advanced_details.setVisible(False)
        advanced_layout.addWidget(self.connection_advanced_details)
        self.connection_advanced_toggle.toggled.connect(self._toggle_connection_advanced)
        layout.addWidget(advanced)
        layout.addStretch(1)

        saved_mode = str(self.settings.get("connection_dns_method", "standard"))
        if saved_mode not in {"standard", "windows_doh", "browser_doh", "dot", "dnscrypt"}:
            saved_mode = "standard"
        self.connection_method_buttons[saved_mode].setChecked(True)
        self._refresh_dns_scope_browsers()
        self._dns_scope_mode_changed()
        self._connection_method_changed(saved_mode)
        self._refresh_connection_summary()
        return scroll_page(content)

    def _toggle_connection_advanced(self, expanded: bool) -> None:
        if not hasattr(self, "connection_advanced_details"):
            return
        self.connection_advanced_details.setVisible(bool(expanded))
        self.connection_advanced_toggle.setText("Advanced settings     ▴" if expanded else "Advanced settings     ▾")

    @staticmethod
    def _browser_display_name(path: str) -> str:
        kind = BrowserSecureDnsController.browser_kind(path)
        return {"firefox": "Mozilla Firefox", "chrome": "Google Chrome", "edge": "Microsoft Edge"}.get(kind, Path(path).name or "Browser")

    def _refresh_dns_scope_browsers(self, *_args: Any) -> None:
        detected = BrowserSecureDnsController.discover_supported_browsers()
        saved = self.settings.get("dns_scope_browsers", [])
        paths: list[str] = []
        seen: set[str] = set()
        for raw_path in [*(detected or []), *(saved if isinstance(saved, list) else [])]:
            if not isinstance(raw_path, str) or not raw_path.strip():
                continue
            if BrowserSecureDnsController.browser_kind(raw_path) is None:
                continue
            path = str(Path(raw_path))
            key = path.casefold()
            if key not in seen and (Path(path).is_file() or path in saved):
                seen.add(key)
                paths.append(path)
        selected = {str(path).casefold() for path in self.settings.get("dns_scope_targets", []) if isinstance(path, str)}
        self.settings["dns_scope_browsers"] = paths
        self.dns_scope_browser_list.blockSignals(True)
        self.dns_scope_browser_list.clear()
        for path in paths:
            item = QListWidgetItem(f"{self._browser_display_name(path)}  ·  {path}")
            item.setToolTip(path)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            item.setCheckState(Qt.CheckState.Checked if path.casefold() in selected else Qt.CheckState.Unchecked)
            self.dns_scope_browser_list.addItem(item)
        self.dns_scope_browser_list.blockSignals(False)
        self._save_settings()
        self._dns_scope_targets_changed()

    def _add_dns_scope_browser(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose supported browser executable", "",
            "Supported browsers (firefox.exe chrome.exe msedge.exe);;Executables (*.exe);;All files (*.*)",
        )
        if not path:
            return
        if BrowserSecureDnsController.browser_kind(path) is None:
            QMessageBox.warning(self, "Unsupported browser", "Browser scope currently supports Firefox, Google Chrome and Microsoft Edge only. Other applications do not expose a supported native DNS setting here.")
            return
        if not Path(path).is_file():
            QMessageBox.warning(self, "Browser executable not found", "Choose an existing browser executable.")
            return
        paths = list(self.settings.get("dns_scope_browsers", []))
        if not any(str(existing).casefold() == str(Path(path)).casefold() for existing in paths):
            paths.append(str(Path(path)))
            self.settings["dns_scope_browsers"] = paths
        targets = list(self.settings.get("dns_scope_targets", []))
        if not any(str(existing).casefold() == str(Path(path)).casefold() for existing in targets):
            targets.append(str(Path(path)))
        self.settings["dns_scope_targets"] = targets
        self._save_settings()
        self._refresh_dns_scope_browsers()

    def _dns_scope_targets_changed(self, *_args: Any) -> None:
        if not hasattr(self, "dns_scope_browser_list"):
            return
        checked = [
            str(self.dns_scope_browser_list.item(i).data(Qt.ItemDataRole.UserRole))
            for i in range(self.dns_scope_browser_list.count())
            if self.dns_scope_browser_list.item(i).checkState() == Qt.CheckState.Checked
        ]
        self.settings["dns_scope_targets"] = checked
        self._save_settings()
        self._refresh_connection_summary()

    def _dns_scope_mode_changed(self, *_args: Any) -> None:
        if not hasattr(self, "dns_scope_mode_combo"):
            return
        mode = str(self.dns_scope_mode_combo.currentData() or "inclusive")
        self.settings["dns_scope_mode"] = mode
        if mode == "inclusive":
            self.dns_scope_description.setText(
                "Inclusive mode applies the chosen provider's DoH only to checked supported browsers. Unchecked browsers and other apps remain untouched."
            )
        else:
            self.dns_scope_description.setText(
                "Exclusive mode applies the chosen provider's DoH to detected supported browsers except checked browsers. Excluded browsers keep their existing DNS settings."
            )
        self._save_settings()
        self._refresh_connection_summary()

    def _connection_dns_provider_changed(self, *_args: Any) -> None:
        if not hasattr(self, "connection_dns_provider_combo"):
            return
        provider_id = str(self.connection_dns_provider_combo.currentData() or self.settings.get("selected_provider", "cloudflare"))
        changed = self.settings.get("connection_dns_provider") != provider_id
        self.settings["connection_dns_provider"] = provider_id
        provider = self._provider(provider_id)
        self._save_settings()
        self._refresh_connection_summary()
        if changed and provider:
            self._log(f"Selected secure DNS provider for Connection tab: {provider.name}.")

    def _connection_method_changed(self, method: str) -> None:
        if method not in {"standard", "windows_doh", "browser_doh", "dot", "dnscrypt"}:
            return
        self.settings["connection_dns_method"] = method
        self._save_settings()
        self.dns_scope_panel.setVisible(method == "browser_doh")
        self.dnscrypt_panel.setVisible(method == "dnscrypt")
        self.connection_dns_provider_combo.setEnabled(method != "dnscrypt")
        self.connection_dns_provider_combo.setToolTip("DNSCrypt automatically selects from the signed resolver list; the provider selector applies to Standard DNS, DoH and DoT." if method == "dnscrypt" else "Choose the provider to use for this DNS transport.")
        self.connection_apply_button.setText({"browser_doh": "Apply browser DoH scope  →", "dot": "Apply DNS over TLS  →", "dnscrypt": "Start DNSCrypt and apply  →"}.get(method, "Apply selected DNS  →"))
        for card_id, card in self.connection_method_cards.items():
            card.setProperty("connectionModeCard", "selected" if card_id == method else "true")
            card.style().unpolish(card); card.style().polish(card)
        self._refresh_connection_summary()

    def _refresh_connection_summary(self) -> None:
        if not hasattr(self, "connection_status_label"):
            return
        provider = self._provider(str(self.connection_dns_provider_combo.currentData() or self.settings.get("connection_dns_provider", "cloudflare")))
        provider_name = provider.name if provider else "No provider selected"
        method = str(self.settings.get("connection_dns_method", "standard"))
        if method == "windows_doh":
            mode_description = "Windows DNS-over-HTTPS"
            eligible = bool(provider and provider.supports_doh and provider.doh_url)
        elif method == "browser_doh":
            mode_description = f"Browser DoH · {self.settings.get('dns_scope_mode', 'inclusive').title()} mode"
            eligible = bool(provider and provider.supports_doh and provider.doh_url)
        elif method == "dot":
            mode_description = "Native Windows DNS-over-TLS"
            eligible = bool(provider and provider.dot_hostname and provider.servers)
        elif method == "dnscrypt":
            mode_description = "Local DNSCrypt proxy · signed resolver catalog"
            eligible = True
        else:
            mode_description = "Standard DNS · encryption not requested"
            eligible = bool(provider)
        if method == "browser_doh":
            browsers = self.settings.get("dns_scope_browsers", [])
            checked = self.settings.get("dns_scope_targets", [])
            target_count = len([path for path in checked if path in browsers])
            effective_count = target_count if self.settings.get("dns_scope_mode") == "inclusive" else max(0, len(browsers) - target_count)
            detail = f"{mode_description} · {provider_name} · {effective_count} browser(s) in scope. Only supported browser DNS settings are changed."
        elif method == "dot":
            detail = f"{mode_description} · {provider_name}. DoT is tested with TLS certificate hostname validation before Windows configuration; UDP/TCP fallback is disabled for configured secure entries."
        elif method == "dnscrypt":
            detail = "DNSCrypt runs through the official local proxy on IPv4 and IPv6 loopback. Requires its executable and generated config; this does not force apps with their own DoH/DoT implementation to use the proxy."
        else:
            detail = f"{mode_description} · {provider_name}. Selection alone does not prove that the resolver is in use."
        self.connection_status_detail.setText(detail)
        self.connection_status_label.setText("Ready to configure" if eligible else "Provider needs configuration")
        self.connection_status_pill.setText("●  READY" if eligible else "●  CHECK PROVIDER")
        self.connection_status_pill.setObjectName("StatusPill" if eligible else "WarningPill")
        self.connection_status_pill.style().unpolish(self.connection_status_pill); self.connection_status_pill.style().polish(self.connection_status_pill)
        self.connection_apply_button.setEnabled(eligible)
        if method == "browser_doh":
            self.apply_dns_scope_button.setEnabled(eligible)

    def _apply_connection_dns(self) -> None:
        method = str(self.settings.get("connection_dns_method", "standard"))
        if method == "browser_doh":
            self._apply_browser_dns_scope(); return
        provider = self._provider(str(self.connection_dns_provider_combo.currentData() or ""))
        if method != "dnscrypt" and not provider:
            QMessageBox.warning(self, "Select a DNS provider", "Choose a DNS provider first."); return
        if method == "dot":
            if not provider or not provider.dot_hostname:
                QMessageBox.warning(self, "DoT hostname required", f"{provider.name if provider else 'The selected provider'} has no configured DoT hostname.")
                return
            self._apply_dot_connection(provider); return
        if method == "dnscrypt":
            self._apply_dnscrypt_connection(); return
        if method == "windows_doh" and (not provider or not provider.doh_url):
            QMessageBox.warning(self, "DoH endpoint required", f"{provider.name if provider else 'The selected provider'} has no configured DoH endpoint.")
            return
        self.settings["selected_provider"] = provider.id
        self.settings["dns_mode"] = "doh" if method == "windows_doh" else "standard"
        if hasattr(self, "dashboard_provider_combo"):
            self.dashboard_provider_combo.blockSignals(True); self.dashboard_provider_combo.setCurrentIndex(max(0, self.dashboard_provider_combo.findData(provider.id))); self.dashboard_provider_combo.blockSignals(False)
        if hasattr(self, "mode_combo"):
            self.mode_combo.blockSignals(True); self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData("doh" if method == "windows_doh" else "standard"))); self.mode_combo.blockSignals(False)
        self._save_settings(); self._update_provider_metrics(); self._update_provider_selection_controls(); self._apply_selected_provider()

    def _set_connection_operation_busy(self, busy: bool, status: str = "connecting") -> None:
        self._dns_operation_in_flight = bool(busy)
        for name in (
            "connection_apply_button", "apply_button", "restore_button",
            "restore_previous_button", "connection_restore_previous_button",
        ):
            button = getattr(self, name, None)
            if button is not None:
                button.setEnabled(not busy)
        if hasattr(self, "connection_visual"):
            self.connection_visual.set_state(status)
        if hasattr(self, "dns_connection_visual"):
            self.dns_connection_visual.set_state(status)
        if not busy:
            self._update_restore_previous_buttons()

    def _update_restore_previous_buttons(self) -> None:
        """Keep the recovery affordance visible but enabled only when a restore point exists."""
        adapter = str(self.adapter_combo.currentData() or "") if hasattr(self, "adapter_combo") else ""
        available = bool(adapter and self.system_dns.has_previous_settings(adapter))
        for name in ("restore_previous_button", "connection_restore_previous_button"):
            button = getattr(self, name, None)
            if button is not None:
                button.setEnabled(available and not self._dns_operation_in_flight and not self._shutdown_started)

    def _apply_dot_connection(
        self, provider: DNSProvider, *, allow_unverified_preflight: bool = False,
        already_confirmed: bool = False,
    ) -> None:
        self.settings["selected_provider"] = provider.id
        self.settings["dns_mode"] = "dot"
        self.settings["connection_dns_provider"] = provider.id
        if hasattr(self, "dashboard_provider_combo"):
            self.dashboard_provider_combo.blockSignals(True); self.dashboard_provider_combo.setCurrentIndex(max(0, self.dashboard_provider_combo.findData(provider.id))); self.dashboard_provider_combo.blockSignals(False)
        if hasattr(self, "mode_combo"):
            self.mode_combo.blockSignals(True); self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData("dot"))); self.mode_combo.blockSignals(False)
        self._save_settings(); self._update_provider_metrics()
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._offer_relaunch_admin("apply native Windows DNS-over-TLS"); return
        adapter = self.adapter_combo.currentData() if hasattr(self, "adapter_combo") else self.settings.get("selected_adapter", "")
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "Select an active adapter before applying DoT."); return
        if self.settings.get("confirm_dns_changes", True) and not already_confirmed:
            answer = QMessageBox.question(self, "Apply DNS over TLS", f"Test {provider.name} at {provider.dot_hostname}:853, then configure {adapter} to use {', '.join(provider.servers)}?\n\nThe TLS certificate hostname will be validated and UDP/TCP fallback disabled for configured secure resolver entries.", QMessageBox.StandardButton.Apply | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Apply: return
        self._set_connection_operation_busy(True)
        self.statusBar().showMessage("Testing authenticated DNS-over-TLS, then applying transactionally…")
        def operation() -> DNSOperationResult:
            return self.system_dns.apply_dot(
                str(adapter), list(provider.servers), str(provider.dot_hostname),
                bool(self.settings.get("flush_dns_after_apply", True)),
                allow_unverified_preflight=allow_unverified_preflight,
            )
        def completed(result: Any) -> None:
            if (
                isinstance(result, DNSOperationResult)
                and not result.success
                and result.message == "DNS-over-TLS preflight failed"
                and not allow_unverified_preflight
            ):
                answer = QMessageBox.question(
                    self, "DoT endpoint could not be verified",
                    f"Raider DNS could not verify an authenticated DNS-over-TLS response from {provider.name}.\n\n"
                    f"{result.details}\n\nApply the Windows DoT settings anyway? This changes adapter DNS and may leave DNS unavailable on this network. The previous settings will remain available for recovery.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Cancel,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self._apply_dot_connection(provider, allow_unverified_preflight=True, already_confirmed=True)
                    return
            self._dns_operation_finished(result, f"Applied native DoT for {provider.name}")
        self._run_background(operation, completed, lambda error: self._dns_operation_error(error))

    def _browse_dnscrypt_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose official dnscrypt-proxy executable", "", "dnscrypt-proxy.exe (dnscrypt-proxy.exe);;Executables (*.exe)")
        if path:
            self.dnscrypt_proxy_path_edit.setText(path); self.settings["dnscrypt_proxy_path"] = path; self._save_settings()

    def _generate_dnscrypt_config(self) -> None:
        try:
            path = DNSCryptProxyController.generate_config()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not generate DNSCrypt config", str(exc)); return
        self.dnscrypt_config_path_edit.setText(str(path)); self.settings["dnscrypt_config_path"] = str(path); self._save_settings()
        self.statusBar().showMessage("Generated a DNSCrypt-only config with a signed resolver list, DNSSEC, cache and no query logging.", 7000)

    def _apply_dnscrypt_connection(self) -> None:
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._offer_relaunch_admin("start DNSCrypt proxy and apply local DNS"); return
        adapter = self.adapter_combo.currentData() if hasattr(self, "adapter_combo") else self.settings.get("selected_adapter", "")
        binary_text = self.dnscrypt_proxy_path_edit.text().strip()
        config_text = self.dnscrypt_config_path_edit.text().strip()
        if not binary_text:
            QMessageBox.warning(self, "DNSCrypt Proxy unavailable", "The DNSCrypt Proxy component was not installed or its executable could not be found. Re-run Raider DNS Setup and select DNSCrypt Proxy, or browse to a trusted dnscrypt-proxy.exe.")
            return
        if not config_text or not Path(config_text).is_file():
            QMessageBox.warning(self, "Generate DNSCrypt config", "Click Generate secure config before applying DNSCrypt."); return
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "Select an active Windows adapter."); return
        if self.settings.get("confirm_dns_changes", True):
            answer = QMessageBox.question(self, "Start DNSCrypt proxy", f"Start the official DNSCrypt proxy, verify it answers DNS, then set {adapter} DNS to 127.0.0.1 and ::1?\n\nThe generated config uses a signed resolver catalog, requires DNSSEC-capable no-log DNSCrypt resolvers, enables post-quantum DNSCrypt when supported, uses latency-aware load balancing and caching, and disables DoH/ODoH fallback and query logging.", QMessageBox.StandardButton.Apply | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Apply: return
        self.settings["dnscrypt_proxy_path"] = binary_text; self.settings["dnscrypt_config_path"] = config_text
        self.settings["dns_mode"] = "dnscrypt"
        if hasattr(self, "mode_combo"):
            self.mode_combo.blockSignals(True); self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData("dnscrypt"))); self.mode_combo.blockSignals(False)
        self._save_settings(); self._update_provider_metrics()
        self._set_connection_operation_busy(True)
        self.statusBar().showMessage("Validating and starting DNSCrypt proxy…")
        def operation() -> DNSOperationResult:
            started = self.dnscrypt_controller.start(Path(binary_text), Path(config_text))
            if not started.success:
                return DNSOperationResult(False, started.message, started.details)
            applied = self.system_dns.apply_dnscrypt_loopback(str(adapter), bool(self.settings.get("flush_dns_after_apply", True)))
            if not applied.success:
                # A proxy may already be serving another adapter from a previous
                # session. Do not stop it blindly after a second adapter fails.
                current_dns = self.system_dns.get_dns_configuration()
                known_loopback_use = any(
                    str(server).strip() in {"127.0.0.1", "::1"}
                    for row in current_dns if isinstance(row, dict)
                    for server in row.get("servers", []) if isinstance(row.get("servers", []), list)
                )
                if current_dns and not known_loopback_use:
                    stop_result = self.dnscrypt_controller.stop()
                    cleanup_note = " The newly started proxy was stopped because no adapter reported a loopback DNS dependency. " + stop_result.message
                elif known_loopback_use:
                    cleanup_note = " The proxy was kept running because an adapter is already configured to use loopback DNS."
                else:
                    cleanup_note = " The proxy was kept running because current adapter DNS state could not be reliably inspected; stop it only after checking that no adapter uses loopback DNS."
                return DNSOperationResult(
                    False, applied.message, applied.details + cleanup_note,
                    verified=applied.verified, rollback_attempted=applied.rollback_attempted,
                    rollback_succeeded=applied.rollback_succeeded,
                    templates_registered=applied.templates_registered,
                )
            return DNSOperationResult(
                True, "DNSCrypt proxy configured",
                started.details + " Windows adapter now points to 127.0.0.1 and ::1. Upstream encryption is provided by DNSCrypt; separate application-managed DoH/DoT can still bypass the Windows resolver.",
                verified=applied.verified, rollback_attempted=applied.rollback_attempted,
                rollback_succeeded=applied.rollback_succeeded,
                templates_registered=applied.templates_registered,
            )
        self._run_background(operation, lambda result: self._dns_operation_finished(result, "Applied DNSCrypt through the local proxy"), lambda error: self._dns_operation_error(error))

    def _stop_dnscrypt_proxy(self) -> None:
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._offer_relaunch_admin("restore previous DNS settings and stop the local DNSCrypt proxy"); return
        adapter = self.adapter_combo.currentData() if hasattr(self, "adapter_combo") else self.settings.get("selected_adapter", "")
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "Select the adapter that was configured for DNSCrypt first."); return
        answer = QMessageBox.question(self, "Restore previous DNS and stop proxy", f"Restore the exact DNS settings saved before Raider DNS changed {adapter}, then stop Raider DNS's DNSCrypt proxy process? If no recovery point exists, the proxy will not be stopped automatically.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
        if answer != QMessageBox.StandardButton.Yes: return
        self._set_connection_operation_busy(True)
        def operation() -> DNSOperationResult:
            restored = self.system_dns.restore_previous_dns_settings(str(adapter))
            if not restored.success:
                return restored
            # Inspect every installed adapter. A different adapter may still use
            # the same local proxy; stopping it would break that adapter's DNS.
            dependency, dependency_detail = self.system_dns.has_loopback_dns_dependency()
            if dependency is not False:
                state_detail = (
                    "The proxy was kept running because an adapter still uses local loopback DNS."
                    if dependency is True else
                    "The proxy was kept running because Raider DNS could not reliably inspect all adapters."
                )
                return DNSOperationResult(
                    True,
                    "Previous DNS restored; proxy kept running",
                    restored.details + " " + dependency_detail + " " + state_detail,
                    verified=restored.verified,
                )
            stopped = self.dnscrypt_controller.stop()
            return DNSOperationResult(
                stopped.success, stopped.message, restored.details + " " + stopped.details,
                verified=bool(restored.verified is True and stopped.success),
                rollback_attempted=restored.rollback_attempted,
                rollback_succeeded=restored.rollback_succeeded,
                templates_registered=restored.templates_registered,
            )
        self._run_background(operation, lambda result: self._dns_operation_finished(result, "Restored previous DNS settings / DNSCrypt proxy cleanup"), lambda error: self._dns_operation_error(error))

    def _browse_singbox_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose official sing-box executable", "", "sing-box.exe (sing-box.exe);;Executables (*.exe)")
        if path:
            self.singbox_path_edit.setText(path); self.settings["singbox_path"] = path; self._save_settings()

    def _browse_singbox_config(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose sing-box TUN JSON configuration", "", "JSON configuration (*.json);;All files (*.*)")
        if path:
            self.singbox_config_path_edit.setText(path); self.settings["singbox_config_path"] = path; self._save_settings()

    def _singbox_paths(self) -> tuple[Path, Path] | None:
        binary = self.singbox_path_edit.text().strip(); config = self.singbox_config_path_edit.text().strip()
        if not binary or not config:
            QMessageBox.warning(self, "Tunnel configuration required", "Choose sing-box.exe and a valid sing-box JSON configuration."); return None
        self.settings["singbox_path"] = binary; self.settings["singbox_config_path"] = config; self._save_settings()
        return Path(binary), Path(config)

    def _validate_singbox_config(self) -> None:
        paths = self._singbox_paths()
        if not paths: return
        self.singbox_status_label.setText("Validating configuration…")
        self._run_background(lambda: self.singbox_controller.validate(*paths), self._singbox_result, lambda error: self._singbox_result(TunnelResult(False, "Validation failed", error)))

    def _monitor_singbox_process(self) -> None:
        """Detect an unexpected TUN-engine exit while Raider DNS remains open."""
        if self._shutdown_started or self._close_tunnel_shutdown_pending:
            return
        result = self.singbox_controller.check_for_unexpected_exit()
        if result is None:
            return
        self._singbox_monitor_timer.stop()
        self._log(result.message, "ERROR", result.details)
        self.singbox_status_label.setText("Tunnel engine exited unexpectedly · network state needs checking\n" + result.details)
        self.statusBar().showMessage("sing-box stopped unexpectedly — check Diagnostics", 15000)
        QMessageBox.warning(
            self,
            "Full traffic tunnel exited unexpectedly",
            result.message + "\n\n" + result.details
            + "\n\nRaider DNS has not removed any adapters or routes automatically. Check the physical adapter and default route in Diagnostics before starting another tunnel.",
        )

    def _start_singbox_tunnel(self) -> None:
        paths = self._singbox_paths()
        if not paths: return
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._offer_relaunch_admin("start the full application traffic tunnel"); return
        if self.settings.get("confirm_dns_changes", True):
            answer = QMessageBox.question(self, "Start full application traffic tunnel", "Start sing-box TUN and route device traffic through the selected proxy outbound? The supplied configuration controls routing and exclusions. A working remote proxy server is required.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Yes: return
        self.singbox_status_label.setText("Starting and validating tunnel…")
        self.singbox_start_button.setEnabled(False)
        self._run_background(lambda: self.singbox_controller.start(*paths), self._singbox_result, lambda error: self._singbox_result(TunnelResult(False, "Tunnel start failed", error)))

    def _stop_singbox_tunnel(self) -> None:
        if not self.singbox_controller.is_running and not self.singbox_controller.has_recovery_record:
            self.singbox_status_label.setText("Tunnel stopped · no active Raider DNS process"); return
        if self.settings.get("confirm_dns_changes", True):
            answer = QMessageBox.question(self, "Stop full traffic tunnel", "Stop sing-box and remove its TUN route? Network settings may briefly change. Continue?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Yes: return
        self._singbox_monitor_timer.stop()
        self.singbox_status_label.setText("Stopping tunnel…")
        stop_task = (
            self.singbox_controller.stop
            if self.singbox_controller.is_running
            else self.singbox_controller.recover_previous_session
        )
        self._run_background(stop_task, self._singbox_result, lambda error: self._singbox_result(TunnelResult(False, "Tunnel stop failed", error)))

    def _singbox_result(self, result: Any) -> None:
        if not isinstance(result, TunnelResult): result = TunnelResult(False, "Unexpected tunnel result", str(result))
        running = "started" in result.message.casefold() or "already running" in result.message.casefold()
        prefix = "Running · " if result.success and running else ("Validated · " if result.success else "Error · ")
        self.singbox_status_label.setText(prefix + result.message + ("\n" + result.details if result.details else ""))
        self.singbox_start_button.setEnabled(True)
        if self.singbox_controller.is_running:
            self._singbox_monitor_timer.start()
        else:
            self._singbox_monitor_timer.stop()
        self._log(f"Full traffic tunnel: {result.message}.", "INFO" if result.success else "ERROR", result.details)
        self.statusBar().showMessage(result.message, 6000)
        review_required = (
            "no adapter, route, or driver was removed" in result.details.casefold()
            or "no adapters or routes automatically" in result.details.casefold()
        )
        if not result.success or review_required:
            QMessageBox.warning(self, "Full traffic tunnel", result.message + ("\n\n" + result.details if result.details else ""))

    def _apply_browser_dns_scope(self) -> None:
        provider = self._provider(str(self.connection_dns_provider_combo.currentData() or ""))
        if not provider or not provider.doh_url:
            QMessageBox.warning(self, "DoH endpoint required", "Choose a provider with a validated HTTPS DoH endpoint.")
            return
        browsers = list(dict.fromkeys(str(path) for path in self.settings.get("dns_scope_browsers", []) if isinstance(path, str)))
        checked = [str(path) for path in self.settings.get("dns_scope_targets", []) if isinstance(path, str)]
        mode = str(self.settings.get("dns_scope_mode", "inclusive"))
        targets = BrowserSecureDnsController.resolve_scope_targets(browsers, checked, mode)
        missing = [path for path in targets if not Path(path).is_file()]
        if missing:
            QMessageBox.warning(self, "Browser not found", "One or more selected browser executables no longer exist. Detect browsers again or remove the missing entry.\n\n" + "\n".join(missing))
            return
        if not targets:
            QMessageBox.information(self, "No browsers in scope", "The current inclusive/exclusive settings produce no browser targets. Check or uncheck browser entries, or switch scope mode.")
            return
        notice = (
            f"Apply {provider.name} DNS-over-HTTPS to {len(targets)} supported browser(s) in {mode} mode?\n\n"
            "Firefox uses its default profile; Chrome and Edge use current-user policy settings. Browser restart may be required. "
            "Only DNS settings for the selected supported browsers are changed."
        )
        if self.settings.get("confirm_dns_changes", True):
            answer = QMessageBox.question(self, "Apply secure DNS scope", notice, QMessageBox.StandardButton.Apply | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Apply:
                self._log("Cancelled secure DNS scope application.", "WARNING")
                return
        try:
            BrowserSecureDnsController.validate_doh_url(provider.doh_url)
        except SecureDnsError as exc:
            QMessageBox.warning(self, "Invalid DoH endpoint", str(exc))
            return
        restore_snapshot = dict(self.settings.get("browser_dns_restore", {}))
        self.connection_apply_button.setEnabled(False)
        self.apply_dns_scope_button.setEnabled(False)
        self.connection_status_label.setText("Applying secure DNS…")
        self.connection_status_detail.setText(f"Configuring encrypted DNS for {len(targets)} browser(s).")
        self.connection_status_pill.setText("●  APPLYING")
        self.connection_status_pill.setObjectName("WarningPill")
        self.connection_status_pill.style().unpolish(self.connection_status_pill)
        self.connection_status_pill.style().polish(self.connection_status_pill)
        self.connection_visual.set_state("connecting")

        def operation() -> dict[str, Any]:
            backups = dict(restore_snapshot)
            messages: list[str] = []
            applied: list[str] = []
            errors: list[str] = []
            try:
                for browser_path in targets:
                    state, message = BrowserSecureDnsController.apply(
                        browser_path, str(provider.doh_url), provider.primary, backups.get(browser_path)
                    )
                    backups[browser_path] = state
                    applied.append(browser_path)
                    messages.append(f"{self._browser_display_name(browser_path)}: {message}")
            except (SecureDnsError, OSError, ValueError, PermissionError) as exc:
                errors.append(str(exc))
            # Restore managed browsers that are no longer in this scope so a
            # switch from inclusive to exclusive doesn't leave stale policies.
            if not errors:
                for old_path in list(backups):
                    if old_path in targets:
                        continue
                    try:
                        messages.append(f"{self._browser_display_name(old_path)}: {BrowserSecureDnsController.restore(backups[old_path])}")
                        backups.pop(old_path, None)
                    except (SecureDnsError, OSError, ValueError, PermissionError) as exc:
                        errors.append(f"{self._browser_display_name(old_path)} restore: {exc}")
            return {"backups": backups, "messages": messages, "applied": applied, "errors": errors, "provider": provider.name}

        self._run_background(operation, self._browser_dns_scope_finished, self._browser_dns_scope_failed)

    def _browser_dns_scope_finished(self, result: Any) -> None:
        self.connection_apply_button.setEnabled(True)
        self.apply_dns_scope_button.setEnabled(True)
        if not isinstance(result, dict):
            self._browser_dns_scope_failed("Secure DNS scope worker returned an invalid result.")
            return
        self.settings["browser_dns_restore"] = dict(result.get("backups", {}))
        self._save_settings()
        errors = list(result.get("errors", []))
        applied = list(result.get("applied", []))
        if errors:
            self.connection_status_label.setText("Secure DNS partly applied" if applied else "Secure DNS failed")
            self.connection_status_detail.setText("; ".join(str(error) for error in errors)[:1000])
            self.connection_status_pill.setText("●  CHECK DETAILS")
            self.connection_status_pill.setObjectName("WarningPill")
            self.connection_visual.set_state("failure")
            self._log(f"Browser secure DNS scope had errors after applying to {len(applied)} browser(s).", "ERROR", "\n".join(errors))
            QMessageBox.warning(self, "Secure DNS scope needs attention", "\n\n".join(str(error) for error in errors) + ("\n\nApplied before the error:\n" + "\n".join(applied) if applied else ""))
            return
        provider_name = str(result.get("provider", "selected provider"))
        self.connection_status_label.setText("Browser secure DNS configured")
        self.connection_status_detail.setText(f"Applied {provider_name} DoH to {len(applied)} browser(s). Restart browsers if they were running. DNS reachability is not independently verified by this configuration change.")
        self.connection_status_pill.setText("●  CONFIGURED")
        self.connection_status_pill.setObjectName("StatusPill")
        self.connection_visual.set_state("success")
        self.connection_status_pill.style().unpolish(self.connection_status_pill)
        self.connection_status_pill.style().polish(self.connection_status_pill)
        self._log(f"Applied browser-native DoH scope to {len(applied)} browser(s) using {provider_name}.")
        self._show_app_notification("Secure DNS configured", f"{provider_name} DoH was applied to {len(applied)} supported browser(s).", "success")
        if result.get("messages"):
            self.statusBar().showMessage("Browser secure DNS configured. Restart supported browsers if needed.", 6500)

    def _browser_dns_scope_failed(self, error: str) -> None:
        self.connection_apply_button.setEnabled(True)
        self.apply_dns_scope_button.setEnabled(True)
        self.connection_status_label.setText("Secure DNS failed")
        self.connection_status_detail.setText(error.splitlines()[0] if error else "The browser DNS operation failed.")
        self.connection_status_pill.setText("●  FAILED")
        self.connection_status_pill.setObjectName("ErrorPill")
        self.connection_visual.set_state("failure")
        self.connection_status_pill.style().unpolish(self.connection_status_pill)
        self.connection_status_pill.style().polish(self.connection_status_pill)
        self._log("Browser secure DNS operation failed.", "ERROR", error)
        self._show_app_notification("Secure DNS failed", self.connection_status_detail.text(), "error")

    def _restore_browser_dns_scope(self) -> None:
        backups = dict(self.settings.get("browser_dns_restore", {}))
        if not backups:
            QMessageBox.information(self, "Nothing to restore", "Raider DNS has no saved browser DNS settings to restore.")
            return
        answer = QMessageBox.question(
            self, "Restore browser DNS settings?",
            f"Restore the saved browser DNS configuration for {len(backups)} browser(s)?\n\nValues changed by another tool after Raider DNS applied them will be left untouched.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.connection_status_label.setText("Restoring browser DNS…")
        self.connection_status_pill.setText("●  RESTORING")
        self.connection_visual.set_state("connecting")
        self.apply_dns_scope_button.setEnabled(False)

        def operation() -> dict[str, Any]:
            remaining = dict(backups)
            messages: list[str] = []
            errors: list[str] = []
            for path, state in list(remaining.items()):
                try:
                    messages.append(f"{self._browser_display_name(path)}: {BrowserSecureDnsController.restore(state)}")
                    remaining.pop(path, None)
                except (SecureDnsError, OSError, ValueError, PermissionError) as exc:
                    errors.append(f"{self._browser_display_name(path)}: {exc}")
            return {"remaining": remaining, "messages": messages, "errors": errors}
        self._run_background(operation, self._browser_dns_restore_finished, self._browser_dns_scope_failed)

    def _browser_dns_restore_finished(self, result: Any) -> None:
        self.apply_dns_scope_button.setEnabled(True)
        if not isinstance(result, dict):
            self._browser_dns_scope_failed("Browser restore worker returned an invalid result.")
            return
        self.settings["browser_dns_restore"] = dict(result.get("remaining", {}))
        self._save_settings()
        errors = list(result.get("errors", []))
        if errors:
            self.connection_status_label.setText("Some browser settings remain")
            self.connection_status_detail.setText("; ".join(str(error) for error in errors)[:1000])
            self.connection_status_pill.setText("●  PARTIAL")
            self.connection_visual.set_state("failure")
            self._log("Browser DNS restoration was partial.", "WARNING", "\n".join(errors))
            QMessageBox.warning(self, "Browser DNS partially restored", "\n\n".join(errors))
        else:
            self.connection_status_label.setText("Browser DNS restored")
            self.connection_status_detail.setText("Saved browser DNS values were restored where safe. Restart browsers if they were running.")
            self.connection_status_pill.setText("●  RESTORED")
            self.connection_status_pill.setObjectName("StatusPill")
            self.connection_visual.set_state("success")
            self._log("Restored saved browser-native DNS settings.")
            self._show_app_notification("Browser DNS restored", "Saved browser DNS settings were restored where safe.", "success")
        self.connection_status_pill.style().unpolish(self.connection_status_pill)
        self.connection_status_pill.style().polish(self.connection_status_pill)

    # ---- Profiles -----------------------------------------------------------
    def _build_profiles_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        header_row = QHBoxLayout()
        header_row.addWidget(PageHeader("Saved profiles", "Store DNS configurations for home, school, work, or troubleshooting."), 1)
        add_button = QPushButton("＋  Create profile")
        add_button.setObjectName("PrimaryButton")
        add_button.clicked.connect(self._create_profile_dialog)
        header_row.addWidget(add_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)
        helper = Panel()
        helper_layout = QHBoxLayout(helper)
        helper_layout.setContentsMargins(16, 14, 16, 14)
        helper_label = make_label("Profiles are saved locally as application settings. Applying one changes only the selected adapter and may require Administrator privileges.", "Muted")
        helper_label.setWordWrap(True)
        helper_layout.addWidget(helper_label, 1)
        layout.addWidget(helper)
        self.profiles_container = QWidget()
        self.profiles_layout = QVBoxLayout(self.profiles_container)
        self.profiles_layout.setContentsMargins(0, 0, 0, 0)
        self.profiles_layout.setSpacing(10)
        self.profiles_layout.addStretch(1)
        layout.addWidget(scroll_page(self.profiles_container), 1)
        return content

    def _create_profile_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Create DNS profile")
        dialog.setMinimumWidth(460)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 18)
        layout.setSpacing(12)
        title = make_label("New DNS profile", "Heading")
        layout.addWidget(title)
        layout.addWidget(make_label("Create a reusable configuration. DNS addresses are validated before saving.", "Muted"))
        form = QFormLayout()
        form.setSpacing(11)
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("e.g. Home network")
        provider_combo = QComboBox()
        provider_combo.addItem("Custom DNS", "custom")
        for provider in self._all_providers():
            provider_combo.addItem(provider.name, provider.id)
        primary_edit = QLineEdit()
        primary_edit.setPlaceholderText("e.g. 1.1.1.1")
        secondary_edit = QLineEdit()
        secondary_edit.setPlaceholderText("e.g. 1.0.0.1 (optional)")
        form.addRow("Profile name", name_edit)
        form.addRow("Use provider", provider_combo)
        form.addRow("Primary DNS", primary_edit)
        form.addRow("Secondary DNS", secondary_edit)
        layout.addLayout(form)

        def provider_changed() -> None:
            provider_id = provider_combo.currentData()
            if provider_id == "custom":
                primary_edit.setText("")
                secondary_edit.setText("")
            else:
                provider = self._provider(str(provider_id))
                if provider:
                    primary_edit.setText(provider.primary)
                    secondary_edit.setText(provider.secondary)
        provider_combo.currentIndexChanged.connect(provider_changed)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name = name_edit.text().strip()[:80]
        primary = primary_edit.text().strip()
        secondary = secondary_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Profile name required", "Enter a name for this profile.")
            return
        servers = [item for item in (primary, secondary) if item]
        if not servers:
            QMessageBox.warning(self, "DNS address required", "Enter at least one DNS server.")
            return
        try:
            for server in servers:
                if ipaddress.ip_address(server).version != 4:
                    raise ValueError("Only IPv4 DNS addresses are supported by the current system-configuration layer.")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid DNS address", str(exc))
            return
        provider_id = provider_combo.currentData()
        provider = self._provider(str(provider_id)) if provider_id != "custom" else None
        self.settings.setdefault("profiles", []).append({
            "id": str(uuid.uuid4()), "name": name, "servers": servers,
            "provider_id": provider.id if provider else None,
            "doh_url": provider.doh_url if provider and provider.supports_doh else None,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        })
        self._save_settings()
        self._refresh_profiles()
        self._log(f"Created profile: {name}.")

    def _refresh_profiles(self) -> None:
        if not hasattr(self, "profiles_layout"):
            return
        while self.profiles_layout.count():
            item = self.profiles_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        profiles = self.settings.get("profiles", [])
        if not profiles:
            empty = Panel()
            empty_layout = make_panel_layout(empty)
            empty_layout.addWidget(make_label("No saved profiles yet", "Heading"))
            empty_layout.addWidget(make_label("Create one to save a pair of DNS addresses for later use.", "Muted"))
            self.profiles_layout.addWidget(empty)
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            card = Panel()
            row = QHBoxLayout(card)
            row.setContentsMargins(17, 13, 17, 13)
            icon = QLabel("▤")
            icon.setObjectName("Accent")
            icon.setStyleSheet("font-size:22px;")
            detail = QVBoxLayout()
            detail.setSpacing(4)
            detail.addWidget(make_label(str(profile.get("name", "Unnamed profile")), "Heading"))
            detail.addWidget(make_label("  ·  ".join(profile.get("servers", [])), "Muted"))
            provider_id = profile.get("provider_id")
            linked_provider = self._provider(str(provider_id)) if provider_id else None
            if linked_provider:
                detail.addWidget(make_label(f"Provider: {linked_provider.name}", "Muted"))
            row.addWidget(icon)
            row.addLayout(detail, 1)
            apply_button = QPushButton("Apply profile")
            apply_button.setObjectName("PrimaryButton")
            apply_button.clicked.connect(lambda checked=False, p=profile: self._apply_profile(p))
            delete_button = QPushButton("Delete")
            delete_button.setObjectName("DangerButton")
            delete_button.clicked.connect(lambda checked=False, pid=profile.get("id"): self._delete_profile(pid))
            row.addWidget(apply_button)
            row.addWidget(delete_button)
            self.profiles_layout.addWidget(card)
        self.profiles_layout.addStretch(1)

    def _delete_profile(self, profile_id: str | None) -> None:
        self.settings["profiles"] = [p for p in self.settings.get("profiles", []) if p.get("id") != profile_id]
        self._save_settings()
        self._refresh_profiles()
        self._log("Deleted a saved DNS profile.")

    def _apply_profile(self, profile: dict[str, Any]) -> None:
        servers = list(profile.get("servers", []))
        use_doh = self.settings.get("dns_mode") == "doh"
        profile_doh = profile.get("doh_url")
        primary_id = profile.get("provider_id")
        if use_doh and not profile_doh:
            QMessageBox.warning(self, "No DoH template", "This profile has no DoH template. Switch to Standard DNS or create a profile using a provider with DoH support.")
            return
        templates: dict[str, str] | None = {server: profile_doh for server in servers} if use_doh and profile_doh else None
        if self.settings.get("failover_enabled"):
            fallback = self._provider(str(self.settings.get("fallback_provider", "quad9")))
            if fallback and fallback.id != primary_id:
                if use_doh and not fallback.supports_doh:
                    QMessageBox.warning(self, "Fallback does not support DoH", f"{fallback.name} has no configured DoH template. Choose a DoH-capable fallback or switch to Standard DNS.")
                    return
                for server in fallback.servers:
                    if server not in servers:
                        servers.append(server)
                    if templates is not None and fallback.doh_url:
                        templates[server] = fallback.doh_url
        self._perform_apply(servers, templates, str(profile.get("name", "Saved profile")))

    # ---- DNS Security Center -----------------------------------------------
    def _build_security_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        layout.addWidget(PageHeader(
            "DNS Security Center",
            "Review the selected resolver, current adapter DNS configuration, encrypted-DNS mode, and optional external leak-test results. A configured mode is not proof that every app uses it.",
        ))

        actions_panel = Panel()
        actions_layout = make_panel_layout(actions_panel)
        actions_row = QHBoxLayout()
        actions_row.addWidget(make_label("Security checks", "Heading"))
        actions_row.addStretch(1)
        self.security_audit_button = QPushButton("Run DNS security audit")
        self.security_audit_button.setObjectName("PrimaryButton")
        self.security_audit_button.clicked.connect(self._run_security_audit)
        self.security_leak_button = QPushButton("Run external DNS leak test")
        self.security_leak_button.clicked.connect(self._start_security_leak_test)
        actions_row.addWidget(self.security_audit_button)
        actions_row.addWidget(self.security_leak_button)
        actions_layout.addLayout(actions_row)
        scope_note = make_label(
            "The audit queries the selected provider and reads DNS servers configured on the selected adapter. The optional leak test sends one-time DNS queries to an external testing service after a privacy confirmation.",
            "Muted",
        )
        scope_note.setWordWrap(True)
        actions_layout.addWidget(scope_note)
        layout.addWidget(actions_panel)

        grid = QGridLayout()
        grid.setSpacing(12)
        def security_card(title: str, value: str, detail: str) -> tuple[Panel, QLabel, QLabel]:
            card = Panel()
            card_layout = make_panel_layout(card, (16, 15, 16, 15), 7)
            card_layout.addWidget(make_label(title.upper(), "TinyCaps"))
            value_label = make_label(value, "Metric")
            value_label.setWordWrap(True)
            card_layout.addWidget(value_label)
            detail_label = make_label(detail, "Muted")
            detail_label.setWordWrap(True)
            card_layout.addWidget(detail_label)
            return card, value_label, detail_label

        provider_card, self.security_provider_value, self.security_provider_detail = security_card(
            "Selected resolver", "Not audited", "The selection applies to the next DNS operation; it may not match current system DNS."
        )
        transport_card, self.security_transport_value, self.security_transport_detail = security_card(
            "DNS transport", "Not audited", "Standard DNS does not imply encryption; DoH selection does not independently prove actual use."
        )
        config_card, self.security_config_value, self.security_config_detail = security_card(
            "Adapter configuration", "Not audited", "Read the DNS servers reported for the selected network adapter."
        )
        query_card, self.security_query_value, self.security_query_detail = security_card(
            "Resolver query test", "Not tested", "Run the audit to measure a fresh query or configured DoH endpoint."
        )
        grid.addWidget(provider_card, 0, 0)
        grid.addWidget(transport_card, 0, 1)
        grid.addWidget(config_card, 1, 0)
        grid.addWidget(query_card, 1, 1)
        layout.addLayout(grid)

        doh_inventory_panel = Panel()
        doh_inventory_layout = make_panel_layout(doh_inventory_panel)
        doh_inventory_layout.addWidget(make_label("Registered DoH templates", "Heading"))
        self.security_doh_templates_value = make_label("Not inspected", "Metric")
        self.security_doh_templates_detail = make_label(
            "Windows DoH template registrations are system-wide metadata and are distinct from DNS servers currently active on an adapter.", "Muted"
        )
        self.security_doh_templates_detail.setWordWrap(True)
        doh_inventory_layout.addWidget(self.security_doh_templates_value)
        doh_inventory_layout.addWidget(self.security_doh_templates_detail)
        layout.addWidget(doh_inventory_panel)

        health_panel = Panel()
        health_layout = make_panel_layout(health_panel)
        health_layout.addWidget(make_label("Automatic DNS health monitor", "Heading"))
        self.security_health_value = make_label("Not enabled", "Metric")
        self.security_health_detail = make_label(
            "Enable and configure monitoring in Settings → DNS Health Monitor. Monitoring tests the selected resolver; it does not prove every application uses it.",
            "Muted",
        )
        self.security_health_detail.setWordWrap(True)
        health_layout.addWidget(self.security_health_value)
        health_layout.addWidget(self.security_health_detail)
        layout.addWidget(health_panel)

        leak_panel = Panel()
        leak_layout = make_panel_layout(leak_panel)
        leak_layout.addWidget(make_label("External DNS leak test", "Heading"))
        self.security_leak_summary = make_label(
            "Not run. This test is optional and contacts an external service; it must not be interpreted as a universal proof of privacy.",
            "Muted",
        )
        self.security_leak_summary.setWordWrap(True)
        leak_layout.addWidget(self.security_leak_summary)
        layout.addWidget(leak_panel)
        layout.addStretch(1)
        return scroll_page(content)

    def _build_benchmark_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(15)
        layout.addWidget(PageHeader(
            "Advanced DNS Benchmark Lab",
            "Compare fresh DNS query latency and reliability across providers. Results are specific to this network and the selected query target.",
        ))

        settings_panel = Panel()
        settings_layout = make_panel_layout(settings_panel)
        settings_layout.addWidget(make_label("Test configuration", "Heading"))
        row_one = QHBoxLayout()
        row_one.addWidget(make_label("Domain", "Muted"))
        self.benchmark_domain_edit = QLineEdit("example.com")
        self.benchmark_domain_edit.setMinimumWidth(205)
        self.benchmark_domain_edit.setToolTip("Hostname to query against each DNS provider.")
        row_one.addWidget(self.benchmark_domain_edit, 1)
        row_one.addWidget(make_label("Record type", "Muted"))
        self.benchmark_qtype_combo = QComboBox()
        for name in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"):
            self.benchmark_qtype_combo.addItem(name, DNS_QUERY_TYPES[name])
        row_one.addWidget(self.benchmark_qtype_combo)
        row_one.addWidget(make_label("Samples", "Muted"))
        self.benchmark_rounds_combo = QComboBox()
        for rounds in (3, 5, 10):
            self.benchmark_rounds_combo.addItem(str(rounds), rounds)
        saved_rounds = int(self.settings.get("benchmark_rounds", 3))
        saved_round_index = self.benchmark_rounds_combo.findData(saved_rounds)
        self.benchmark_rounds_combo.setCurrentIndex(saved_round_index if saved_round_index >= 0 else 0)
        row_one.addWidget(self.benchmark_rounds_combo)
        row_one.addWidget(make_label("Timeout", "Muted"))
        self.benchmark_timeout_combo = QComboBox()
        for value, label in ((1.0, "1 second"), (2.0, "2 seconds"), (3.0, "3 seconds"), (5.0, "5 seconds")):
            self.benchmark_timeout_combo.addItem(label, value)
        row_one.addWidget(self.benchmark_timeout_combo)
        settings_layout.addLayout(row_one)

        row_two = QHBoxLayout()
        row_two.addWidget(make_label("Measurements", "Muted"))
        self.benchmark_measurement_checks: dict[str, QCheckBox] = {}
        for key, title in (("query", "DNS query latency (primary)"), ("tcp", "TCP/53 connect"), ("median", "ICMP ping")):
            check = QCheckBox(title)
            check.setChecked(key == "query")
            self.benchmark_measurement_checks[key] = check
            row_two.addWidget(check)
        row_two.addStretch(1)
        self.benchmark_run_button = QPushButton("Run advanced benchmark")
        self.benchmark_run_button.setObjectName("PrimaryButton")
        self.benchmark_run_button.clicked.connect(self._run_lab_benchmark)
        row_two.addWidget(self.benchmark_run_button)
        self.benchmark_export_button = QPushButton("Export CSV")
        self.benchmark_export_button.setEnabled(False)
        self.benchmark_export_button.clicked.connect(self._export_benchmark_results)
        row_two.addWidget(self.benchmark_export_button)
        settings_layout.addLayout(row_two)
        note = make_label(
            "The DNS query metric is the default ranking key. P95 is the nearest-rank 95th percentile; jitter is the median absolute difference between consecutive successful samples. ICMP and TCP/53 are separate connectivity measurements, not DNS query time.",
            "Muted",
        )
        note.setWordWrap(True)
        settings_layout.addWidget(note)
        layout.addWidget(settings_panel)

        summary_panel = Panel()
        summary_layout = make_panel_layout(summary_panel)
        summary_layout.addWidget(make_label("Live results", "Heading"))
        self.benchmark_summary = make_label("No advanced benchmark run yet.", "Muted")
        self.benchmark_summary.setWordWrap(True)
        summary_layout.addWidget(self.benchmark_summary)
        self.benchmark_chart = BenchmarkLatencyChart()
        summary_layout.addWidget(self.benchmark_chart)
        layout.addWidget(summary_panel)

        results_panel = Panel()
        results_layout = make_panel_layout(results_panel)
        results_layout.addWidget(make_label("Provider comparison", "Heading"))
        self.benchmark_table = QTableWidget(0, 9)
        self.benchmark_table.setHorizontalHeaderLabels(["RANK", "PROVIDER", "QUERY MEDIAN", "P95", "JITTER", "SUCCESS", "TCP/53", "ICMP", "DETAILS"])
        self.benchmark_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.benchmark_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.benchmark_table.setAlternatingRowColors(True)
        self.benchmark_table.verticalHeader().setVisible(False)
        self.benchmark_table.setWordWrap(False)
        self.benchmark_table.setMinimumHeight(280)
        header = self.benchmark_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        for column in range(2, 8):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        self.benchmark_table.verticalHeader().setDefaultSectionSize(28)
        results_layout.addWidget(self.benchmark_table)
        layout.addWidget(results_panel, 1)
        self._lab_results: list[dict[str, Any]] = []
        self._lab_pending = 0
        self._lab_total = 0
        return scroll_page(content)

    def _run_lab_benchmark(self) -> None:
        selected = tuple(key for key, box in self.benchmark_measurement_checks.items() if box.isChecked())
        if not selected:
            QMessageBox.warning(self, "Select measurements", "Choose at least one benchmark measurement.")
            return
        domain = self.benchmark_domain_edit.text().strip()
        qtype = int(self.benchmark_qtype_combo.currentData())
        try:
            build_dns_query(domain=domain, qtype=qtype)
        except (ValueError, UnicodeError) as exc:
            QMessageBox.warning(self, "Invalid query target", str(exc))
            return
        if self._lab_pending:
            self.statusBar().showMessage("An advanced benchmark is already running.", 3500)
            return
        providers = self._all_providers()
        provider_order = [item for item in self.settings.get("provider_order", []) if isinstance(item, str)]
        providers.sort(key=lambda provider: provider_order.index(provider.id) if provider.id in provider_order else len(provider_order))
        self._lab_results = []
        self._lab_pending = len(providers)
        self._lab_total = len(providers)
        self.benchmark_table.setRowCount(0)
        self.benchmark_run_button.setEnabled(False)
        self.benchmark_run_button.setText("Benchmarking…")
        self.benchmark_export_button.setEnabled(False)
        self.benchmark_summary.setText(f"Testing {domain} ({self.benchmark_qtype_combo.currentText()}) against {len(providers)} providers…")
        rounds = int(self.benchmark_rounds_combo.currentData())
        timeout = float(self.benchmark_timeout_combo.currentData())
        for checkbox in self.benchmark_measurement_checks.values():
            checkbox.setEnabled(False)
        self.benchmark_domain_edit.setEnabled(False)
        self.benchmark_qtype_combo.setEnabled(False)
        self.benchmark_rounds_combo.setEnabled(False)
        self.benchmark_timeout_combo.setEnabled(False)
        self.settings["benchmark_rounds"] = rounds
        self._save_settings()
        if not providers:
            self._finish_lab_benchmark()
            self.benchmark_summary.setText("No DNS providers are configured.")
            return
        for provider in providers:
            self._run_background(
                lambda p=provider, metrics=selected, r=rounds, t=timeout, d=domain, qt=qtype: benchmark_provider_metrics(
                    p, rounds=r, timeout=t, measurements=metrics, domain=d, query_type=qt
                ),
                self._lab_probe_finished,
                lambda error, pid=provider.id: self._lab_probe_failed(pid, error),
            )

    def _lab_probe_finished(self, result: Any) -> None:
        if isinstance(result, dict):
            self._lab_results.append(result)
        self._lab_probe_complete()

    def _lab_probe_failed(self, provider_id: str, error: str) -> None:
        provider = self._provider(provider_id)
        self._lab_results.append({
            "provider_id": provider_id,
            "provider_name": provider.name if provider else provider_id,
            "rounds": int(self.benchmark_rounds_combo.currentData()),
            "measurements": [key for key, box in self.benchmark_measurement_checks.items() if box.isChecked()],
            "median_ms": None, "tcp_median_ms": None, "query_median_ms": None,
            "query_min_ms": None, "query_max_ms": None, "query_p95_ms": None, "query_jitter_ms": None,
            "query_success_rate": 0.0, "query_successes": 0,
            "message": error.splitlines()[0] if error else "Unexpected benchmark error",
        })
        self._lab_probe_complete()

    def _lab_probe_complete(self) -> None:
        self._lab_pending = max(0, self._lab_pending - 1)
        if self._lab_pending:
            ranked = rank_benchmark_results(self._lab_results, metric="query", ascending=True)
            self._lab_ranked_results = ranked
            self._render_lab_results()
            self.benchmark_chart.set_results(ranked, self.settings.get("theme", "dark"))
            self.benchmark_summary.setText(f"Finished {len(self._lab_results)} of {self._lab_total} provider tests… · partial results are fresh measurements")
            return
        self._finish_lab_benchmark()

    def _finish_lab_benchmark(self) -> None:
        self._lab_pending = 0
        self.benchmark_run_button.setEnabled(True)
        self.benchmark_run_button.setText("Run advanced benchmark")
        self.benchmark_export_button.setEnabled(bool(self._lab_results))
        for checkbox in self.benchmark_measurement_checks.values():
            checkbox.setEnabled(True)
        for widget in (self.benchmark_domain_edit, self.benchmark_qtype_combo, self.benchmark_rounds_combo, self.benchmark_timeout_combo):
            widget.setEnabled(True)
        ranked = rank_benchmark_results(self._lab_results, metric="query", ascending=True)
        self._lab_ranked_results = ranked
        self._render_lab_results()
        measured = [row for row in ranked if row.get("query_median_ms") is not None]
        if measured:
            winner = measured[0]
            self.benchmark_summary.setText(
                f"Fastest measured DNS query: {winner.get('provider_name')} at {winner.get('query_median_ms')} ms · "
                f"success rate {winner.get('query_success_rate', 0)}% · P95 {winner.get('query_p95_ms') if winner.get('query_p95_ms') is not None else 'n/a'} ms · "
                f"jitter {winner.get('query_jitter_ms') if winner.get('query_jitter_ms') is not None else 'n/a'} ms. "
                f"Target: {self.benchmark_domain_edit.text().strip()} ({self.benchmark_qtype_combo.currentText()})."
            )
        else:
            self.benchmark_summary.setText("No provider returned a successful DNS query for this run. Review timeout/network conditions; cached latency values were not used.")
        self.benchmark_chart.set_results(ranked, self.settings.get("theme", "dark"))
        self._log(f"Advanced DNS benchmark completed for {self.benchmark_domain_edit.text().strip()} ({self.benchmark_qtype_combo.currentText()}): {len(measured)} providers returned successful DNS queries.")

    def _render_lab_results(self) -> None:
        ranked = getattr(self, "_lab_ranked_results", self._lab_results)
        self.benchmark_table.setUpdatesEnabled(False)
        self.benchmark_table.setRowCount(0)
        for rank, row in enumerate(ranked, 1):
            values = (
                str(rank), str(row.get("provider_name", "Unknown")),
                f"{row['query_median_ms']} ms" if row.get("query_median_ms") is not None else "—",
                f"{row['query_p95_ms']} ms" if row.get("query_p95_ms") is not None else "—",
                f"{row['query_jitter_ms']} ms" if row.get("query_jitter_ms") is not None else "—",
                f"{row.get('query_success_rate', 0)}%",
                f"{row['tcp_median_ms']} ms" if row.get("tcp_median_ms") is not None else "—",
                f"{row['median_ms']} ms" if row.get("median_ms") is not None else "—",
                str(row.get("message", ""))[:180],
            )
            row_index = self.benchmark_table.rowCount()
            self.benchmark_table.insertRow(row_index)
            for column, value in enumerate(values):
                self.benchmark_table.setItem(row_index, column, QTableWidgetItem(value))
        self.benchmark_table.setUpdatesEnabled(True)

    def _export_benchmark_results(self) -> None:
        if not self._lab_results:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export DNS benchmark results", "raider_dns_benchmark.csv", "CSV files (*.csv)")
        if not path:
            return
        fields = ("provider_name", "query_domain", "query_type", "rounds", "query_median_ms", "query_min_ms", "query_max_ms", "query_p95_ms", "query_jitter_ms", "query_success_rate", "tcp_median_ms", "median_ms", "message")
        try:
            with Path(path).open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(self._lab_ranked_results if hasattr(self, "_lab_ranked_results") else self._lab_results)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            self._log("Benchmark CSV export failed.", "ERROR", str(exc))
            return
        self._log("Exported advanced DNS benchmark results as CSV.")
        self.statusBar().showMessage("Benchmark results exported.", 3500)

    def _run_security_audit(self) -> None:
        provider = self._selected_provider()
        if provider is None:
            self.security_query_value.setText("No provider")
            return
        self.security_audit_button.setEnabled(False)
        self.security_audit_button.setText("Auditing…")
        mode = str(self.settings.get("dns_mode", "standard"))
        adapter = str(self.settings.get("selected_adapter", ""))
        timeout = float(self.settings.get("health_timeout_seconds", 2.5))
        self._run_background(
            lambda p=provider, m=mode, a=adapter, t=timeout: {
                "provider_id": p.id,
                "provider_name": p.name,
                "servers": list(p.servers),
                "mode": m,
                "adapter": a,
                "dns_rows": self.system_dns.get_dns_configuration(),
                "probe": self._probe_selected_transport(p, m, t).to_dict(),
            },
            self._security_audit_finished,
            self._security_audit_failed,
        )

    def _security_audit_finished(self, result: Any) -> None:
        self.security_audit_button.setEnabled(True)
        self.security_audit_button.setText("Run DNS security audit")
        if not isinstance(result, dict):
            self._security_audit_failed("The security audit returned an unexpected result.")
            return
        provider_name = str(result.get("provider_name", "Selected resolver"))
        self.security_provider_value.setText(provider_name)
        self.security_provider_detail.setText(f"Addresses tested: {', '.join(result.get('servers', [])) or 'none'} · this is the selected provider, not proof it is currently active for all applications.")
        if result.get("mode") == "doh":
            probe_protocol = str((result.get("probe") or {}).get("protocol", ""))
            if probe_protocol == "DNS-over-HTTPS":
                self.security_transport_value.setText("DoH selected")
                self.security_transport_detail.setText("The configured HTTPS endpoint was probed. This does not verify that all system or app traffic used DoH.")
            else:
                self.security_transport_value.setText("DoH unavailable")
                self.security_transport_detail.setText("The selected provider has no configured DoH endpoint; a standard UDP DNS query was used for reachability instead.")
        else:
            self.security_transport_value.setText("Standard DNS")
            self.security_transport_detail.setText("A standard UDP DNS query was tested. Transport encryption is not implied.")
        rows = result.get("dns_rows", [])
        adapter = str(result.get("adapter", ""))
        configured = sorted({
            str(server)
            for row in rows if isinstance(row, dict) and str(row.get("adapter", "")) == adapter
            for server in (row.get("servers", []) if isinstance(row.get("servers", []), (list, tuple)) else [])
            if str(server).strip()
        }) if isinstance(rows, list) else []
        provider_servers = set(result.get("servers", []))
        if not adapter:
            self.security_config_value.setText("No adapter selected")
            self.security_config_detail.setText("Choose an active adapter before interpreting system DNS configuration.")
        elif not configured:
            self.security_config_value.setText("Not available")
            self.security_config_detail.setText(f"No DNS server addresses were returned for {adapter}.")
        elif provider_servers and provider_servers.issubset(set(configured)):
            self.security_config_value.setText("Selected addresses present")
            self.security_config_detail.setText(f"{adapter}: {', '.join(configured)} includes the selected provider addresses. Additional configured DNS servers may affect IPv4/IPv6 behavior; this is not a per-application traffic test.")
        else:
            self.security_config_value.setText("Different from selection")
            self.security_config_detail.setText(f"Configured on {adapter}: {', '.join(configured)}. {provider_name} is only the selected provider until applied.")
        probe = result.get("probe", {})
        if isinstance(probe, dict) and probe.get("success"):
            latency = probe.get("latency_ms")
            self.security_query_value.setText("Responding" if latency is None else f"{latency} ms")
            self.security_query_detail.setText(f"{probe.get('protocol', 'DNS query')}: {probe.get('message', 'response received')} · newly measured for this audit.")
        else:
            self.security_query_value.setText("No response")
            self.security_query_detail.setText(str(probe.get("message", "The resolver probe failed.")) if isinstance(probe, dict) else "The probe returned no usable result.")
        self._refresh_security_snapshot()
        self._log(f"DNS security audit completed for {provider_name}.")
        self._show_app_notification("DNS security audit completed", f"Checked {provider_name}; review the configuration and query results.", "success" if isinstance(probe, dict) and probe.get("success") else "warning")

    def _security_audit_failed(self, error: str) -> None:
        self.security_audit_button.setEnabled(True)
        self.security_audit_button.setText("Run DNS security audit")
        detail = error.splitlines()[0] if error else "Unknown error"
        self.security_query_value.setText("Audit failed")
        self.security_query_detail.setText(detail)
        self._log("DNS security audit failed.", "ERROR", detail)
        self._show_app_notification("DNS security audit failed", detail, "error")

    def _start_security_leak_test(self) -> None:
        disclosure = (
            "This optional test contacts an external DNS leak testing service. It sends one-time test hostnames and the service may observe "
            "the public IP/network metadata of the test connection. Its published API says test results are held in memory for up to ten minutes.\n\n"
            "This checks the resolver path used by system DNS lookups; it does not inspect browser-specific DoH. Continue and send the test queries?"
        )
        consent = QMessageBox.question(
            self, "External DNS leak test — privacy notice", disclosure,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if consent != QMessageBox.StandardButton.Yes:
            return
        self.security_leak_button.setEnabled(False)
        self.security_leak_button.setText("Testing…")
        self.security_leak_summary.setText("Sending one-time test queries and waiting for the external service's result…")
        self._run_background(run_external_dns_leak_test, self._security_leak_test_finished, self._security_leak_test_failed)

    def _security_leak_test_finished(self, result: Any) -> None:
        self.security_leak_button.setEnabled(True)
        self.security_leak_button.setText("Run external DNS leak test")
        if not isinstance(result, dict):
            self._security_leak_test_failed("The external service returned an unexpected result.")
            return
        status = str(result.get("status", "inconclusive"))
        labels = {
            "no_leak": "No split-resolver leak detected by the service",
            "split": "Split resolver detected — review the result",
            "leak": "Potential leak reported — review the result",
            "inconclusive": "Inconclusive — no definitive verdict",
        }
        self.security_leak_summary.setText(
            f"{labels.get(status, labels['inconclusive'])}. {result.get('detail', '')} "
            f"Observed lookups: {result.get('lookups_seen', 0)} of {result.get('hostnames_attempted', 0)} · "
            f"{result.get('elapsed_seconds', '?')} seconds. This is evidence from one test session, not a universal guarantee."
        )
        self._log(f"DNS Security Center external leak test completed: {status}.")
        self._show_app_notification("DNS leak test finished", labels.get(status, labels["inconclusive"]), "warning" if status in {"leak", "split", "inconclusive"} else "success")

    def _security_leak_test_failed(self, error: str) -> None:
        self.security_leak_button.setEnabled(True)
        self.security_leak_button.setText("Run external DNS leak test")
        detail = error.splitlines()[0] if error else "Unknown error"
        self.security_leak_summary.setText(f"Test failed: {detail}. A failed test is not evidence that DNS is leak-free.")
        self._log("DNS Security Center external leak test failed.", "ERROR", detail)
        self._show_app_notification("DNS leak test failed", detail, "error")

    def _refresh_security_snapshot(self) -> None:
        if not hasattr(self, "security_health_value"):
            return
        self._refresh_doh_registration_inventory()
        if not self.settings.get("health_monitor_enabled", False):
            self.security_health_value.setText("Not enabled")
            self.security_health_detail.setText("Enable monitoring in Settings → DNS Health Monitor to receive automatic checks and notifications.")
            return
        state = self._health_state_tracker.state
        result = self._health_last_result or {}
        labels = {"unknown": "Waiting for first check", "healthy": "Healthy", "unhealthy": "Unhealthy"}
        self.security_health_value.setText(labels.get(state, "Unknown"))
        provider = self._selected_provider()
        provider_name = provider.name if provider else "Selected provider"
        self.security_health_detail.setText(
            f"Monitoring {provider_name} every {self.settings.get('health_interval_seconds', 30)} seconds; "
            f"timeout {self.settings.get('health_timeout_seconds', 2.5)} s. "
            f"Last result: {result.get('message', 'No completed check yet')}"
        )

    def _refresh_doh_registration_inventory(self, force: bool = False) -> None:
        """Read system-wide DoH template registration separately from active adapters."""
        import time
        if not hasattr(self, "security_doh_templates_value") or self._doh_inventory_in_flight:
            return
        now = time.monotonic()
        if not force and now - self._doh_inventory_last_refresh < 15.0:
            return
        self._doh_inventory_in_flight = True
        self._doh_inventory_last_refresh = now
        self.security_doh_templates_value.setText("Inspecting Windows registration…")
        self._run_background(
            self.system_dns.get_doh_template_registrations,
            self._doh_registration_inventory_loaded,
            self._doh_registration_inventory_failed,
        )

    def _doh_registration_inventory_loaded(self, result: Any) -> None:
        self._doh_inventory_in_flight = False
        if not hasattr(self, "security_doh_templates_value") or not isinstance(result, dict):
            return
        if not result.get("supported"):
            self.security_doh_templates_value.setText("Not available")
            self.security_doh_templates_detail.setText(str(result.get("detail") or "Windows DoH template inventory is unavailable on this system."))
            return
        entries = result.get("entries", [])
        entries = entries if isinstance(entries, list) else []
        self.security_doh_templates_value.setText(f"{len(entries)} registered template{'s' if len(entries) != 1 else ''}")
        if not entries:
            detail = "No explicit DoH templates are registered. This does not by itself indicate whether ordinary DNS is encrypted by another mechanism."
        else:
            lines = [
                f"{row.get('server', '?')} → {row.get('template', '(empty)')} · auto-upgrade={'on' if row.get('auto_upgrade') else 'off'} · plaintext fallback={'on' if row.get('fallback') else 'off'}"
                for row in entries[:8] if isinstance(row, dict)
            ]
            if len(entries) > 8:
                lines.append(f"… and {len(entries) - 8} more")
            detail = "\n".join(lines) + "\n\nThese are registered resolver templates, not proof that the selected adapter currently uses them."
        self.security_doh_templates_detail.setText(detail)

    def _doh_registration_inventory_failed(self, error: str) -> None:
        self._doh_inventory_in_flight = False
        if hasattr(self, "security_doh_templates_value"):
            self.security_doh_templates_value.setText("Inspection failed")
            self.security_doh_templates_detail.setText(error.splitlines()[0] if error else "Windows DoH template inspection failed.")

    # ---- Diagnostics --------------------------------------------------------
    def _build_diagnostics_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        layout.addWidget(PageHeader(
            "Network diagnostics",
            "Test connectivity first, review evidence-based repair suggestions, then choose any manual fixes deliberately.",
        ))

        # 1. Full read-only connectivity pass. All probes execute in a background
        # worker and include adapter/device state, gateway, IPs, ports, DNS and HTTPS.
        connectivity = Panel()
        connectivity_layout = make_panel_layout(connectivity)
        connectivity_header = QHBoxLayout()
        connectivity_header.addWidget(make_label("1. Connectivity test", "Heading"))
        connectivity_header.addStretch(1)
        self.connectivity_run_button = QPushButton("Run full connectivity test")
        self.connectivity_run_button.setObjectName("PrimaryButton")
        self.connectivity_run_button.clicked.connect(self._run_full_connectivity_test)
        connectivity_header.addWidget(self.connectivity_run_button)
        connectivity_layout.addLayout(connectivity_header)
        connectivity_note = make_label(
            "Read-only checks: adapter and driver state, default gateway, internal/external ping, TCP ports, system DNS resolution and HTTPS/TLS. A failed ping alone does not prove the internet is down.",
            "Muted",
        )
        connectivity_note.setWordWrap(True)
        connectivity_layout.addWidget(connectivity_note)
        self.connectivity_summary = make_label("No full connectivity test has run in this session.", "Muted")
        self.connectivity_summary.setWordWrap(True)
        connectivity_layout.addWidget(self.connectivity_summary)
        self.connectivity_table = QTableWidget(0, 4)
        self.connectivity_table.setHorizontalHeaderLabels(["CHECK", "RESULT", "MEASUREMENT", "DETAILS"])
        self.connectivity_table.setAlternatingRowColors(True)
        self.connectivity_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.connectivity_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.connectivity_table.setWordWrap(True)
        self.connectivity_table.verticalHeader().setVisible(False)
        self.connectivity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.connectivity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.connectivity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.connectivity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.connectivity_table.setMinimumHeight(240)
        connectivity_layout.addWidget(self.connectivity_table)
        layout.addWidget(connectivity)

        # 2. Suggested repairs are derived from the most recent connectivity report.
        suggestions = Panel()
        suggestions_layout = make_panel_layout(suggestions)
        suggestions_header = QHBoxLayout()
        suggestions_header.addWidget(make_label("2. Suggested troubleshooting", "Heading"))
        suggestions_header.addStretch(1)
        self.auto_repair_button = QPushButton("Run suggested repair")
        self.auto_repair_button.setObjectName("PrimaryButton")
        self.auto_repair_button.setEnabled(False)
        self.auto_repair_button.clicked.connect(self._run_suggested_network_repair)
        suggestions_header.addWidget(self.auto_repair_button)
        suggestions_layout.addLayout(suggestions_header)
        self.troubleshooting_summary = make_label(
            "Run the full connectivity test first. Raider DNS will suggest only repairs supported by the observed results.",
            "Muted",
        )
        self.troubleshooting_summary.setWordWrap(True)
        suggestions_layout.addWidget(self.troubleshooting_summary)
        suggestions_note = make_label(
            "Automatic suggestions are deliberately limited to lower-impact actions such as flushing DNS cache or renewing DHCP when the test indicates an addressing problem. Driver resets/reinstalls and Winsock/TCP-IP resets are never run automatically.",
            "Muted",
        )
        suggestions_note.setWordWrap(True)
        suggestions_layout.addWidget(suggestions_note)
        layout.addWidget(suggestions)

        # 3. Selectable manual repairs. DNS flush is available here as a checkbox,
        # not as a separate Diagnostics button. All actions default to unchecked.
        maintenance = Panel()
        maintenance_layout = make_panel_layout(maintenance)
        maintenance_layout.addWidget(make_label("3. Selective manual repairs", "Heading"))
        maintenance_note = make_label(
            "Select only the steps you want. DHCP release/renew may disconnect you; Winsock and IP stack resets can require a restart; resetting WinHTTP removes its configured proxy. These operations are not undoable in every environment.",
            "Muted",
        )
        maintenance_note.setWordWrap(True)
        maintenance_layout.addWidget(maintenance_note)
        self.repair_checks: dict[str, QCheckBox] = {}
        repair_grid = QGridLayout()
        repair_items = [
            ("flush_dns", "Flush DNS cache", False),
            ("register_dns", "Register DNS records", False),
            ("clear_arp_cache", "Clear ARP cache", False),
            ("renew_ip", "Renew DHCP lease", False),
            ("release_ip", "Release DHCP lease", False),
            ("winsock_reset", "Reset Winsock catalog", False),
            ("tcpip_reset", "Reset IPv4 TCP/IP stack", False),
            ("ipv6_reset", "Reset IPv6 stack", False),
            ("reset_proxy", "Reset WinHTTP proxy to direct", False),
        ]
        for index, (key, title, checked) in enumerate(repair_items):
            check = QCheckBox(title)
            check.setChecked(checked)
            self.repair_checks[key] = check
            repair_grid.addWidget(check, index // 3, index % 3)
        maintenance_layout.addLayout(repair_grid)
        selection_row = QHBoxLayout()
        select_all = QPushButton("Select all")
        select_all.clicked.connect(lambda: self._set_repair_selection(True))
        select_none = QPushButton("Clear selection")
        select_none.clicked.connect(lambda: self._set_repair_selection(False))
        selection_row.addWidget(select_all)
        selection_row.addWidget(select_none)
        self.repair_selection_buttons = [select_all, select_none]
        selection_row.addStretch(1)
        self.repair_button = QPushButton("Run selected repair steps")
        self.repair_button.setObjectName("PrimaryButton")
        self.repair_button.clicked.connect(self._run_network_repair)
        selection_row.addWidget(self.repair_button)
        maintenance_layout.addLayout(selection_row)
        layout.addWidget(maintenance)

        # 4. Configuration inventory remains separate from connectivity behavior.
        audit = Panel()
        audit_layout = make_panel_layout(audit)
        audit_title_row = QHBoxLayout()
        audit_title_row.addWidget(make_label("DNS configuration audit", "Heading"))
        audit_title_row.addStretch(1)
        inspect_button = QPushButton("Refresh system DNS")
        inspect_button.clicked.connect(self._refresh_system_state)
        audit_title_row.addWidget(inspect_button)
        audit_layout.addLayout(audit_title_row)
        self.audit_text = make_label("System DNS configuration has not been checked yet.", "Muted")
        self.audit_text.setWordWrap(True)
        audit_layout.addWidget(self.audit_text)
        audit_note = make_label(
            "This reads DNS servers configured on Windows adapters and registered DoH templates separately. It does not claim to identify every application's private resolver.",
            "Muted",
        )
        audit_note.setWordWrap(True)
        audit_layout.addWidget(audit_note)
        layout.addWidget(audit)

        leak_panel = Panel()
        leak_layout = make_panel_layout(leak_panel)
        leak_header = QHBoxLayout()
        leak_header.addWidget(make_label("External DNS leak test", "Heading"))
        leak_header.addStretch(1)
        self.leak_test_button = QPushButton("Run external test")
        self.leak_test_button.setObjectName("PrimaryButton")
        self.leak_test_button.clicked.connect(self._start_leak_test)
        leak_header.addWidget(self.leak_test_button)
        leak_layout.addLayout(leak_header)
        self.leak_test_summary = make_label(
            "Optional third-party test. It observes which recursive DNS resolvers handle one-time test hostnames.", "Muted"
        )
        self.leak_test_summary.setWordWrap(True)
        leak_layout.addWidget(self.leak_test_summary)
        self.leak_test_resolvers = make_label("No external leak test has been run in this session.", "Muted")
        self.leak_test_resolvers.setWordWrap(True)
        leak_layout.addWidget(self.leak_test_resolvers)
        layout.addWidget(leak_panel)

        probe_panel = Panel()
        probe_layout = make_panel_layout(probe_panel)
        button_row = QHBoxLayout()
        button_row.addWidget(make_label("Resolver reachability", "Heading"))
        button_row.addStretch(1)
        self.probe_protocol_combo = QComboBox()
        self.probe_protocol_combo.addItem("Automatic (DoH when available)", "auto")
        self.probe_protocol_combo.addItem("ICMP ping", "icmp")
        self.probe_protocol_combo.addItem("TCP / 53 connection", "tcp")
        self.probe_protocol_combo.addItem("Actual DNS query (UDP / 53)", "udp")
        self.probe_protocol_combo.addItem("DNS-over-HTTPS", "doh")
        self.probe_protocol_combo.addItem("DNS-over-TLS", "dot")
        self.probe_protocol_combo.setMinimumWidth(235)
        button_row.addWidget(self.probe_protocol_combo)
        self.probe_button = QPushButton("Run all tests")
        self.probe_button.setObjectName("PrimaryButton")
        self.probe_button.clicked.connect(self._run_all_probes)
        button_row.addWidget(self.probe_button)
        probe_layout.addLayout(button_row)
        self.probe_progress = QLabel("No diagnostic run yet.")
        self.probe_progress.setObjectName("Muted")
        probe_layout.addWidget(self.probe_progress)
        self.probe_table = QTableWidget(0, 5)
        self.probe_table.setHorizontalHeaderLabels(["PROVIDER", "PROTOCOL", "STATUS", "LATENCY", "DETAILS"])
        self.probe_table.setAlternatingRowColors(True)
        self.probe_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.probe_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.probe_table.verticalHeader().setVisible(False)
        self.probe_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.probe_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.probe_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.probe_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.probe_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.probe_table.setMinimumHeight(320)
        probe_layout.addWidget(self.probe_table)
        layout.addWidget(probe_panel, 1)
        self._last_connectivity_report: dict[str, Any] | None = None
        self._suggested_repairs: list[str] = []
        self._connectivity_job_running = False
        return scroll_page(content)

    def _set_repair_selection(self, selected: bool) -> None:
        for checkbox in self.repair_checks.values():
            checkbox.setChecked(selected)

    def _run_full_connectivity_test(self) -> None:
        if getattr(self, "_connectivity_job_running", False):
            self.statusBar().showMessage("A full connectivity test is already running.", 3500)
            return
        adapter = str(self.adapter_combo.currentData() or self.settings.get("selected_adapter", ""))
        self._connectivity_job_running = True
        self.connectivity_run_button.setEnabled(False)
        self.connectivity_run_button.setText("Testing connectivity…")
        self.connectivity_summary.setText("Checking adapter/driver state, gateway, ping, ports, DNS and HTTPS…")
        self._run_background(
            lambda name=adapter: run_connectivity_checks(name),
            self._connectivity_test_finished,
            self._connectivity_test_failed,
        )

    def _connectivity_test_finished(self, report: Any) -> None:
        self._connectivity_job_running = False
        self.connectivity_run_button.setEnabled(True)
        self.connectivity_run_button.setText("Run full connectivity test")
        if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
            self._connectivity_test_failed("Connectivity diagnostics returned an invalid report.")
            return
        self._last_connectivity_report = report
        rows = [row for row in report["checks"] if isinstance(row, dict)]
        self.connectivity_table.setUpdatesEnabled(False)
        self.connectivity_table.setRowCount(len(rows))
        status_colors = {"PASS": QColor("#38d996"), "FAIL": QColor("#ff647c"), "WARN": QColor("#ffbf69"), "SKIP": QColor("#93a4bd")}
        for index, row in enumerate(rows):
            values = [str(row.get("title", "Check")), str(row.get("status", "WARN")), str(row.get("measurement", "")), str(row.get("details", ""))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 1:
                    item.setForeground(QBrush(status_colors.get(value, QColor("#93a4bd"))))
                if column == 3 and len(value) > 180:
                    item.setText(value[:177] + "…")
                self.connectivity_table.setItem(index, column, item)
        self.connectivity_table.setUpdatesEnabled(True)
        summary = report.get("summary", {})
        self.connectivity_summary.setText(
            f"Adapter: {report.get('adapter', 'Unknown')} ({report.get('adapter_status', 'Unknown')}) · "
            f"{summary.get('passed', 0)} passed · {summary.get('failed', 0)} failed · "
            f"{summary.get('warnings', 0)} warnings · Checked {report.get('checked_at', 'just now')}"
        )
        self._suggested_repairs = suggest_repairs(report)
        names = {key: title for key, title, _ in [
            ("flush_dns", "Flush DNS cache", False), ("renew_ip", "Renew DHCP lease", False),
            ("release_ip", "Release DHCP lease", False),
        ]}
        if self._suggested_repairs:
            human = [names.get(key, key.replace("_", " ")) for key in self._suggested_repairs]
            self.troubleshooting_summary.setText(
                "Suggested based on this test: " + ", ".join(human) + ". Review the explanation above and confirm before applying."
            )
            self.auto_repair_button.setEnabled(True)
        else:
            driver_issue = next((row for row in rows if row.get("id") == "driver_state" and row.get("status") == "FAIL"), None)
            if driver_issue:
                self.troubleshooting_summary.setText(
                    "Windows reported a network-device/driver problem. Raider DNS will not reset or reinstall drivers automatically because that can disable connectivity. Review the driver details in the table and use Windows Device Manager or the PC manufacturer's supported driver utility."
                )
            elif summary.get("failed", 0) or summary.get("warnings", 0):
                self.troubleshooting_summary.setText(
                    "Issues or warnings were detected, but no low-risk automatic repair was confidently supported by these results. Review the failed checks and choose a targeted manual repair if appropriate. A failed ping alone is not proof the connection is down."
                )
            else:
                self.troubleshooting_summary.setText("No low-risk repair is currently suggested by this test. Keep this report as a baseline.")
            self.auto_repair_button.setEnabled(False)
        self._log(
            f"Connectivity test completed: {summary.get('passed', 0)} passed, {summary.get('failed', 0)} failed, {summary.get('warnings', 0)} warnings.",
            "WARNING" if summary.get("failed", 0) else "INFO",
        )
        self.statusBar().showMessage("Full connectivity test completed.", 5000)

    def _connectivity_test_failed(self, error: str) -> None:
        self._connectivity_job_running = False
        if hasattr(self, "connectivity_run_button"):
            self.connectivity_run_button.setEnabled(True)
            self.connectivity_run_button.setText("Run full connectivity test")
        detail = (error.splitlines()[0] if error else "Unknown error")[:300]
        if hasattr(self, "connectivity_summary"):
            self.connectivity_summary.setText("Connectivity test could not complete: " + detail)
        self._log("Full connectivity test failed.", "ERROR", detail)

    def _run_suggested_network_repair(self) -> None:
        recommendations = list(getattr(self, "_suggested_repairs", []))
        if not recommendations or not isinstance(self._last_connectivity_report, dict):
            QMessageBox.information(self, "Run diagnostics first", "Run a full connectivity test before applying suggested repairs.")
            return
        names = {"flush_dns": "Flush DNS cache", "renew_ip": "Renew DHCP lease"}
        readable = ", ".join(names.get(key, key) for key in recommendations)
        warning = (
            f"Latest connectivity evidence suggests: {readable}.\n\n"
            "This operation may temporarily interrupt networking. Raider DNS will not reset network stacks or drivers automatically. Continue?"
        )
        answer = QMessageBox.warning(
            self, "Confirm suggested repair", warning,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._log("Cancelled suggested repair.")
            return
        if not self.system_dns.is_windows():
            QMessageBox.warning(self, "Windows only", "Network repair commands are supported on Windows only.")
            return
        if not self.system_dns.is_admin():
            self._offer_relaunch_admin("run suggested network repairs")
            return
        self.auto_repair_button.setEnabled(False)
        self.auto_repair_button.setText("Repairing…")
        adapter = str(self.adapter_combo.currentData() or self.settings.get("selected_adapter", ""))
        self._run_background(
            lambda keys=tuple(recommendations), name=adapter: repair_network(keys, adapter=name),
            self._suggested_repair_finished,
            self._suggested_repair_failed,
        )

    def _suggested_repair_finished(self, outcomes: Any) -> None:
        self.auto_repair_button.setEnabled(True)
        self.auto_repair_button.setText("Run suggested repair")
        if isinstance(outcomes, list):
            lines = [f"{'SUCCESS' if outcome.success else 'FAILED'} — {outcome.title}: {outcome.message}" for outcome in outcomes]
            any_failed = any(not outcome.success for outcome in outcomes)
            QMessageBox.warning(self, "Suggested repair results", "\n".join(lines)) if any_failed else QMessageBox.information(self, "Suggested repair results", "\n".join(lines))
            self._log("Suggested repair sequence finished.", "WARNING" if any_failed else "INFO")
        else:
            QMessageBox.warning(self, "Suggested repair failed", "The repair service returned an invalid result.")
        self._refresh_system_state()
        self._suggested_repairs = []
        self.troubleshooting_summary.setText("Repair complete. Run the full connectivity test again to verify whether the issue was resolved.")
        self._run_full_connectivity_test()

    def _suggested_repair_failed(self, error: str) -> None:
        self.auto_repair_button.setEnabled(True)
        self.auto_repair_button.setText("Run suggested repair")
        first = (error.splitlines()[0] if error else "Unknown error")[:300]
        QMessageBox.warning(self, "Suggested repair could not complete", first)
        self._log("Suggested repair raised an exception.", "ERROR", first)

    def _fastest_measurement_changed(self, metric: str) -> None:
        """Keep ranking tied to an enabled metric; rerun if it has no current samples."""
        check = getattr(self, "fastest_measurement_checks", {}).get(metric)
        if check is not None and not check.isChecked() and getattr(self, "fastest_sort_metric", "query") == metric:
            enabled = [key for key, box in self.fastest_measurement_checks.items() if box.isChecked()]
            if enabled:
                self.fastest_sort_metric = enabled[0]
                self.fastest_sort_ascending = True
                self._fastest_sort_clicked = False
                if self.fastest_sort_metric not in self._fastest_completed_measurements and self.fastest_button.isEnabled():
                    self._run_fastest_dns()
                else:
                    self._render_fastest_results()
                    self._update_fastest_summary(log_result=False)

    def _sort_fastest_by_column(self, column: int) -> None:
        metric_by_column = {2: "median", 3: "tcp", 4: "query"}
        metric = metric_by_column.get(column)
        if not metric:
            return
        check = self.fastest_measurement_checks.get(metric)
        if check is not None and (not check.isChecked() or metric not in self._fastest_completed_measurements):
            if not check.isChecked():
                check.setChecked(True)
            # The requested metric was not collected by the latest run, so re-run with it enabled.
            self.fastest_sort_metric = metric
            self.fastest_sort_ascending = True
            self._fastest_sort_clicked = True
            if self.fastest_button.isEnabled():
                self._run_fastest_dns()
            else:
                self.fastest_summary.setText(f"{metric.upper()} ranking selected; the current benchmark is running. Run the benchmark again when it finishes.")
            return
        if self.fastest_sort_metric == metric:
            if self._fastest_sort_clicked:
                self.fastest_sort_ascending = not self.fastest_sort_ascending
            else:
                self.fastest_sort_ascending = True
                self._fastest_sort_clicked = True
        else:
            self.fastest_sort_metric = metric
            self.fastest_sort_ascending = True
            self._fastest_sort_clicked = True
        self._render_fastest_results()
        if not self._fastest_pending:
            self._update_fastest_summary(log_result=False)

    def _run_fastest_dns(self) -> None:
        selected = tuple(key for key, box in self.fastest_measurement_checks.items() if box.isChecked())
        if not selected:
            QMessageBox.warning(self, "Select measurements", "Choose at least one measurement: median ping, TCP ping, or DNS query ping.")
            return
        if self._fastest_pending:
            self.statusBar().showMessage("A DNS benchmark is already running.", 3500)
            return

        providers = self._all_providers()
        provider_order = [item for item in self.settings.get("provider_order", []) if isinstance(item, str)]
        providers.sort(key=lambda provider: provider_order.index(provider.id) if provider.id in provider_order else len(provider_order))
        self.fastest_button.setEnabled(False)
        self.fastest_button.setText("Benchmarking…")
        self.fastest_table.setEnabled(False)
        self.fastest_summary.setText("Testing the selected measurements on each resolver. This may take several seconds depending on network timeouts.")
        self.fastest_table.setRowCount(0)
        self._fastest_results = []
        self._fastest_pending = len(providers)
        self._fastest_total = len(providers)
        self._fastest_completed_measurements = set(selected)
        for check in self.fastest_measurement_checks.values():
            check.setEnabled(False)
        if not providers:
            self._finish_fastest_benchmark()
            self.fastest_summary.setText("No DNS providers are configured.")
            return
        for provider in providers:
            self._run_background(
                lambda p=provider, metrics=selected: benchmark_provider_metrics(p, rounds=BENCHMARK_ROUNDS, timeout=BENCHMARK_PROBE_TIMEOUT_SECONDS, measurements=metrics),
                self._fastest_probe_finished,
                self._fastest_probe_failed,
            )

    def _fastest_probe_finished(self, result: Any) -> None:
        if isinstance(result, dict):
            self._fastest_results.append(result)
        self._fastest_probe_complete()

    def _fastest_probe_failed(self, error: str) -> None:
        failed_metrics = list(getattr(self, "_fastest_completed_measurements", set()))
        self._fastest_results.append({
            "provider_name": "Unknown", "successes": 0, "rounds": BENCHMARK_ROUNDS, "success_rate": 0.0,
            "measurements": failed_metrics,
            "median_ms": None, "median_success_rate": 0.0,
            "tcp_median_ms": None, "tcp_success_rate": 0.0,
            "query_median_ms": None, "query_successes": 0, "query_success_rate": 0.0,
            "message": error.splitlines()[0] if error else "Unexpected error",
        })
        self._fastest_probe_complete()

    def _fastest_probe_complete(self) -> None:
        self._fastest_pending = max(0, self._fastest_pending - 1)
        if self._fastest_pending:
            self.fastest_summary.setText(f"Finished {len(self._fastest_results)} of {self._fastest_total} provider benchmarks…")
            return
        self._finish_fastest_benchmark()

    def _finish_fastest_benchmark(self) -> None:
        self._fastest_pending = 0
        for check in self.fastest_measurement_checks.values():
            check.setEnabled(True)
        self.fastest_button.setEnabled(True)
        self.fastest_button.setText("Run DNS benchmark")
        self.fastest_table.setEnabled(True)
        self._render_fastest_results()
        self._update_dashboard_benchmark_metrics()
        self._update_fastest_summary(log_result=True)

    def _update_dashboard_benchmark_metrics(self) -> None:
        """Reflect only fresh query measurements from the most recent completed run."""
        query_rows = [
            row for row in self._fastest_results
            if isinstance(row, dict) and "query" in row.get("measurements", [])
        ]
        measured = [row for row in query_rows if row.get("query_median_ms") is not None]
        total = len(query_rows)
        successes = sum(1 for row in query_rows if int(row.get("query_successes", 0) or 0) > 0)
        if not measured:
            self.metric_dns_latency.setText("Not measured")
            self.metric_dns_latency_details.setText("No successful DNS query latency measurement in the latest run")
        else:
            ranked = rank_benchmark_results(query_rows, metric="query", ascending=True)
            winner = next((row for row in ranked if row.get("query_median_ms") is not None), None)
            if winner is None:
                self.metric_dns_latency.setText("Not measured")
                self.metric_dns_latency_details.setText("No DNS query latency measurement is available")
            else:
                self.metric_dns_latency.setText(f"{winner['query_median_ms']} ms")
                self.metric_dns_latency_details.setText(f"Fastest successful query test: {winner.get('provider_name', 'Unknown')} · latest run")
                self._animate_opacity(self.metric_dns_latency, "dns-latency-update", start_opacity=0.45, duration=320)
        if not query_rows:
            self.metric_dns_health.setText("Not tested")
            self.metric_dns_health_details.setText("DNS query measurement was not included in this run")
        elif successes == total and all(float(row.get("query_success_rate", 0) or 0) >= 99.9 for row in query_rows):
            self.metric_dns_health.setText("Healthy")
            self.metric_dns_health_details.setText(f"All {total} tested providers answered at least one DNS query")
        elif successes == total and total > 0:
            self.metric_dns_health.setText("Partial results")
            self.metric_dns_health_details.setText("All providers responded at least once, but some repeated queries failed")
        elif successes > 0:
            self.metric_dns_health.setText("Partial results")
            self.metric_dns_health_details.setText(f"{successes} of {total} providers returned at least one DNS response")
        else:
            self.metric_dns_health.setText("No response")
            self.metric_dns_health_details.setText(f"No DNS responses from {total} tested providers")
        self._animate_opacity(self.metric_dns_health, "dns-health-update", start_opacity=0.45, duration=320)
        # When the persistent monitor is enabled, its state owns the DNS Health card;
        # benchmark completion must not overwrite live health-monitor status.
        if self.settings.get("health_monitor_enabled", False):
            self._update_health_display(self._health_last_result)

    def _update_fastest_summary(self, log_result: bool = False) -> None:
        field = {"median": "median_ms", "tcp": "tcp_median_ms", "query": "query_median_ms"}[self.fastest_sort_metric]
        ranked = getattr(self, "_fastest_ranked_results", self._fastest_results)
        successful = [item for item in ranked if item.get(field) is not None]
        if successful:
            winner = successful[0]
            labels = {"median": "median ICMP ping", "tcp": "TCP/53 connection time", "query": "actual DNS query latency"}
            metric_value = winner.get(field)
            query_rate_text = (
                f"DNS query success rate: {winner.get('query_success_rate', 0)}%. "
                if "query" in self._fastest_completed_measurements else "DNS query success rate: not measured. "
            )
            self.fastest_summary.setText(
                f"Ranked by {labels[self.fastest_sort_metric]}: {winner.get('provider_name', 'Unknown')} leads at {metric_value} ms. "
                f"{query_rate_text}Results are network-specific measurements, not a guarantee of future performance."
            )
            if log_result:
                self._log(f"DNS benchmark completed; {winner.get('provider_name', 'Unknown')} ranked first by {labels[self.fastest_sort_metric]} ({metric_value} ms).")
        else:
            self.fastest_summary.setText("No resolver completed the active ranking measurement. Other metrics may have succeeded; click another measurement header to rank by it.")
            if log_result:
                self._log("DNS benchmark completed with no successful measurements.", "WARNING")

    def _render_fastest_results(self) -> None:
        field_by_metric = {"median": "median_ms", "tcp": "tcp_median_ms", "query": "query_median_ms"}
        field = field_by_metric.get(self.fastest_sort_metric, "query_median_ms")
        rows = rank_benchmark_results(
            self._fastest_results, metric=self.fastest_sort_metric, ascending=self.fastest_sort_ascending
        )
        self._fastest_ranked_results = rows
        self.fastest_table.setSortingEnabled(False)
        self.fastest_table.setRowCount(len(rows))
        metric_header = {"median": "MEDIAN ICMP", "tcp": "TCP/53 CONNECT", "query": "DNS QUERY LATENCY"}[self.fastest_sort_metric]
        self.fastest_table.setToolTip(f"Ranked by {metric_header}. Actual DNS query latency is the default ranking. Click another metric header to change ranking; click the active header again to reverse order.")
        for row, result in enumerate(rows):
            median = result.get("median_ms")
            tcp = result.get("tcp_median_ms")
            query = result.get("query_median_ms")
            query_success_rate = result.get("query_success_rate")
            query_successes = result.get("query_successes")
            rounds = result.get("rounds", 0)
            values = [
                str(row + 1) if result.get(field) is not None else "—",
                str(result.get("provider_name", "Unknown")),
                f"{median} ms" if median is not None else "Not measured",
                f"{tcp} ms" if tcp is not None else "Not measured",
                f"{query} ms" if query is not None else "Not measured",
                f"{query_success_rate}% ({query_successes}/{rounds})" if query_success_rate is not None and "query" in result.get("measurements", []) else "Not measured",
                str(result.get("message", "")),
            ]
            for col, value in enumerate(values):
                self.fastest_table.setItem(row, col, QTableWidgetItem(value))
        self.fastest_table.setSortingEnabled(False)

    def _start_leak_test(self) -> None:
        disclosure = (
            "This optional test contacts dnsleak.dev and resolves unique, temporary DNS test hostnames through "
            "this computer's system resolver. The test service can observe the recursive resolvers that ask for "
            "those names and the public IP/network metadata of the test connection. Its published API says test "
            "results are held in memory for up to ten minutes.\n\n"
            "This checks the resolver path used by this app's system DNS lookups; it does not inspect browser-specific DoH. "
            "Continue and send the test queries?"
        )
        consent = QMessageBox.question(
            self, "External DNS leak test — privacy notice", disclosure,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if consent != QMessageBox.StandardButton.Yes:
            return
        self.leak_test_button.setEnabled(False)
        self.leak_test_button.setText("Testing…")
        self.leak_test_summary.setText("Creating a one-time test and resolving hostnames through the system resolver…")
        self.leak_test_resolvers.setText("Waiting for the authoritative test service to report the observed resolvers.")
        self._run_background(
            run_external_dns_leak_test,
            self._external_leak_test_finished,
            self._external_leak_test_failed,
        )

    def _external_leak_test_finished(self, result: Any) -> None:
        self.leak_test_button.setEnabled(True)
        self.leak_test_button.setText("Run external test")
        if not isinstance(result, dict):
            self._external_leak_test_failed("The external service returned an unexpected result.")
            return
        status = str(result.get("status", "inconclusive"))
        labels = {
            "no_leak": "No split-resolver leak detected by the service",
            "split": "Split resolver detected — review the result",
            "leak": "Potential leak reported — review the result",
            "inconclusive": "Inconclusive — the service could not determine a verdict",
        }
        self.leak_test_summary.setText(
            f"{labels.get(status, labels['inconclusive'])}\n{result.get('detail', '')}\n"
            f"Observed lookups: {result.get('lookups_seen', 0)} of {result.get('hostnames_attempted', 0)} attempts · "
            f"Completed in {result.get('elapsed_seconds', '?')} s"
        )
        resolvers = result.get("resolvers", [])
        if resolvers:
            formatted = []
            for resolver in resolvers:
                location = ", ".join(part for part in (resolver.get("city"), resolver.get("country")) if part)
                suffix = f" — {location}" if location else ""
                formatted.append(f"• {resolver.get('label', 'Unknown resolver')}{suffix} · {resolver.get('status', 'unknown')}")
            resolver_text = "\n".join(formatted)
        else:
            resolver_text = "The service did not identify any resolver groups. This is not the same as a clean result."
        self.leak_test_resolvers.setText(
            f"Connection as seen by the service: {result.get('client_ip', 'Not provided')} · "
            f"{result.get('client_location', '')} · {result.get('client_network', '')}\n{resolver_text}"
        )
        self._log(f"External DNS leak test completed: {status}.")

    def _external_leak_test_failed(self, error: str) -> None:
        self.leak_test_button.setEnabled(True)
        self.leak_test_button.setText("Run external test")
        self.leak_test_summary.setText(f"The external test failed: {error.splitlines()[0] if error else 'Unknown error'}")
        self.leak_test_resolvers.setText("No verdict was produced. A failed test must not be interpreted as proof that DNS is leak-free.")
        self._log("External DNS leak test failed.")

    def _run_all_probes(self) -> None:
        self.probe_button.setEnabled(False)
        self.probe_button.setText("Testing…")
        self.probe_progress.setText("Starting selected reachability tests. ICMP ping and TCP/53 are connectivity checks; DNS query probes verify resolver responses.")
        self.probe_table.setRowCount(0)
        self._probe_row_by_id.clear()
        protocol = str(self.probe_protocol_combo.currentData())
        providers = self._all_providers()
        self._probe_total = len(providers)
        self._probe_pending = len(providers)
        self._probe_success = 0
        for provider in providers:
            row = self.probe_table.rowCount()
            self.probe_table.insertRow(row)
            self._probe_row_by_id[provider.id] = row
            for col, value in enumerate((provider.name, "Testing…", "Pending", "—", "Waiting for result")):
                self.probe_table.setItem(row, col, QTableWidgetItem(value))
            self._run_background(lambda p=provider, proto=protocol: probe_provider(p, proto).to_dict(), lambda result, pid=provider.id: self._probe_finished(pid, result), lambda error, pid=provider.id: self._probe_error(pid, error))

    def _probe_error(self, provider_id: str, error: str) -> None:
        provider = self._provider(provider_id)
        self._probe_finished(provider_id, {"provider_id": provider_id, "provider_name": provider.name if provider else provider_id, "protocol": "Error", "success": False, "latency_ms": None, "message": error.splitlines()[0] if error else "Unexpected probe error"})

    def _probe_finished(self, provider_id: str, result: Any) -> None:
        row = self._probe_row_by_id.get(provider_id)
        if row is not None and isinstance(result, dict):
            values = [
                str(result.get("provider_name", "Unknown")),
                str(result.get("protocol", "—")),
                "Reachable" if result.get("success") else "Failed",
                f"{result.get('latency_ms')} ms" if result.get("latency_ms") is not None else "—",
                str(result.get("message", "")),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setForeground(QBrush(QColor("#42d9ab" if result.get("success") else "#ff7284")))
                self.probe_table.setItem(row, col, item)
            if result.get("success"):
                self._probe_success += 1
        self._probe_pending -= 1
        total = getattr(self, "_probe_total", len(self._all_providers()))
        self.probe_progress.setText(f"Completed {total - self._probe_pending}/{total} tests · {self._probe_success} reachable")
        if self._probe_pending <= 0:
            self.probe_button.setEnabled(True)
            self.probe_button.setText("Run all tests")
            self._log(f"DNS diagnostics completed: {self._probe_success}/{total} resolvers reachable.")

    # ---- Persistent activity history ---------------------------------------
    def _build_activity_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("Activity log", "A persistent record of DNS changes, repairs, diagnostics, imports, themes and connection actions."))
        controls = QHBoxLayout()
        self.activity_search = QLineEdit()
        self.activity_search.setPlaceholderText("Search actions or details…")
        self.activity_search.textChanged.connect(self._schedule_activity_table_refresh)
        controls.addWidget(self.activity_search, 1)
        self.activity_level_combo = QComboBox()
        self.activity_level_combo.addItem("All levels", "ALL")
        self.activity_level_combo.addItem("Info", "INFO")
        self.activity_level_combo.addItem("Warnings", "WARNING")
        self.activity_level_combo.addItem("Errors", "ERROR")
        self.activity_level_combo.currentIndexChanged.connect(self._schedule_activity_table_refresh)
        controls.addWidget(self.activity_level_combo)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_activity_table)
        export = QPushButton("Export CSV")
        export.clicked.connect(self._export_activity_log)
        clear = QPushButton("Clear history")
        clear.setObjectName("DangerButton")
        clear.clicked.connect(self._clear_activity_log)
        controls.addWidget(refresh)
        controls.addWidget(export)
        controls.addWidget(clear)
        layout.addLayout(controls)
        self.activity_count_label = make_label("Activity is saved locally.", "Muted")
        layout.addWidget(self.activity_count_label)
        self.activity_table = QTableWidget(0, 4)
        self.activity_table.setHorizontalHeaderLabels(["TIME", "LEVEL", "ACTION", "DETAILS"])
        self.activity_table.setAlternatingRowColors(True)
        self.activity_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.activity_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.activity_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.activity_table.setMinimumHeight(430)
        layout.addWidget(self.activity_table, 1)
        return scroll_page(content)

    def _schedule_activity_table_refresh(self, *_args: Any) -> None:
        self._activity_table_dirty = True
        if self.pages.currentWidget() is self.activity_page:
            self._activity_table_refresh_timer.start(180)

    def _set_activity_row(self, row_index: int, record: dict[str, Any]) -> None:
        values = (record.get("timestamp", ""), record.get("level", "INFO"), record.get("action", ""), record.get("details", ""))
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if col == 1:
                color = {"ERROR": "#e85a70", "WARNING": "#d59b38", "INFO": "#38a88a"}.get(record.get("level", "INFO"), "#8090a0")
                item.setForeground(QBrush(QColor(color)))
            self.activity_table.setItem(row_index, col, item)

    def _refresh_activity_table(self, *_args: Any) -> None:
        if not hasattr(self, "activity_table"):
            return
        # Use the in-memory record cache. Disk persistence is handled asynchronously by
        # BackgroundActivityLogger; reading/reparsing the file during tab navigation is unnecessary.
        records = list(self._activity_records)
        query = self.activity_search.text().strip().casefold() if hasattr(self, "activity_search") else ""
        level_filter = str(self.activity_level_combo.currentData()) if hasattr(self, "activity_level_combo") else "ALL"
        if level_filter != "ALL":
            records = [record for record in records if record.get("level") == level_filter]
        if query:
            records = [record for record in records if query in " ".join(str(record.get(field, "")) for field in ("timestamp", "level", "action", "details")).casefold()]
        records.reverse()
        self.activity_table.setUpdatesEnabled(False)
        self.activity_table.setRowCount(len(records))
        for row_index, record in enumerate(records):
            self._set_activity_row(row_index, record)
        self.activity_table.setUpdatesEnabled(True)
        self.activity_count_label.setText(f"Showing {len(records)} records · stored locally, capped at {self.activity_store.limit} entries.")
        self._activity_table_initialized = True
        self._activity_table_dirty = False

    def _insert_activity_row_if_fast_path(self, record: dict[str, Any]) -> bool:
        if not self._activity_table_initialized or self._activity_table_dirty:
            return False
        if self.activity_search.text().strip() or str(self.activity_level_combo.currentData()) != "ALL":
            return False
        self.activity_table.insertRow(0)
        self._set_activity_row(0, record)
        while self.activity_table.rowCount() > self.activity_store.limit:
            self.activity_table.removeRow(self.activity_table.rowCount() - 1)
        self.activity_count_label.setText(f"Showing {self.activity_table.rowCount()} records · stored locally, capped at {self.activity_store.limit} entries.")
        return True

    def _export_activity_log(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Raider DNS activity log", "raider_dns_activity.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with Path(path).open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=("timestamp", "level", "action", "details"))
                writer.writeheader()
                writer.writerows(self._activity_records)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            self._log("Activity log export failed.", "ERROR")
            return
        self._log("Exported the activity log as CSV.")
        QMessageBox.information(self, "Activity log exported", "The activity log was exported successfully.")

    def _clear_activity_log(self) -> None:
        answer = QMessageBox.question(self, "Clear activity history", "Permanently clear the locally stored Raider DNS activity history?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._activity_writer.clear()
        self._activity_records = []
        self._activity = []
        self._refresh_activity_table()
        self._log("Cleared activity history.", "WARNING")

    # ---- Settings -----------------------------------------------------------
    def _build_settings_page(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(26, 22, 26, 25)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("Application settings", "Preferences are stored locally. System DNS changes remain an explicit action."))

        appearance = Panel()
        appearance_layout = make_panel_layout(appearance)
        appearance_layout.addWidget(make_label("Appearance", "Heading"))
        theme_row = QHBoxLayout()
        theme_text = QVBoxLayout()
        theme_text.addWidget(make_label("Color theme"))
        theme_text.addWidget(make_label("Switch between dark and light appearance.", "Muted"))
        theme_row.addLayout(theme_text, 1)
        self.settings_theme_combo = QComboBox()
        for label, theme_id in (("Dark", "dark"), ("Light — redesigned", "light"), ("Midnight", "midnight"), ("Ocean", "ocean"), ("High contrast", "high_contrast")):
            self.settings_theme_combo.addItem(label, theme_id)
        selected_theme_index = self.settings_theme_combo.findData(self.settings.get("theme", "dark"))
        self.settings_theme_combo.setCurrentIndex(selected_theme_index if selected_theme_index >= 0 else 0)
        self.settings_theme_combo.currentIndexChanged.connect(self._settings_theme_changed)
        theme_row.addWidget(self.settings_theme_combo)
        appearance_layout.addLayout(theme_row)
        tooltip_row = QHBoxLayout()
        tooltip_text = QVBoxLayout()
        tooltip_text.addWidget(make_label("Button description delay"))
        tooltip_text.addWidget(make_label("Wait before showing help on hover, then fade it in gently.", "Muted"))
        tooltip_row.addLayout(tooltip_text, 1)
        self.tooltip_delay_combo = QComboBox()
        for delay, label in ((500, "0.5 seconds"), (750, "0.75 seconds"), (1000, "1 second"), (1250, "1.25 seconds")):
            self.tooltip_delay_combo.addItem(label, delay)
        tooltip_index = self.tooltip_delay_combo.findData(int(self.settings.get("tooltip_delay_ms", 750)))
        self.tooltip_delay_combo.setCurrentIndex(tooltip_index if tooltip_index >= 0 else 1)
        self.tooltip_delay_combo.currentIndexChanged.connect(self._settings_changed)
        tooltip_row.addWidget(self.tooltip_delay_combo)
        appearance_layout.addLayout(tooltip_row)
        layout.addWidget(appearance)

        behavior = Panel()
        behavior_layout = make_panel_layout(behavior)
        behavior_layout.addWidget(make_label("Network behavior", "Heading"))
        self.flush_checkbox = QCheckBox("Flush the Windows DNS cache after applying or restoring DNS")
        self.flush_checkbox.setChecked(bool(self.settings.get("flush_dns_after_apply", True)))
        self.flush_checkbox.stateChanged.connect(self._settings_changed)
        behavior_layout.addWidget(self.flush_checkbox)
        self.confirm_checkbox = QCheckBox("Ask for confirmation before changing system DNS")
        self.confirm_checkbox.setChecked(bool(self.settings.get("confirm_dns_changes", True)))
        self.confirm_checkbox.stateChanged.connect(self._settings_changed)
        behavior_layout.addWidget(self.confirm_checkbox)
        self.failover_checkbox = QCheckBox("Use a fallback DNS provider after the preferred provider")
        self.failover_checkbox.setChecked(bool(self.settings.get("failover_enabled", False)))
        self.failover_checkbox.stateChanged.connect(self._settings_changed)
        behavior_layout.addWidget(self.failover_checkbox)
        self.minimize_to_tray_checkbox = QCheckBox("Minimize to the system tray")
        self.minimize_to_tray_checkbox.setChecked(bool(self.settings.get("minimize_to_tray", True)))
        self.minimize_to_tray_checkbox.stateChanged.connect(self._settings_changed)
        behavior_layout.addWidget(self.minimize_to_tray_checkbox)
        self.close_to_tray_checkbox = QCheckBox("Close button hides the app in the tray (use Exit in tray menu to quit)")
        self.close_to_tray_checkbox.setChecked(bool(self.settings.get("close_to_tray", False)))
        self.close_to_tray_checkbox.stateChanged.connect(self._settings_changed)
        behavior_layout.addWidget(self.close_to_tray_checkbox)
        fallback_row = QHBoxLayout()
        fallback_text = QVBoxLayout()
        fallback_text.addWidget(make_label("Fallback resolver"))
        fallback_description = make_label("Windows can try alternate configured servers when the preferred one does not respond; failover timing is controlled by Windows.", "Muted")
        fallback_description.setWordWrap(True)
        fallback_text.addWidget(fallback_description)
        fallback_row.addLayout(fallback_text, 1)
        self.fallback_provider_combo = QComboBox()
        for provider in self._all_providers():
            self.fallback_provider_combo.addItem(provider.name, provider.id)
        fallback_index = self.fallback_provider_combo.findData(self.settings.get("fallback_provider", "quad9"))
        self.fallback_provider_combo.setCurrentIndex(fallback_index if fallback_index >= 0 else 2)
        self.fallback_provider_combo.currentIndexChanged.connect(self._settings_changed)
        fallback_row.addWidget(self.fallback_provider_combo)
        behavior_layout.addLayout(fallback_row)
        layout.addWidget(behavior)

        monitor_panel = Panel()
        monitor_layout = make_panel_layout(monitor_panel)
        monitor_layout.addWidget(make_label("Notifications and DNS health monitor", "Heading"))
        self.notifications_enabled_checkbox = QCheckBox("Show Raider DNS notifications for DNS changes, network changes, disconnects and health transitions")
        self.notifications_enabled_checkbox.setToolTip("Show a themed notification in the app, or a tray notification while the window is hidden.")
        self.notifications_enabled_checkbox.setChecked(bool(self.settings.get("notifications_enabled", True)))
        self.notifications_enabled_checkbox.stateChanged.connect(self._settings_changed)
        monitor_layout.addWidget(self.notifications_enabled_checkbox)
        self.health_monitor_enabled_checkbox = QCheckBox("Enable automatic DNS health monitoring in the background")
        self.health_monitor_enabled_checkbox.setToolTip("Check the selected resolver without changing Windows DNS automatically.")
        self.health_monitor_enabled_checkbox.setChecked(bool(self.settings.get("health_monitor_enabled", False)))
        self.health_monitor_enabled_checkbox.stateChanged.connect(self._settings_changed)
        monitor_layout.addWidget(self.health_monitor_enabled_checkbox)
        monitor_note = make_label("When enabled, Raider DNS sends a small DNS query to the selected provider at the chosen interval. It requires consecutive failures before warning and consecutive successes before reporting recovery. It does not change system DNS automatically.", "Muted")
        monitor_note.setWordWrap(True)
        monitor_layout.addWidget(monitor_note)
        network_poll_row = QHBoxLayout()
        network_poll_text = QVBoxLayout()
        network_poll_text.addWidget(make_label("Network change detection interval", "Muted"))
        network_poll_text.addWidget(make_label("How often Raider DNS checks adapter, DNS server and local IP changes.", "Muted"))
        network_poll_row.addLayout(network_poll_text, 1)
        self.network_poll_interval_combo = QComboBox()
        for seconds in (10, 20, 30, 60):
            self.network_poll_interval_combo.addItem(f"Every {seconds} seconds", seconds)
        network_interval_index = self.network_poll_interval_combo.findData(int(self.settings.get("network_poll_interval_seconds", 20)))
        self.network_poll_interval_combo.setCurrentIndex(network_interval_index if network_interval_index >= 0 else 1)
        self.network_poll_interval_combo.setToolTip("Shorter intervals detect changes sooner but run adapter inspection more often.")
        self.network_poll_interval_combo.currentIndexChanged.connect(self._settings_changed)
        network_poll_row.addWidget(self.network_poll_interval_combo)
        monitor_layout.addLayout(network_poll_row)
        health_settings = QGridLayout()
        health_settings.addWidget(make_label("DNS health check interval", "Muted"), 0, 0)
        self.health_interval_combo = QComboBox()
        for seconds in (15, 30, 60, 120, 300):
            self.health_interval_combo.addItem(f"Every {seconds} seconds", seconds)
        health_interval_index = self.health_interval_combo.findData(int(self.settings.get("health_interval_seconds", 30)))
        self.health_interval_combo.setCurrentIndex(health_interval_index if health_interval_index >= 0 else 1)
        self.health_interval_combo.currentIndexChanged.connect(self._settings_changed)
        health_settings.addWidget(self.health_interval_combo, 0, 1)
        health_settings.addWidget(make_label("DNS query timeout", "Muted"), 0, 2)
        self.health_timeout_combo = QComboBox()
        for seconds in (1.0, 2.0, 2.5, 3.0, 5.0):
            self.health_timeout_combo.addItem(f"{seconds:g} seconds", seconds)
        health_timeout_index = self.health_timeout_combo.findData(float(self.settings.get("health_timeout_seconds", 2.5)))
        if health_timeout_index < 0:
            health_timeout_index = self.health_timeout_combo.findData(2.0)
        self.health_timeout_combo.setCurrentIndex(max(0, health_timeout_index))
        self.health_timeout_combo.currentIndexChanged.connect(self._settings_changed)
        health_settings.addWidget(self.health_timeout_combo, 0, 3)
        health_settings.addWidget(make_label("Failures before warning", "Muted"), 1, 0)
        self.health_failure_combo = QComboBox()
        for number in (2, 3, 4, 5):
            self.health_failure_combo.addItem(f"{number} consecutive failures", number)
        failure_index = self.health_failure_combo.findData(int(self.settings.get("health_failure_threshold", 3)))
        self.health_failure_combo.setCurrentIndex(failure_index if failure_index >= 0 else 1)
        self.health_failure_combo.currentIndexChanged.connect(self._settings_changed)
        health_settings.addWidget(self.health_failure_combo, 1, 1)
        health_settings.addWidget(make_label("Successes before recovery", "Muted"), 1, 2)
        self.health_recovery_combo = QComboBox()
        for number in (1, 2, 3):
            self.health_recovery_combo.addItem(f"{number} consecutive successes", number)
        recovery_index = self.health_recovery_combo.findData(int(self.settings.get("health_recovery_threshold", 2)))
        self.health_recovery_combo.setCurrentIndex(recovery_index if recovery_index >= 0 else 1)
        self.health_recovery_combo.currentIndexChanged.connect(self._settings_changed)
        health_settings.addWidget(self.health_recovery_combo, 1, 3)
        monitor_layout.addLayout(health_settings)
        layout.addWidget(monitor_panel)

        data_panel = Panel()
        data_layout = make_panel_layout(data_panel)
        data_layout.addWidget(make_label("Data and recovery", "Heading"))
        data_layout.addWidget(make_label("Export a portable settings backup or restore one. Backups may include your saved profile names and DNS addresses.", "Muted"))
        data_buttons = QHBoxLayout()
        export_button = QPushButton("Export full backup")
        export_button.clicked.connect(self._export_settings)
        import_button = QPushButton("Import full backup")
        import_button.clicked.connect(self._import_settings)
        data_buttons.addWidget(export_button)
        data_buttons.addWidget(import_button)
        data_layout.addLayout(data_buttons)
        collection_buttons = QGridLayout()
        export_providers = QPushButton("Export DNS providers")
        export_providers.clicked.connect(self._export_providers_backup)
        import_providers = QPushButton("Import DNS providers")
        import_providers.clicked.connect(self._import_providers_backup)
        export_profiles = QPushButton("Export DNS profiles")
        export_profiles.clicked.connect(self._export_profiles_backup)
        import_profiles = QPushButton("Import DNS profiles")
        import_profiles.clicked.connect(self._import_profiles_backup)
        collection_buttons.addWidget(export_providers, 0, 0)
        collection_buttons.addWidget(import_providers, 0, 1)
        collection_buttons.addWidget(export_profiles, 1, 0)
        collection_buttons.addWidget(import_profiles, 1, 1)
        data_layout.addLayout(collection_buttons)
        layout.addWidget(data_panel)

        about = Panel()
        about_layout = make_panel_layout(about)
        about_layout.addWidget(make_label("About Raider DNS", "Heading"))
        about_layout.addWidget(make_label(f"Raider DNS · PySide6 edition · {__version__}", "Accent"))
        about_layout.addWidget(make_label("Copyright © 2026 Nima Zahedi", "Muted"))
        about_layout.addWidget(make_label(f"Python {platform.python_version()} · Qt for Python / PySide6 · {platform.system()}", "Muted"))
        about_layout.addWidget(make_label("DNS configuration is Windows-specific. Resolver probes can run wherever outbound DNS/HTTPS is permitted.", "Muted"))
        layout.addWidget(about)
        layout.addStretch(1)
        return scroll_page(content)

    def _settings_theme_changed(self, *_args: Any) -> None:
        self.settings["theme"] = str(self.settings_theme_combo.currentData())
        self._save_settings()
        self._apply_theme()
        self._log(f"Changed appearance theme to {self.settings['theme']}.")

    def _toggle_theme(self) -> None:
        self.settings["theme"] = "light" if self.settings.get("theme") != "light" else "dark"
        self.settings_theme_combo.blockSignals(True)
        selected_index = self.settings_theme_combo.findData(self.settings["theme"])
        self.settings_theme_combo.setCurrentIndex(max(0, selected_index))
        self.settings_theme_combo.blockSignals(False)
        self._save_settings()
        self._apply_theme()
        self._log(f"Changed appearance theme to {self.settings['theme']}.")

    def _apply_theme(self) -> None:
        current_stylesheet = stylesheet(self.settings.get("theme", "dark"))
        if self.centralWidget() is not None:
            self.centralWidget().setProperty("raiderDarkTheme", self.settings.get("theme", "dark") != "light")
        if hasattr(self, "_tooltip_controller"):
            self._tooltip_controller._style_popup()
        if hasattr(self, "_notification_toast"):
            self._notification_toast._apply_style()
        if hasattr(self, "benchmark_chart"):
            self.benchmark_chart.set_results(getattr(self, "_lab_results", []), self.settings.get("theme", "dark"))
        app = QApplication.instance()
        if app:
            app.setStyleSheet(current_stylesheet)
        self.setStyleSheet(current_stylesheet)
        self.theme_button.setText("☼" if self.settings.get("theme") in {"dark", "midnight", "ocean", "high_contrast"} else "☾")
        status_color = "#526780" if self.settings.get("theme") == "light" else ("#ffffff" if self.settings.get("theme") == "high_contrast" else "#a1aec1")
        self.statusBar().setStyleSheet(f"QStatusBar{{background:transparent;color:{status_color};border-top:1px solid palette(mid);padding:3px 8px;}}")

    def _settings_changed(self, *_args: Any) -> None:
        if hasattr(self, "flush_checkbox"):
            old_monitor_enabled = bool(self.settings.get("health_monitor_enabled", False))
            self.settings["flush_dns_after_apply"] = self.flush_checkbox.isChecked()
            self.settings["confirm_dns_changes"] = self.confirm_checkbox.isChecked()
            self.settings["failover_enabled"] = self.failover_checkbox.isChecked() if hasattr(self, "failover_checkbox") else bool(self.settings.get("failover_enabled", False))
            self.settings["minimize_to_tray"] = self.minimize_to_tray_checkbox.isChecked() if hasattr(self, "minimize_to_tray_checkbox") else bool(self.settings.get("minimize_to_tray", True))
            self.settings["close_to_tray"] = self.close_to_tray_checkbox.isChecked() if hasattr(self, "close_to_tray_checkbox") else bool(self.settings.get("close_to_tray", False))
            self.settings["fallback_provider"] = str(self.fallback_provider_combo.currentData()) if hasattr(self, "fallback_provider_combo") else str(self.settings.get("fallback_provider", "quad9"))
            if hasattr(self, "notifications_enabled_checkbox"):
                self.settings["notifications_enabled"] = self.notifications_enabled_checkbox.isChecked()
            if hasattr(self, "health_monitor_enabled_checkbox"):
                self.settings["health_monitor_enabled"] = self.health_monitor_enabled_checkbox.isChecked()
                self.settings["health_interval_seconds"] = int(self.health_interval_combo.currentData())
                self.settings["health_timeout_seconds"] = float(self.health_timeout_combo.currentData())
                self.settings["health_failure_threshold"] = int(self.health_failure_combo.currentData())
                self.settings["health_recovery_threshold"] = int(self.health_recovery_combo.currentData())
            if hasattr(self, "network_poll_interval_combo"):
                self.settings["network_poll_interval_seconds"] = int(self.network_poll_interval_combo.currentData())
                self._network_change_timer.setInterval(self.settings["network_poll_interval_seconds"] * 1000)
                if not self._network_change_timer.isActive():
                    self._network_change_timer.start()
            if hasattr(self, "tooltip_delay_combo"):
                self.settings["tooltip_delay_ms"] = int(self.tooltip_delay_combo.currentData())
                if hasattr(self, "_tooltip_controller"):
                    self._tooltip_controller.set_delay(self.settings["tooltip_delay_ms"])
            self._save_settings()
            self._configure_health_monitor(run_now=(not old_monitor_enabled and bool(self.settings.get("health_monitor_enabled", False))))
            self._log("Updated application preferences.")

    def _export_settings(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Raider DNS settings", "raider_dns_settings.json", "JSON files (*.json)")
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self.settings, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            self._log("Full settings backup export failed.", "ERROR", str(exc))
            return
        QMessageBox.information(self, "Backup exported", "Your settings backup was exported successfully.")
        self._log("Exported settings backup.")

    def _export_providers_backup(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export DNS providers", "raider_dns_providers.json", "JSON files (*.json)")
        if not path:
            return
        provider_rows = [{
            "id": item.id, "name": item.name, "description": item.description,
            "primary": item.primary, "secondary": item.secondary, "category": item.category,
            "doh_url": item.doh_url, "dot_hostname": item.dot_hostname, "website": item.website,
        } for item in self._all_providers()]
        payload = {
            "format": "raiderdns-provider-backup", "version": 1,
            "providers": provider_rows,
            "custom_providers": list(self.settings.get("custom_providers", [])),
            "provider_overrides": dict(self.settings.get("provider_overrides", {})),
            "disabled_builtin_providers": list(self.settings.get("disabled_builtin_providers", [])),
            "provider_order": list(self.settings.get("provider_order", [])),
            "favorites": list(self.settings.get("favorites", [])),
        }
        try:
            Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Provider backup failed", str(exc))
            self._log("DNS provider backup export failed.", "ERROR")
            return
        self._log("Exported DNS provider catalogue backup.")
        QMessageBox.information(self, "Providers exported", "Provider order, favorites, and custom provider definitions were exported. Built-in providers are included as a reference catalogue.")

    def _sanitize_import_providers(self, raw_items: Any) -> list[dict[str, Any]]:
        builtin_ids = {provider.id for provider in PROVIDERS}
        seen_ids: set[str] = set()
        seen_names = {provider.name.casefold() for provider in PROVIDERS}
        valid: list[dict[str, Any]] = []
        if not isinstance(raw_items, list):
            raise ValueError("The provider backup must contain a provider list.")
        for item in raw_items[:100]:
            if not isinstance(item, dict):
                continue
            provider_id = item.get("id")
            name = item.get("name")
            primary = item.get("primary")
            secondary = item.get("secondary", "")
            if not isinstance(provider_id, str) or not re.fullmatch(r"custom-[a-z0-9_-]{1,64}", provider_id):
                # Built-in IDs are code-defined and are not overwritten by imported data.
                continue
            if provider_id in builtin_ids or provider_id in seen_ids:
                continue
            if not isinstance(name, str) or not name.strip() or len(name) > 80:
                continue
            if not isinstance(primary, str) or not isinstance(secondary, str):
                continue
            if name.strip().casefold() in seen_names:
                continue
            try:
                if ipaddress.ip_address(primary).version != 4 or (secondary and ipaddress.ip_address(secondary).version != 4):
                    continue
            except ValueError:
                continue
            doh = item.get("doh_url")
            if not isinstance(doh, str) or not _valid_web_url(doh, {"https"}):
                doh = None
            website = item.get("website")
            if not isinstance(website, str) or not _valid_web_url(website, {"http", "https"}):
                website = ""
            dot = item.get("dot_hostname")
            if not isinstance(dot, str) or not dot.strip() or any(ch in dot for ch in "/\\?#@[] "):
                dot = None
            clean = {
                "id": provider_id,
                "name": name.strip(),
                "description": str(item.get("description", "Custom DNS provider"))[:240],
                "primary": primary.strip(), "secondary": secondary.strip(),
                "category": str(item.get("category", "Custom"))[:60] or "Custom",
                "doh_url": doh.strip() if doh else None,
                "dot_hostname": dot.strip() if dot else None,
                "website": website.strip() if website else "",
            }
            valid.append(clean)
            seen_ids.add(provider_id)
            seen_names.add(name.strip().casefold())
        if len(raw_items) and not valid:
            raise ValueError("No valid custom DNS providers were found in this backup.")
        return valid

    def _refresh_after_collection_import(self) -> None:
        disabled_ids = set(self.settings.get("disabled_builtin_providers", []))
        valid_ids = {provider.id for provider in PROVIDERS if provider.id not in disabled_ids} | {row.get("id") for row in self.settings.get("custom_providers", []) if isinstance(row, dict)}
        if not valid_ids:
            # Imported data must never leave the app with an empty resolver catalogue.
            self.settings["disabled_builtin_providers"] = []
            valid_ids = {provider.id for provider in PROVIDERS}
        fallback_default = "quad9" if "quad9" in valid_ids else sorted(valid_ids)[0]
        selected_default = "cloudflare" if "cloudflare" in valid_ids else fallback_default
        for key, fallback in (("selected_provider", selected_default), ("fallback_provider", fallback_default), ("connection_dns_provider", selected_default)):
            if self.settings.get(key) not in valid_ids:
                self.settings[key] = fallback
        self.settings["favorites"] = list(dict.fromkeys(item for item in self.settings.get("favorites", []) if item in valid_ids))
        self.settings["provider_order"] = list(dict.fromkeys(item for item in self.settings.get("provider_order", []) if item in valid_ids))
        for provider in self._all_providers():
            if provider.id not in self.settings["provider_order"]:
                self.settings["provider_order"].append(provider.id)
        for provider in self.settings.get("custom_providers", []):
            if provider.get("id") not in self.settings["provider_order"]:
                self.settings["provider_order"].append(provider.get("id"))
        for profile in self.settings.get("profiles", []):
            if profile.get("provider_id") not in valid_ids:
                profile["provider_id"] = None
                profile["doh_url"] = None
        self._save_settings()
        self._rebuild_provider_cards()
        self._refresh_provider_selector_options()
        self._update_favorite_controls()
        self._reorder_provider_cards()
        self._update_provider_selection_controls()
        self._update_provider_metrics()
        if hasattr(self, "connection_dns_provider_combo"):
            self.connection_dns_provider_combo.blockSignals(True)
            idx = self.connection_dns_provider_combo.findData(self.settings.get("connection_dns_provider", "cloudflare"))
            self.connection_dns_provider_combo.setCurrentIndex(max(0, idx))
            self.connection_dns_provider_combo.blockSignals(False)
        if hasattr(self, "fallback_provider_combo"):
            self.fallback_provider_combo.blockSignals(True)
            idx = self.fallback_provider_combo.findData(self.settings.get("fallback_provider", "quad9"))
            self.fallback_provider_combo.setCurrentIndex(max(0, idx))
            self.fallback_provider_combo.blockSignals(False)
        self._refresh_profiles()
        self._refresh_activity_table()

    def _import_providers_backup(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import DNS providers", "", "JSON files (*.json)")
        if not path:
            return
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("format") != "raiderdns-provider-backup" or raw.get("version") != 1:
                raise ValueError("This file is not a supported Raider DNS provider backup.")
            custom = self._sanitize_import_providers(raw.get("custom_providers", []))
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Invalid provider backup", str(exc))
            self._log("DNS provider backup import rejected.", "WARNING")
            return
        merge = QMessageBox.question(self, "Restore DNS providers", "Merge the imported custom providers with your existing ones? Choose No to replace existing custom providers.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Yes)
        if merge == QMessageBox.StandardButton.Cancel:
            return
        existing = list(self.settings.get("custom_providers", [])) if merge == QMessageBox.StandardButton.Yes else []
        by_id = {row.get("id"): row for row in existing if isinstance(row, dict)}
        by_name = {str(row.get("name", "")).casefold(): row.get("id") for row in existing if isinstance(row, dict)}
        for item in custom:
            prior_id = by_name.get(item["name"].casefold())
            if prior_id and prior_id != item["id"]:
                item = dict(item, id=prior_id)
                by_id.pop(item.get("id"), None)
            by_id[item["id"]] = item
        self.settings["custom_providers"] = list(by_id.values())[:100]
        raw_overrides = raw.get("provider_overrides", {})
        if isinstance(raw_overrides, dict):
            known_builtin_ids = {provider.id for provider in PROVIDERS}
            clean_overrides = {}
            for provider_id, item in raw_overrides.items():
                if provider_id not in known_builtin_ids or not isinstance(item, dict):
                    continue
                name = item.get("name")
                primary = item.get("primary")
                secondary = item.get("secondary", "")
                if not isinstance(name, str) or not name.strip() or len(name) > 80:
                    continue
                if not isinstance(primary, str) or not isinstance(secondary, str):
                    continue
                try:
                    if ipaddress.ip_address(primary).version != 4 or (secondary and ipaddress.ip_address(secondary).version != 4):
                        continue
                except ValueError:
                    continue
                doh = item.get("doh_url")
                if not isinstance(doh, str) or not _valid_web_url(doh, {"https"}):
                    doh = None
                website = item.get("website")
                if not isinstance(website, str) or not _valid_web_url(website, {"http", "https"}):
                    website = ""
                dot = item.get("dot_hostname")
                if not isinstance(dot, str) or not dot.strip() or len(dot) > 253 or any(ch.isspace() or ch in "/\\?#@[]" for ch in dot):
                    dot = None
                clean_overrides[provider_id] = {
                    "id": provider_id, "name": name.strip(),
                    "description": str(item.get("description", ""))[:240],
                    "primary": primary.strip(), "secondary": secondary.strip(),
                    "category": str(item.get("category", "General"))[:60] or "General",
                    "doh_url": doh.strip() if doh else None,
                    "dot_hostname": dot.strip() if dot else None,
                    "website": website.strip() if website else "",
                }
            self.settings["provider_overrides"] = clean_overrides
        raw_disabled = raw.get("disabled_builtin_providers", [])
        if isinstance(raw_disabled, list):
            known_builtin_ids = {provider.id for provider in PROVIDERS}
            self.settings["disabled_builtin_providers"] = list(dict.fromkeys(item for item in raw_disabled if isinstance(item, str) and item in known_builtin_ids))
        valid_ids = {provider.id for provider in PROVIDERS if provider.id not in self.settings.get("disabled_builtin_providers", [])} | {row["id"] for row in self.settings["custom_providers"]}
        imported_order = raw.get("provider_order", [])
        if isinstance(imported_order, list):
            self.settings["provider_order"] = list(dict.fromkeys(item for item in imported_order if isinstance(item, str) and item in valid_ids))
        for item in valid_ids:
            if item not in self.settings["provider_order"]:
                self.settings["provider_order"].append(item)
        imported_favorites = raw.get("favorites", [])
        if isinstance(imported_favorites, list):
            incoming = [item for item in imported_favorites if isinstance(item, str) and item in valid_ids]
            self.settings["favorites"] = list(dict.fromkeys((self.settings.get("favorites", []) if merge == QMessageBox.StandardButton.Yes else []) + incoming))
        self._refresh_after_collection_import()
        self._log(f"Imported DNS provider backup ({len(custom)} custom provider definitions).")
        QMessageBox.information(self, "Providers restored", "The DNS provider catalogue was restored successfully.")

    def _export_profiles_backup(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export DNS profiles", "raider_dns_profiles.json", "JSON files (*.json)")
        if not path:
            return
        payload = {
            "format": "raiderdns-profile-backup", "version": 1,
            "profiles": list(self.settings.get("profiles", [])),
            "custom_providers": list(self.settings.get("custom_providers", [])),
        }
        try:
            Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Profile backup failed", str(exc))
            self._log("DNS profile backup export failed.", "ERROR")
            return
        self._log("Exported DNS profile backup.")
        QMessageBox.information(self, "Profiles exported", "DNS profiles and their custom-provider references were exported.")

    def _import_profiles_backup(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import DNS profiles", "", "JSON files (*.json)")
        if not path:
            return
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("format") != "raiderdns-profile-backup" or raw.get("version") != 1:
                raise ValueError("This file is not a supported Raider DNS profile backup.")
            if not isinstance(raw.get("profiles"), list):
                raise ValueError("The profile backup has no profile list.")
            provider_dependencies = self._sanitize_import_providers(raw.get("custom_providers", [])) if raw.get("custom_providers", []) else []
            current_custom = {item["id"]: item for item in self.settings.get("custom_providers", []) if isinstance(item, dict)}
            for item in provider_dependencies:
                current_custom.setdefault(item["id"], item)
            temp_custom = list(current_custom.values())
            known_ids = {item.id for item in PROVIDERS} | {item["id"] for item in temp_custom}
            known_doh = {item.id: item.doh_url for item in PROVIDERS}
            known_doh.update({item["id"]: item.get("doh_url") for item in temp_custom})
            clean_profiles: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for profile in raw["profiles"][:500]:
                if not isinstance(profile, dict):
                    continue
                name, servers = profile.get("name"), profile.get("servers")
                if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80 or not isinstance(servers, list) or not 1 <= len(servers) <= 8:
                    continue
                try:
                    if any(not isinstance(server, str) or ipaddress.ip_address(server).version != 4 for server in servers):
                        continue
                except ValueError:
                    continue
                provider_id = profile.get("provider_id")
                if provider_id not in known_ids:
                    provider_id = None
                doh_url = profile.get("doh_url")
                if not provider_id or not known_doh.get(provider_id) or doh_url != known_doh.get(provider_id):
                    doh_url = None
                profile_id = str(profile.get("id") or uuid.uuid4())[:100]
                if profile_id in seen_ids:
                    profile_id = str(uuid.uuid4())
                seen_ids.add(profile_id)
                clean_profiles.append({"id": profile_id, "name": name.strip(), "servers": servers, "provider_id": provider_id, "doh_url": doh_url, "created_at": str(profile.get("created_at", ""))[:40]})
            if raw["profiles"] and not clean_profiles:
                raise ValueError("No valid DNS profiles were found in this backup.")
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Invalid profile backup", str(exc))
            self._log("DNS profile backup import rejected.", "WARNING")
            return
        merge = QMessageBox.question(self, "Restore DNS profiles", "Merge imported profiles with your existing profiles? Choose No to replace the current profile list.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Yes)
        if merge == QMessageBox.StandardButton.Cancel:
            return
        if merge == QMessageBox.StandardButton.Yes:
            by_id = {row.get("id"): row for row in self.settings.get("profiles", []) if isinstance(row, dict)}
            by_id.update({row["id"]: row for row in clean_profiles})
            self.settings["profiles"] = list(by_id.values())[:500]
        else:
            self.settings["profiles"] = clean_profiles
        self.settings["custom_providers"] = temp_custom
        self._refresh_after_collection_import()
        self._log(f"Imported DNS profile backup ({len(clean_profiles)} profiles).")
        QMessageBox.information(self, "Profiles restored", "The DNS profiles were restored successfully.")

    def _import_settings(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Raider DNS settings", "", "JSON files (*.json)")
        if not path:
            return
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("The backup must contain a JSON object.")
            if raw.get("format") in {"raiderdns-provider-backup", "raiderdns-profile-backup"}:
                raise ValueError("This is a provider/profile backup. Use the matching Import DNS Providers or Import DNS Profiles button.")
            # Reuse the defensive settings normalizer so malformed values and
            # profiles are filtered before they reach widgets or system commands.
            merged = ConfigStore(Path(path)).load()
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Invalid backup", str(exc))
            self._log("Full settings backup import rejected.", "WARNING", str(exc))
            return
        self.settings = merged
        self.activity_store.limit = int(self.settings.get("activity_log_limit", 1000))
        self._save_settings()
        self._apply_theme()
        controls = [self.settings_theme_combo, self.flush_checkbox, self.confirm_checkbox, self.failover_checkbox, self.fallback_provider_combo, self.mode_combo, self.minimize_to_tray_checkbox, self.close_to_tray_checkbox]
        controls.extend([self.connection_dns_provider_combo, self.dns_scope_mode_combo, *self.connection_method_buttons.values()])
        for control in controls:
            control.blockSignals(True)
        selected_theme_index = self.settings_theme_combo.findData(self.settings.get("theme", "dark"))
        self.settings_theme_combo.setCurrentIndex(selected_theme_index if selected_theme_index >= 0 else 0)
        self.flush_checkbox.setChecked(bool(self.settings.get("flush_dns_after_apply", True)))
        self.confirm_checkbox.setChecked(bool(self.settings.get("confirm_dns_changes", True)))
        self.failover_checkbox.setChecked(bool(self.settings.get("failover_enabled", False)))
        self.minimize_to_tray_checkbox.setChecked(bool(self.settings.get("minimize_to_tray", True)))
        self.close_to_tray_checkbox.setChecked(bool(self.settings.get("close_to_tray", False)))
        fallback_index = self.fallback_provider_combo.findData(self.settings.get("fallback_provider", "quad9"))
        self.fallback_provider_combo.setCurrentIndex(fallback_index if fallback_index >= 0 else 2)
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(self.settings.get("dns_mode", "standard"))))
        conn_dns_idx = self.connection_dns_provider_combo.findData(self.settings.get("connection_dns_provider", "cloudflare"))
        self.connection_dns_provider_combo.setCurrentIndex(conn_dns_idx if conn_dns_idx >= 0 else 0)
        method = str(self.settings.get("connection_dns_method", "standard"))
        for method_id, button in self.connection_method_buttons.items():
            button.setChecked(method_id == method)
        scope_idx = self.dns_scope_mode_combo.findData(self.settings.get("dns_scope_mode", "inclusive"))
        self.dns_scope_mode_combo.setCurrentIndex(scope_idx if scope_idx >= 0 else 0)
        for control in controls:
            control.blockSignals(False)
        self._rebuild_provider_cards()
        self._refresh_provider_selector_options()
        self._refresh_dns_scope_browsers()
        self._dns_scope_mode_changed()
        self._connection_method_changed(method)
        self._connection_dns_provider_changed()
        self._update_favorite_controls()
        self._reorder_provider_cards()
        self._update_provider_selection_controls()
        self._update_provider_metrics()
        self._refresh_profiles()
        self._refresh_system_state()
        QMessageBox.information(self, "Backup imported", "Settings and saved profiles were imported.")
        self._log("Imported settings backup.")

    def _offer_relaunch_admin(self, operation: str) -> None:
        if not self.system_dns.is_windows():
            QMessageBox.information(self, "Windows only", "Elevation is available only for the Windows version of Raider DNS.")
            return
        answer = QMessageBox.question(
            self, "Administrator permission required",
            f"Raider DNS needs administrator permission to {operation}.\n\nRestart the app with elevation now? The current operation will not be resumed automatically; repeat it after the elevated window opens.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._relaunch_as_admin()

    def _relaunch_as_admin(self) -> None:
        """Relaunch this executable/script through the UAC 'runas' verb on Windows."""
        if not self.system_dns.is_windows():
            QMessageBox.information(self, "Windows only", "Administrator relaunch is supported only on Windows.")
            return
        if self.system_dns.is_admin():
            QMessageBox.information(self, "Already elevated", "Raider DNS is already running with administrator permissions.")
            if hasattr(self, "admin_button"):
                self.admin_button.setVisible(False)
            return
        try:
            executable = Path(sys.executable).resolve()
            if getattr(sys, "frozen", False) or "__compiled__" in globals():
                parameters = subprocess.list2cmdline(sys.argv[1:])
                working_directory = str(executable.parent)
            else:
                script = Path(sys.argv[0]).resolve()
                parameters = subprocess.list2cmdline([str(script), *sys.argv[1:]])
                working_directory = str(script.parent)
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", str(executable), parameters, working_directory, 1
            )
            if int(result) <= 32:
                raise OSError(f"Windows ShellExecute returned error code {result}.")
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self, "Could not restart as administrator",
                f"Windows could not start the elevated application.\n\n{exc}\n\nYou can also close Raider DNS and choose Run as administrator from its shortcut or executable.",
            )
            self._log("Administrator relaunch failed.", "ERROR", str(exc))
            return
        self._log("Launched an elevated Raider DNS instance; closing the unelevated instance.")
        self._exit_requested = True
        if self._tray_icon:
            self._tray_icon.hide()
        self.close()

    # ---- System operations --------------------------------------------------
    def _mode_changed(self, *_args: Any) -> None:
        self.settings["dns_mode"] = str(self.mode_combo.currentData())
        provider = self._selected_provider()
        if self.settings["dns_mode"] == "doh" and provider and not provider.supports_doh:
            QMessageBox.information(self, "DoH unavailable for this provider", "This provider has no configured DoH endpoint. Standard DNS will be selected instead.")
            self.settings["dns_mode"] = "standard"
        elif self.settings["dns_mode"] == "dot" and provider and not provider.dot_hostname:
            QMessageBox.information(self, "DoT unavailable for this provider", "This provider has no configured DoT hostname. Standard DNS will be selected instead.")
            self.settings["dns_mode"] = "standard"
        if self.mode_combo.currentData() != self.settings["dns_mode"]:
            self.mode_combo.blockSignals(True)
            self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(self.settings["dns_mode"])))
            self.mode_combo.blockSignals(False)
        self._save_settings()
        self._update_provider_metrics()
        self._animate_opacity(self.metric_security_status, "dns-mode-change", start_opacity=0.35, duration=280)
        self._log(f"Changed DNS mode to {self.settings['dns_mode']}.")

    def _selected_provider(self) -> DNSProvider | None:
        return self._provider(str(self.settings.get("selected_provider", "cloudflare")))

    def _update_provider_metrics(self) -> None:
        provider = self._selected_provider()
        if not provider:
            return
        mode = str(self.settings.get("dns_mode", "standard"))
        if mode == "doh" and not provider.supports_doh:
            mode = "standard"; self.settings["dns_mode"] = mode
        if mode == "dot" and not provider.dot_hostname:
            mode = "standard"; self.settings["dns_mode"] = mode
        if hasattr(self, "mode_combo") and self.mode_combo.currentData() != mode:
            self.mode_combo.blockSignals(True); self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(mode))); self.mode_combo.blockSignals(False)
        if mode == "doh":
            self.metric_security_status.setText("DoH selected")
            self.metric_security_details.setText(f"{provider.name} · Windows-native DoH selected. Actual system configuration and traffic use are not independently verified.")
        elif mode == "dot":
            self.metric_security_status.setText("DoT selected")
            self.metric_security_details.setText(f"{provider.name} · native Windows DoT will use {provider.dot_hostname}:853 with plaintext fallback disabled for the configured entry.")
        elif mode == "dnscrypt":
            self.metric_security_status.setText("DNSCrypt proxy selected")
            self.metric_security_details.setText("Local DNSCrypt proxy · signed resolver catalog · DNSSEC-capable/no-log resolver selection · post-quantum mode when supported. Verify the proxy is running.")
        else:
            self.metric_security_status.setText("Standard DNS selected")
            self.metric_security_details.setText(f"{provider.name} · {provider.primary} · Standard mode does not request DNS encryption.")
        if hasattr(self, "dashboard_provider_combo"):
            self.dashboard_provider_combo.blockSignals(True)
            selected_index = self.dashboard_provider_combo.findData(provider.id)
            if selected_index >= 0:
                self.dashboard_provider_combo.setCurrentIndex(selected_index)
            self.dashboard_provider_combo.blockSignals(False)

    def _adapter_changed(self, *_args: Any) -> None:
        if not hasattr(self, "adapter_combo"):
            return
        adapter = self.adapter_combo.currentData()
        if adapter:
            changed = self.settings.get("selected_adapter") != str(adapter)
            self.settings["selected_adapter"] = str(adapter)
            self._save_settings()
            if changed:
                self._log(f"Selected network adapter: {adapter}.")
            self._update_restore_previous_buttons()

    def _refresh_network_info(self, include_public: bool = True) -> None:
        if hasattr(self, "ip_refresh_button"):
            self.ip_refresh_button.setEnabled(False)
            self.ip_refresh_button.setText("Refreshing…")
        self._run_background(lambda: get_network_info(include_public=include_public), self._network_info_loaded, self._network_info_failed)

    def _network_info_loaded(self, result: Any) -> None:
        if hasattr(self, "ip_refresh_button"):
            self.ip_refresh_button.setEnabled(True)
            self.ip_refresh_button.setText("Refresh IP information")
        if not isinstance(result, dict):
            self._network_info_failed("The network information service returned an unexpected result.")
            return
        ipv4 = result.get("private_ipv4") or []
        ipv6 = result.get("private_ipv6") or []
        self.private_ipv4_label.setText(", ".join(ipv4) if ipv4 else "Not detected")
        self.private_ipv6_label.setText(", ".join(ipv6) if ipv6 else "Not detected")
        public_ip = str(result.get("public_ip", ""))
        self.public_ip_label.setText(public_ip or "Unavailable")
        self.ip_info_time_label.setText(str(result.get("public_error") or f"Updated {result.get('checked_at', 'just now')} · Public IP was checked through an external HTTPS service."))
        if not result.get("public_checked", True):
            self._log("Refreshed local private IP addresses; public IP lookup was skipped.")
        else:
            self._log("Refreshed network address information." if public_ip else "Refreshed network address information; public IP lookup failed.", "INFO" if public_ip else "WARNING")

    def _network_info_failed(self, error: str) -> None:
        if hasattr(self, "ip_refresh_button"):
            self.ip_refresh_button.setEnabled(True)
            self.ip_refresh_button.setText("Refresh IP information")
        if hasattr(self, "ip_info_time_label"):
            self.ip_info_time_label.setText(f"Network information unavailable: {error.splitlines()[0] if error else 'unknown error'}")
        self._log("Network address discovery failed.")

    def _flush_dns_cache(self) -> None:
        if not self.system_dns.is_windows():
            QMessageBox.information(self, "Windows only", "Flushing the Windows DNS Client cache is available on Windows only.")
            self._log("DNS cache flush requested on unsupported platform.", "WARNING")
            return
        if not self.system_dns.is_admin():
            self._log("DNS cache flush blocked: administrator permission required.", "WARNING")
            self._offer_relaunch_admin("flush the Windows DNS cache")
            return
        for button_name in ("flush_dashboard_button",):
            button = getattr(self, button_name, None)
            if button is not None:
                button.setEnabled(False)
        self._run_background(flush_dns_cache, self._flush_dns_cache_finished, self._flush_dns_cache_failed)

    def _flush_dns_cache_finished(self, outcome: Any) -> None:
        for button_name in ("flush_dashboard_button",):
            button = getattr(self, button_name, None)
            if button is not None:
                button.setEnabled(True)
        if not getattr(outcome, "success", False):
            detail = getattr(outcome, "output", "")
            QMessageBox.warning(self, "DNS cache flush failed", f"{getattr(outcome, 'message', 'Operation failed')}\n\n{detail}".strip())
            self._log("DNS cache flush failed.", "ERROR")
            return
        QMessageBox.information(self, "DNS cache flushed", getattr(outcome, "message", "DNS cache flushed."))
        self._log("Flushed the Windows DNS resolver cache.")

    def _flush_dns_cache_failed(self, error: str) -> None:
        for button_name in ("flush_dashboard_button",):
            button = getattr(self, button_name, None)
            if button is not None:
                button.setEnabled(True)
        QMessageBox.warning(self, "DNS cache flush failed", error.splitlines()[0] if error else "Unknown error")
        self._log("DNS cache flush raised an exception.", "ERROR")

    def _run_network_repair(self) -> None:
        selected = [key for key, checkbox in self.repair_checks.items() if checkbox.isChecked()]
        if not selected:
            QMessageBox.information(self, "No repair steps selected", "Select one or more repair operations first.")
            return
        disruptive = {"release_ip", "renew_ip", "winsock_reset", "tcpip_reset", "ipv6_reset", "reset_proxy"}
        selected_disruptive = [key for key in selected if key in disruptive]
        if selected_disruptive:
            labels = {
                "release_ip": "Release DHCP lease (may disconnect the adapter)",
                "renew_ip": "Renew DHCP lease (may briefly interrupt connectivity)",
                "winsock_reset": "Reset Winsock (may require reboot)",
                "tcpip_reset": "Reset IPv4 TCP/IP (may require reboot)",
                "ipv6_reset": "Reset IPv6 stack (may affect IPv6 connectivity)",
                "reset_proxy": "Reset WinHTTP proxy (removes its current proxy configuration)",
            }
            details = "\n".join("• " + labels.get(key, key) for key in selected_disruptive)
            warning = (
                "Review the selected actions carefully. These operations can interrupt networking or remove configuration.\n\n"
                + details + "\n\nProceed with the selected repairs?"
            )
            if QMessageBox.warning(self, "Confirm network repair", warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
                self._log("Cancelled network repair before commands were run.")
                return
        if not self.system_dns.is_windows():
            QMessageBox.warning(self, "Windows only", "Network repair commands are supported on Windows only.")
            return
        if not self.system_dns.is_admin():
            self._log("Network repair blocked: administrator permission required.", "WARNING")
            self._offer_relaunch_admin("repair the Windows network configuration")
            return
        for checkbox in self.repair_checks.values():
            checkbox.setEnabled(False)
        for button in getattr(self, "repair_selection_buttons", []):
            button.setEnabled(False)
        self.repair_button.setEnabled(False)
        self.statusBar().showMessage("Running selected Windows network repair steps…")
        selected_adapter = str(self.settings.get("selected_adapter", ""))
        self._run_background(lambda keys=tuple(selected), adapter=selected_adapter: repair_network(keys, adapter=adapter), self._network_repair_finished, self._network_repair_failed)

    def _network_repair_finished(self, outcomes: Any) -> None:
        for checkbox in getattr(self, "repair_checks", {}).values():
            checkbox.setEnabled(True)
        for button in getattr(self, "repair_selection_buttons", []):
            button.setEnabled(True)
        if hasattr(self, "repair_button"):
            self.repair_button.setEnabled(True)
        if not isinstance(outcomes, list):
            self._network_repair_failed("The repair service returned an unexpected result.")
            return
        lines: list[str] = []
        restart_needed = False
        any_failed = False
        for outcome in outcomes:
            success = bool(getattr(outcome, "success", False))
            any_failed = any_failed or not success
            restart_needed = restart_needed or bool(getattr(outcome, "requires_restart", False))
            title = str(getattr(outcome, "title", "Network repair"))
            message = str(getattr(outcome, "message", ""))
            lines.append(f"{'SUCCESS' if success else 'FAILED'} — {title}: {message}")
            output = str(getattr(outcome, "output", "")).strip()
            if output:
                lines.append(output[:1600])
            self._log(f"Network repair {'completed' if success else 'failed'}: {title}.", "INFO" if success else "ERROR", output[:1200] if output else message)
        if restart_needed:
            lines.append("\nRestart Windows if Winsock/TCP-IP changes do not take effect until reboot.")
        QMessageBox.information(self, "Network repair results", "\n\n".join(lines)[:9000]) if not any_failed else QMessageBox.warning(self, "Network repair partially failed", "\n\n".join(lines)[:9000])
        self.statusBar().showMessage("Network repair finished." if not any_failed else "Network repair finished with errors.", 6000)
        self._refresh_system_state()
        if hasattr(self, "connectivity_run_button"):
            self.troubleshooting_summary.setText("Manual repair finished. Run a fresh connectivity test to confirm whether the issue is resolved.")
            self._run_full_connectivity_test()

    def _network_repair_failed(self, error: str) -> None:
        for checkbox in getattr(self, "repair_checks", {}).values():
            checkbox.setEnabled(True)
        for button in getattr(self, "repair_selection_buttons", []):
            button.setEnabled(True)
        if hasattr(self, "repair_button"):
            self.repair_button.setEnabled(True)
        QMessageBox.critical(self, "Network repair error", error.splitlines()[0] if error else "Unknown error")
        self._log("Network repair raised an exception.", "ERROR")

    def _poll_network_changes(self) -> None:
        """Periodically inspect active adapters, DNS servers and local IP addresses."""
        if not self._exit_requested:
            self._refresh_system_state(automatic=True)

    def _configure_health_monitor(self, run_now: bool = False) -> None:
        if not hasattr(self, "_health_timer"):
            return
        self._health_generation += 1
        enabled = bool(self.settings.get("health_monitor_enabled", False))
        interval = max(15, min(300, int(self.settings.get("health_interval_seconds", 30))))
        if enabled:
            self._health_timer.start(interval * 1000)
            if run_now:
                QTimer.singleShot(350, self._run_health_check)
        else:
            self._health_timer.stop()
            self._health_check_in_flight = False
            self._health_state_tracker.reset()
            self._health_last_result = None
            self._health_state_provider_id = None
            self._health_probe_provider_id = None
        self._update_health_display(self._health_last_result)

    @staticmethod
    def _probe_selected_transport(provider: DNSProvider, mode: str, timeout: float):
        if mode == "doh":
            return probe_doh(provider, timeout=timeout)
        if mode == "dot":
            return probe_dot(provider, timeout=timeout)
        if mode == "dnscrypt":
            local_proxy = DNSProvider(provider.id, "DNSCrypt local proxy", "Local encrypted DNSCrypt health test", "127.0.0.1", "", "Local DNSCrypt")
            result = probe_udp(local_proxy, timeout=timeout)
            result.protocol = "DNSCrypt via local proxy (UDP/53)"
            result.message = ("Local proxy returned a DNS response; upstream encryption is provided by DNSCrypt." if result.success else result.message)
            return result
        return probe_udp(provider, timeout=timeout)

    def _run_health_check(self) -> None:
        if not self.settings.get("health_monitor_enabled", False) or self._health_check_in_flight or self._exit_requested:
            return
        provider = self._selected_provider()
        if provider is None:
            return
        self._health_check_in_flight = True
        if self._health_state_provider_id != provider.id:
            self._health_state_provider_id = provider.id
            self._health_state_tracker.reset()
            self._health_last_result = None
        self._health_probe_provider_id = provider.id
        self._health_probe_generation = self._health_generation
        generation = self._health_probe_generation
        self._health_active_probe_generation = generation
        if hasattr(self, "metric_dns_health"):
            self.metric_dns_health.setText("Checking…")
            self.metric_dns_health_details.setText(f"Testing {provider.name} with a fresh DNS request.")
        if hasattr(self, "security_health_value"):
            self.security_health_value.setText("Checking…")
        mode = str(self.settings.get("dns_mode", "standard"))
        timeout = float(self.settings.get("health_timeout_seconds", 2.5))
        if mode == "doh" and not provider.supports_doh:
            mode = "standard"
        self._run_background(
            lambda p=provider, m=mode, t=timeout: self._probe_selected_transport(p, m, t).to_dict(),
            lambda result, pid=provider.id, gen=generation: self._health_probe_finished(result, pid, gen),
            lambda error, pid=provider.id, gen=generation: self._health_probe_failed(error, pid, gen),
        )

    def _health_probe_finished(self, result: Any, probe_provider_id: str | None = None, probe_generation: int | None = None) -> None:
        # A superseded worker (for example, from before monitoring was disabled
        # and re-enabled) must never clear the in-flight flag for a newer probe.
        if probe_generation is not None and probe_generation != self._health_active_probe_generation:
            if self.settings.get("health_monitor_enabled", False) and not self._health_check_in_flight:
                QTimer.singleShot(100, self._run_health_check)
            return
        self._health_check_in_flight = False
        if not self.settings.get("health_monitor_enabled", False):
            return
        if probe_generation is not None and probe_generation != self._health_generation:
            QTimer.singleShot(100, self._run_health_check)
            return
        expected_provider_id = str(self.settings.get("selected_provider", ""))
        result_provider_id = str(result.get("provider_id", "")) if isinstance(result, dict) else ""
        if (probe_provider_id and probe_provider_id != expected_provider_id) or (result_provider_id and result_provider_id != expected_provider_id):
            QTimer.singleShot(100, self._run_health_check)
            return
        if not isinstance(result, dict):
            self._health_probe_failed("The health monitor returned an unexpected result.", probe_provider_id, probe_generation)
            return
        self._health_last_result = result
        self._health_state_provider_id = expected_provider_id
        self._health_probe_provider_id = probe_provider_id or expected_provider_id
        success = bool(result.get("success"))
        transition = self._health_state_tracker.record(
            success,
            int(self.settings.get("health_failure_threshold", 3)),
            int(self.settings.get("health_recovery_threshold", 2)),
        )
        provider = self._provider(str(result.get("provider_id", "")))
        provider_name = provider.name if provider else str(result.get("provider_name", "selected DNS provider"))
        latency = result.get("latency_ms")
        if transition.changed and transition.current == "unhealthy":
            detail = str(result.get("message", "DNS query failed"))
            self._log(f"DNS health warning: {provider_name} failed {transition.failures} consecutive checks.", "ERROR", detail)
            self._show_app_notification("DNS health warning", f"{provider_name} failed {transition.failures} consecutive checks. {detail}", "error")
        elif transition.changed and transition.previous == "unhealthy" and transition.current == "healthy":
            self._log(f"DNS health recovered: {provider_name} responded again.")
            self._show_app_notification("DNS health recovered", f"{provider_name} has returned successful DNS responses.", "success")
        self._update_health_display(result)

    def _health_probe_failed(self, error: str, probe_provider_id: str | None = None, probe_generation: int | None = None) -> None:
        if probe_generation is not None and probe_generation != self._health_active_probe_generation:
            if self.settings.get("health_monitor_enabled", False) and not self._health_check_in_flight:
                QTimer.singleShot(100, self._run_health_check)
            return
        self._health_check_in_flight = False
        if not self.settings.get("health_monitor_enabled", False):
            return
        if probe_generation is not None and probe_generation != self._health_generation:
            QTimer.singleShot(100, self._run_health_check)
            return
        expected_provider_id = str(self.settings.get("selected_provider", ""))
        if probe_provider_id and probe_provider_id != expected_provider_id:
            QTimer.singleShot(100, self._run_health_check)
            return
        detail = error.splitlines()[0] if error else "Unexpected health-check error"
        result = {"provider_id": str(self.settings.get("selected_provider", "")), "success": False, "latency_ms": None, "message": detail}
        self._health_last_result = result
        self._health_probe_provider_id = probe_provider_id or expected_provider_id
        transition = self._health_state_tracker.record(
            False,
            int(self.settings.get("health_failure_threshold", 3)),
            int(self.settings.get("health_recovery_threshold", 2)),
        )
        provider = self._selected_provider()
        if transition.changed and transition.current == "unhealthy":
            self._log(f"DNS health warning: {provider.name if provider else 'Selected resolver'} failed repeated checks.", "ERROR", detail)
            self._show_app_notification("DNS health warning", detail, "error")
        self._update_health_display(result)

    def _update_health_display(self, result: dict[str, Any] | None) -> None:
        if not self.settings.get("health_monitor_enabled", False):
            if hasattr(self, "security_health_value"):
                self.security_health_value.setText("Not enabled")
                self.security_health_detail.setText("Enable the monitor in Settings → DNS Health Monitor. No background DNS checks are running.")
            return
        state = self._health_state_tracker.state
        labels = {"unknown": "Monitoring", "healthy": "Healthy", "unhealthy": "Unhealthy"}
        status = labels.get(state, "Monitoring")
        provider = self._selected_provider()
        provider_name = provider.name if provider else "Selected provider"
        last_result = result or {}
        if last_result.get("success"):
            detail = f"{provider_name} · last query {last_result.get('latency_ms', 'n/a')} ms · checks every {self.settings.get('health_interval_seconds', 30)} s"
        elif last_result:
            detail = f"{provider_name} · {last_result.get('message', 'No DNS response')} · consecutive failures {self._health_state_tracker.consecutive_failures}/{self.settings.get('health_failure_threshold', 3)}"
        else:
            detail = f"Waiting for a result · checks every {self.settings.get('health_interval_seconds', 30)} s"
        if hasattr(self, "metric_dns_health"):
            self.metric_dns_health.setText(status)
            self.metric_dns_health_details.setText(detail)
        if hasattr(self, "security_health_value"):
            self.security_health_value.setText(status)
            self.security_health_detail.setText(
                f"Monitoring {provider_name} every {self.settings.get('health_interval_seconds', 30)} seconds with a {self.settings.get('health_timeout_seconds', 2.5)}-second timeout. {detail}. "
                "This tests the selected provider, not every application's effective resolver. System DNS is not changed automatically."
            )

    def _refresh_system_state(self, *_args: Any, automatic: bool = False, operation_followup: bool = False) -> None:
        if self._system_state_refresh_in_flight:
            if operation_followup:
                self._pending_post_apply_refresh = True
            return
        self._system_state_refresh_in_flight = True
        if not automatic:
            self.statusBar().showMessage("Checking network adapters and DNS configuration…")
        self._run_background(
            lambda: {
                "adapters": self.system_dns.get_adapters(),
                "dns": self.system_dns.get_dns_configuration(),
                "network_info": get_network_info(include_public=False),
                "admin": self.system_dns.is_admin(),
            },
            lambda result, auto=automatic, followup=operation_followup: self._system_state_loaded(result, automatic=auto, post_dns_apply=followup),
            lambda error, auto=automatic, followup=operation_followup: self._system_state_failed(error, automatic=auto, post_dns_apply=followup),
        )

    def _continue_pending_dns_followup(self, completed_post_dns_apply: bool) -> None:
        if self._pending_post_apply_refresh and not completed_post_dns_apply and not self._exit_requested:
            self._pending_post_apply_refresh = False
            QTimer.singleShot(120, lambda: self._refresh_system_state(automatic=True, operation_followup=True))

    def _system_state_failed(self, error: str, automatic: bool = False, post_dns_apply: bool = False) -> None:
        self._system_state_refresh_in_flight = False
        if not automatic:
            self.statusBar().showMessage(f"System inspection failed: {error.splitlines()[0] if error else 'unknown error'}", 7000)
        self._continue_pending_dns_followup(post_dns_apply)

    def _system_state_loaded(self, result: Any, automatic: bool = False, post_dns_apply: bool = False) -> None:
        self._system_state_refresh_in_flight = False
        if not isinstance(result, dict):
            if not automatic:
                self.statusBar().showMessage("System inspection returned an unexpected result.", 5000)
            self._continue_pending_dns_followup(post_dns_apply)
            return
        new_adapters = list(result.get("adapters", []))
        new_dns = list(result.get("dns", []))
        network_info = result.get("network_info", {})
        current_signature = build_network_signature(
            new_adapters, new_dns, network_info if isinstance(network_info, dict) else {}
        )
        previous_signature = self._network_state_signature
        self._adapters = new_adapters
        self._adapter_dns = new_dns
        self._network_state_signature = current_signature

        # The first successful inspection establishes a baseline; subsequent differences
        # are reported without modal dialogs so background polling never interrupts work.
        suppress_dns_toast = self._suppress_next_dns_change_notification if post_dns_apply else False
        if post_dns_apply:
            self._suppress_next_dns_change_notification = False
        if previous_signature is not None and current_signature != previous_signature:
            changes = describe_network_changes(previous_signature, current_signature)
            if changes:
                detail = "\n".join(changes)
                dns_only_change = all(change.startswith("DNS servers for ") for change in changes)
                if suppress_dns_toast and dns_only_change:
                    self._log("Confirmed DNS configuration change after Raider DNS apply/restore.", "INFO", detail)
                    self.statusBar().showMessage("DNS configuration change confirmed.", 3500)
                    # The DNS operation already showed its own distinct completion toast.
                    changes = []
                if not changes:
                    pass
                else:
                    transition = classify_network_transition(previous_signature, current_signature)
                    if transition == "disconnected":
                        title = "Network disconnected"
                        body = "No active network adapter was detected. DNS checks may fail until the connection returns."
                        kind = "error"
                    elif transition == "reconnected":
                        title = "Network reconnected"
                        body = f"An active network adapter is available: {', '.join(new_adapters[:3])}."
                        kind = "success"
                    else:
                        title = "Network configuration changed"
                        body = "Adapter, DNS server or local IP information changed. Review the activity details if this was unexpected."
                        kind = "warning"
                    self._log(title + ".", "WARNING" if kind != "success" else "INFO", detail)
                    self.statusBar().showMessage(title + ".", 6500)
                    if hasattr(self, "connection_badge"):
                        self._animate_opacity(self.connection_badge, "network-change", start_opacity=0.40, duration=430)
                    self._show_app_notification(title, body, kind)

        if hasattr(self, "admin_button"):
            self.admin_button.setVisible(self.system_dns.is_windows() and not bool(result.get("admin", False)))
        if hasattr(self, "adapter_combo"):
            previous = str(self.settings.get("selected_adapter", ""))
            # Preserve a disconnected adapter in the selector when it still has
            # a recovery record. This lets users restore its original DNS after
            # Wi-Fi/Ethernet drops instead of silently switching the selection.
            recovery_for_previous = bool(previous and previous not in self._adapters and self.system_dns.has_previous_settings(previous))
            display_items: list[tuple[str, str]] = [(adapter, adapter) for adapter in self._adapters]
            if recovery_for_previous:
                display_items.append((f"{previous} (disconnected · recovery available)", previous))
            if not display_items:
                display_items = [("No active Windows adapters", "")]
            combo_data = [str(self.adapter_combo.itemData(index) or "") for index in range(self.adapter_combo.count())]
            expected_data = [value for _label, value in display_items]
            expected_selection = previous if previous in expected_data else (self._adapters[0] if self._adapters else "")
            current_selection = str(self.adapter_combo.currentData() or "")
            if combo_data != expected_data or current_selection != expected_selection:
                self.adapter_combo.blockSignals(True)
                self.adapter_combo.clear()
                for label, value in display_items:
                    self.adapter_combo.addItem(label, value)
                selected_index = self.adapter_combo.findData(expected_selection)
                self.adapter_combo.setCurrentIndex(selected_index if selected_index >= 0 else 0)
                if previous not in self._adapters and not recovery_for_previous and self._adapters:
                    self.settings["selected_adapter"] = self._adapters[0]
                    self._save_settings()
                self.adapter_combo.blockSignals(False)

        self._update_restore_previous_buttons()
        old_connection_status = self.metric_connection_status.text()
        old_connection_details = self.metric_connection_details.text()
        old_badge_text = self.connection_badge.text()
        selected_adapter = str(self.settings.get("selected_adapter", ""))
        rows_for_selected = [row for row in self._adapter_dns if row.get("adapter") == selected_adapter]
        ipv4_rows = [row for row in rows_for_selected if str(row.get("family", "IPv4")).casefold() == "ipv4"]
        addresses = ipv4_rows[0].get("servers", []) if ipv4_rows else []
        adapter_active = bool(selected_adapter and selected_adapter in self._adapters)
        if adapter_active:
            self.metric_connection_status.setText("Connected")
            self.metric_connection_details.setText(f"{selected_adapter} is active · Internet reachability is not independently tested here")
            self.connection_badge.setText("●  Adapter active")
            self.connection_badge.setObjectName("StatusPill")
        elif not self.system_dns.is_windows():
            self.metric_connection_status.setText("Preview mode")
            self.metric_connection_details.setText("Windows adapter inspection is unavailable on this OS")
            self.connection_badge.setText("●  Preview mode")
            self.connection_badge.setObjectName("WarningPill")
        else:
            self.metric_connection_status.setText("No active adapter")
            self.metric_connection_details.setText("No active adapter matches the selected network")
            self.connection_badge.setText("●  Needs inspection")
            self.connection_badge.setObjectName("WarningPill")

        if addresses:
            details = f"{selected_adapter} · configured DNS: {', '.join(str(item) for item in addresses[:3])}"
        elif not self.system_dns.is_windows():
            details = "System DNS configuration inspection is Windows-only"
        else:
            details = "No IPv4 DNS servers were returned for the selected adapter"
        if hasattr(self, "metric_security_details"):
            mode = self.settings.get("dns_mode", "standard")
            provider = self._selected_provider()
            provider_name = provider.name if provider else "Selected provider"
            if mode == "doh" and provider and provider.supports_doh:
                self.metric_security_status.setText("DoH selected")
                self.metric_security_details.setText(f"{provider_name} · selected for the next apply; actual system configuration and traffic use are not verified. {details}.")
            else:
                self.metric_security_status.setText("Standard DNS selected")
                self.metric_security_details.setText(f"{provider_name} · selected for the next apply. {details}. DNS encryption is not implied.")

        if self.connection_badge.text() != old_badge_text:
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
            self._animate_opacity(self.connection_badge, "connection-status-badge", start_opacity=0.62, duration=280)
        if (self.metric_connection_status.text(), self.metric_connection_details.text()) != (old_connection_status, old_connection_details):
            self._animate_opacity(self.metric_connection_status, "connection-status", start_opacity=0.72, duration=250)
        if hasattr(self, "audit_text"):
            if self._adapter_dns:
                report = "\n".join(
                    f"{row['adapter']} ({row.get('family', 'IPv4')}): {', '.join(row['servers'])}"
                    for row in self._adapter_dns
                )
                self.audit_text.setText(report)
            elif not self.system_dns.is_windows():
                self.audit_text.setText("DNS configuration inspection is available only on Windows. Resolver reachability tests may still work here.")
            else:
                self.audit_text.setText("No DNS servers were returned. Check adapter connectivity or run the app as Administrator.")
        if not automatic:
            self.statusBar().showMessage("Network inspection completed.", 4500)
        self._continue_pending_dns_followup(post_dns_apply)

    def _apply_selected_provider(self) -> None:
        provider = self._selected_provider()
        mode = str(self.settings.get("dns_mode", "standard"))
        if mode == "dnscrypt":
            if hasattr(self, "connection_method_buttons"):
                self.connection_method_buttons["dnscrypt"].setChecked(True)
            self._connection_method_changed("dnscrypt")
            self._apply_dnscrypt_connection()
            return
        if not provider:
            QMessageBox.warning(self, "Select a provider", "Choose a DNS provider first.")
            return
        if mode == "dot":
            if hasattr(self, "connection_dns_provider_combo"):
                self.connection_dns_provider_combo.setCurrentIndex(max(0, self.connection_dns_provider_combo.findData(provider.id)))
                self.connection_method_buttons["dot"].setChecked(True)
            self._connection_method_changed("dot")
            self._apply_dot_connection(provider)
            return
        use_doh = mode == "doh"
        if use_doh and not provider.supports_doh:
            QMessageBox.warning(self, "DoH unavailable", f"{provider.name} has no configured DoH endpoint in this app.")
            return
        servers = list(provider.servers)
        templates: dict[str, str] | None = {server: str(provider.doh_url) for server in servers} if use_doh and provider.doh_url else None
        if self.settings.get("failover_enabled"):
            fallback = self._provider(str(self.settings.get("fallback_provider", "quad9")))
            if fallback and fallback.id != provider.id:
                if use_doh and not fallback.supports_doh:
                    QMessageBox.warning(self, "Fallback does not support DoH", f"{fallback.name} has no configured DoH template. Choose a DoH-capable fallback or switch to Standard DNS.")
                    return
                for server in fallback.servers:
                    if server not in servers:
                        servers.append(server)
                    if templates is not None and fallback.doh_url:
                        templates[server] = fallback.doh_url
        label = provider.name
        if self.settings.get("failover_enabled") and len(servers) > len(provider.servers):
            fallback = self._provider(str(self.settings.get("fallback_provider", "quad9")))
            if fallback and fallback.id != provider.id:
                label += f" (fallback: {fallback.name})"
        self._perform_apply(servers, templates, label)

    def _perform_apply(
        self, servers: list[str], doh_url: str | dict[str, str] | None, display_name: str,
        *, allow_unverified_doh_preflight: bool = False, already_confirmed: bool = False,
    ) -> None:
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._log(f"Apply DNS blocked for {display_name}: administrator permission required.", "WARNING")
            self._offer_relaunch_admin("apply the selected DNS configuration")
            return
        adapter = self.adapter_combo.currentData() if hasattr(self, "adapter_combo") else self.settings.get("selected_adapter", "")
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "No active Windows adapter is available. Refresh adapters and try again.")
            return
        if self.settings.get("confirm_dns_changes", True) and not already_confirmed:
            mode_label = "Windows DNS-over-HTTPS" if doh_url else "standard DNS"
            confirm = QMessageBox.question(
                self, "Apply DNS configuration",
                f"Apply {display_name} to adapter ‘{adapter}’?\n\nDNS servers: {', '.join(servers)}\nMode: {mode_label}\n\nThis changes system DNS for the selected adapter. Resolver reachability will be reported separately from whether Windows accepted the settings.",
                QMessageBox.StandardButton.Apply | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if confirm != QMessageBox.StandardButton.Apply:
                return
        self._set_connection_operation_busy(True, "connecting")
        self.dns_connection_visual.set_state("connecting")
        if hasattr(self, "connection_visual"):
            self.connection_visual.set_state("connecting")
        if hasattr(self, "connection_badge"):
            self.connection_badge.setText("●  Applying DNS…")
            self.connection_badge.setObjectName("WarningPill")
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
            self._start_dns_status_pulse()
        self.statusBar().showMessage(f"Applying {display_name}…")
        flush_cache = bool(self.settings.get("flush_dns_after_apply", True))
        def completed(result: Any) -> None:
            if (
                isinstance(result, DNSOperationResult)
                and not result.success
                and result.message == "DoH endpoint preflight failed"
                and doh_url is not None
                and not allow_unverified_doh_preflight
            ):
                answer = QMessageBox.question(
                    self, "DoH endpoint could not be verified",
                    f"Raider DNS could not reach and authenticate the configured DoH endpoint for {display_name}.\n\n"
                    f"{result.details}\n\nApply the Windows DoH registration anyway? The Windows DNS settings will be checked after the change, but DNS may remain unavailable on this network. Your previous settings will remain available for recovery.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Cancel,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self._perform_apply(
                        servers, doh_url, display_name,
                        allow_unverified_doh_preflight=True, already_confirmed=True,
                    )
                    return
            self._dns_operation_finished(result, f"Applied {display_name}")
        self._run_background(
            lambda: self.system_dns.apply_dns(
                str(adapter), list(servers), doh_url, flush_cache,
                allow_unverified_doh_preflight=allow_unverified_doh_preflight,
            ),
            completed,
            lambda error: self._dns_operation_error(error),
        )

    def _restore_automatic_dns(self) -> None:
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._log("Restore automatic DNS blocked: administrator permission required.", "WARNING")
            self._offer_relaunch_admin("restore automatic DNS on the selected adapter")
            return
        adapter = self.adapter_combo.currentData() if hasattr(self, "adapter_combo") else ""
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "Select an active Windows adapter first.")
            return
        if self.settings.get("confirm_dns_changes", True):
            confirm = QMessageBox.question(self, "Restore automatic DNS", f"Restore the DNS configuration for ‘{adapter}’ to automatic assignment?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if confirm != QMessageBox.StandardButton.Yes:
                return
        self._set_connection_operation_busy(True, "connecting")
        self.dns_connection_visual.set_state("connecting")
        if hasattr(self, "connection_visual"):
            self.connection_visual.set_state("connecting")
        if hasattr(self, "connection_badge"):
            self.connection_badge.setText("●  Restoring automatic DNS…")
            self.connection_badge.setObjectName("WarningPill")
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
            self._start_dns_status_pulse()
        flush_cache = bool(self.settings.get("flush_dns_after_apply", True))
        self._run_background(
            lambda: self.system_dns.restore_dhcp(str(adapter), flush_cache),
            lambda result: self._dns_operation_finished(result, "Restored automatic DNS"),
            lambda error: self._dns_operation_error(error),
        )

    def _restore_previous_dns_settings(self) -> None:
        """Restore the exact saved adapter configuration rather than assuming DHCP."""
        if self._dns_operation_in_flight:
            self.statusBar().showMessage("A DNS operation is already running. Wait for it to finish before restoring settings.", 5000)
            return
        if self.system_dns.is_windows() and not self.system_dns.is_admin():
            self._log("Restore previous DNS blocked: administrator permission required.", "WARNING")
            self._offer_relaunch_admin("restore previous DNS settings on the selected adapter")
            return
        adapter = str(self.adapter_combo.currentData() or "") if hasattr(self, "adapter_combo") else ""
        if not adapter:
            QMessageBox.warning(self, "No network adapter", "Select an active network adapter first.")
            return
        if not self.system_dns.has_previous_settings(adapter):
            QMessageBox.information(self, "No restore point", f"Raider DNS has no saved previous DNS settings for {adapter}. Apply a DNS configuration through Raider DNS first.")
            self._update_restore_previous_buttons()
            return
        answer = QMessageBox.question(
            self, "Restore Previous DNS Settings",
            f"Restore the DNS settings captured before Raider DNS last changed {adapter}?\n\n"
            "This may restore manual IPv4/IPv6 DNS, automatic/DHCP settings, and touched DoH/DoT registrations. "
            "The current configuration will be retained as a rollback point if restoration fails.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._set_connection_operation_busy(True, "connecting")
        if hasattr(self, "connection_badge"):
            self.connection_badge.setText("●  Restoring previous DNS…")
            self.connection_badge.setObjectName("WarningPill")
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
        if hasattr(self, "connection_status_label"):
            self.connection_status_label.setText("Restoring previous DNS settings…")
            self.connection_status_detail.setText("Reading the durable restore point and restoring the prior IPv4/IPv6 and encrypted-DNS registrations.")
        self.statusBar().showMessage(f"Restoring previous DNS settings for {adapter}…")
        self._run_background(
            lambda a=adapter: self.system_dns.restore_previous_dns_settings(a),
            lambda result: self._dns_operation_finished(result, "Restored previous DNS settings"),
            self._dns_operation_error,
        )

    def _dns_operation_finished(self, result: Any, success_label: str) -> None:
        self._stop_dns_status_pulse()
        self._set_connection_operation_busy(False, "idle")
        if not isinstance(result, DNSOperationResult):
            self.dns_connection_visual.set_state("failure")
            if hasattr(self, "connection_visual"):
                self.connection_visual.set_state("failure")
            if hasattr(self, "connection_apply_button"):
                self.connection_apply_button.setEnabled(True)
            self.connection_badge.setText("●  DNS result unavailable")
            self.connection_badge.setObjectName("WarningPill")
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
            QMessageBox.warning(self, "Unexpected system result", "The DNS operation returned an unexpected result.")
            self._show_app_notification("DNS result unavailable", "Windows returned an unexpected DNS operation result.", "error")
            return
        if result.success and result.verified is False:
            # Windows accepted the requested DNS settings and read-back matched.
            # Resolver reachability is reported separately; it must not be
            # mislabelled as a rollback or trigger an automatic config reversal.
            self.dns_connection_visual.set_state("warning")
            if hasattr(self, "connection_visual"):
                self.connection_visual.set_state("warning")
            adapter_name = self.settings.get("selected_adapter") or "selected adapter"
            detail = result.details or result.message
            label_lower = success_label.casefold()
            if "previous" in label_lower:
                status_heading = "Previous DNS settings restored · connectivity unverified"
            elif "automatic" in label_lower or "dhcp" in label_lower:
                status_heading = "Automatic DNS configured · connectivity unverified"
            else:
                status_heading = "DNS settings applied · connectivity unverified"
            if hasattr(self, "connection_status_label"):
                self.connection_status_label.setText(status_heading)
                self.connection_status_detail.setText(detail)
                self.connection_status_pill.setText("●  CHECK CONNECTIVITY")
                self.connection_status_pill.setObjectName("WarningPill")
                self.connection_status_pill.style().unpolish(self.connection_status_pill)
                self.connection_status_pill.style().polish(self.connection_status_pill)
            if hasattr(self, "connection_badge"):
                self.connection_badge.setText("●  DNS configured · check connection")
                self.connection_badge.setObjectName("WarningPill")
                self.connection_badge.style().unpolish(self.connection_badge)
                self.connection_badge.style().polish(self.connection_badge)
            self.statusBar().showMessage(f"{success_label}; resolver reachability needs attention.", 8000)
            self._log(f"{success_label}; resolver reachability could not be verified on {adapter_name}.", "WARNING", detail)
            self._show_app_notification("DNS settings applied — check connectivity", f"{adapter_name}: Windows settings were applied, but resolver reachability was not confirmed.", "warning")
            self._suppress_next_dns_change_notification = True
            self._refresh_system_state(operation_followup=True)
            self._update_restore_previous_buttons()
            return
        if result.success:
            visual_state = "success" if result.verified is True else "warning"
            self.dns_connection_visual.set_state(visual_state)
            if hasattr(self, "connection_visual"):
                self.connection_visual.set_state(visual_state)
            adapter_name = self.settings.get("selected_adapter") or "selected adapter"
            if result.verified is True:
                verification_text = "DNS settings and DNS/HTTPS connectivity were independently verified."
                pill_text = "●  VERIFIED"
                badge_text = "●  DNS verified"
                notification_title = "DNS configuration verified"
                notification_kind = "success"
            else:
                verification_text = "The configuration command returned success, but independent DNS/HTTPS connectivity verification was not available for this operation."
                pill_text = "●  CONFIGURED"
                badge_text = "●  DNS settings applied"
                notification_title = "DNS configuration applied"
                notification_kind = "warning"
            full_detail = f"{success_label}. {verification_text} {result.details}".strip()
            if hasattr(self, "connection_status_label"):
                label_lower = success_label.casefold()
                if "previous" in label_lower:
                    status_heading = "Previous DNS settings restored"
                elif "automatic" in label_lower or "dhcp" in label_lower:
                    status_heading = "Automatic DNS restored"
                else:
                    status_heading = "System DNS configured"
                if result.verified is not True:
                    status_heading += " · verification incomplete"
                self.connection_status_label.setText(status_heading)
                self.connection_status_detail.setText(full_detail)
                self.connection_status_pill.setText(pill_text)
                self.connection_status_pill.setObjectName("StatusPill" if result.verified is True else "WarningPill")
                self.connection_status_pill.style().unpolish(self.connection_status_pill)
                self.connection_status_pill.style().polish(self.connection_status_pill)
            if hasattr(self, "connection_badge"):
                self.connection_badge.setText(badge_text)
                self.connection_badge.setObjectName("StatusPill" if result.verified is True else "WarningPill")
                self.connection_badge.style().unpolish(self.connection_badge)
                self.connection_badge.style().polish(self.connection_badge)
                self._animate_opacity(self.connection_badge, "dns-operation", start_opacity=0.45, duration=420)
            self.statusBar().showMessage(f"{success_label}. {result.message}", 6000)
            self._log(f"{success_label} on {adapter_name}.", "INFO" if result.verified is True else "WARNING", full_detail)
            self._show_app_notification(notification_title, f"{success_label} on {adapter_name}.", notification_kind)
            self._suppress_next_dns_change_notification = True
            self._refresh_system_state(operation_followup=True)
            self._update_restore_previous_buttons()
        else:
            self._suppress_next_dns_change_notification = False
            self.dns_connection_visual.set_state("failure")
            if hasattr(self, "connection_visual"):
                self.connection_visual.set_state("failure")
            if hasattr(self, "connection_status_label"):
                self.connection_status_label.setText("System DNS change failed")
                self.connection_status_detail.setText(result.message)
                self.connection_status_pill.setText("●  FAILED")
                self.connection_status_pill.setObjectName("ErrorPill")
                self.connection_status_pill.style().unpolish(self.connection_status_pill)
                self.connection_status_pill.style().polish(self.connection_status_pill)
            if hasattr(self, "connection_badge"):
                self.connection_badge.setText("●  DNS change failed")
                self.connection_badge.setObjectName("ErrorPill")
                self.connection_badge.style().unpolish(self.connection_badge)
                self.connection_badge.style().polish(self.connection_badge)
                self._animate_opacity(self.connection_badge, "dns-operation", start_opacity=0.45, duration=420)
            detail = f"{result.message}\n\n{result.details}" if result.details else result.message
            QMessageBox.warning(self, "DNS change failed", detail)
            self._log(f"DNS operation failed: {result.message}.", "ERROR", result.details)
            self._show_app_notification("DNS change failed", result.message, "error")
            self.statusBar().showMessage(result.message, 6000)
            self._update_restore_previous_buttons()

    def _dns_operation_error(self, error: str) -> None:
        self._stop_dns_status_pulse()
        self._set_connection_operation_busy(False, "failure")
        self.dns_connection_visual.set_state("failure")
        if hasattr(self, "connection_visual"):
            self.connection_visual.set_state("failure")
        if hasattr(self, "connection_status_label"):
            self.connection_status_label.setText("System DNS operation failed")
            self.connection_status_detail.setText(error.splitlines()[0] if error else "Unknown error")
            self.connection_status_pill.setText("●  FAILED")
            self.connection_status_pill.setObjectName("ErrorPill")
            self.connection_status_pill.style().unpolish(self.connection_status_pill)
            self.connection_status_pill.style().polish(self.connection_status_pill)
        if hasattr(self, "connection_badge"):
            self.connection_badge.setText("●  DNS operation failed")
            self.connection_badge.setObjectName("ErrorPill")
            self.connection_badge.style().unpolish(self.connection_badge)
            self.connection_badge.style().polish(self.connection_badge)
            self._animate_opacity(self.connection_badge, "dns-operation", start_opacity=0.40, duration=380)
        self._suppress_next_dns_change_notification = False
        first_line = error.splitlines()[0] if error else "Unknown error"
        QMessageBox.critical(self, "DNS operation error", first_line)
        self._log(f"DNS operation exception: {first_line}.", "ERROR")
        self._show_app_notification("DNS operation error", first_line, "error")
        self._update_restore_previous_buttons()

    # ---- Shared helpers -----------------------------------------------------
    def _run_background(self, task: Callable[[], Any], on_result: Callable[[Any], None], on_error: Callable[[str], None] | None = None) -> None:
        worker = Worker(task)
        self._workers.add(worker)
        # Do not invoke UI callbacks directly from QRunnable's worker thread.
        worker.signals.result.connect(
            lambda value, callback=on_result: (
                self._dispatcher.invoke.emit(callback, value) if not self._shutdown_started else None
            )
        )
        error_callback = on_error or (lambda message: self.statusBar().showMessage(message.splitlines()[0], 8000))
        worker.signals.error.connect(
            lambda message, callback=error_callback: (
                self._dispatcher.invoke.emit(callback, message) if not self._shutdown_started else None
            )
        )
        # Bookkeeping only: no UI access is needed to drop a completed worker.
        worker.signals.finished.connect(lambda w=worker: self._workers.discard(w))
        if self._shutdown_started:
            self._workers.discard(worker)
            return
        self.thread_pool.start(worker)

    def _start_dns_status_pulse(self) -> None:
        """Pulse the connection badge while a DNS apply/restore task is in progress."""
        self._stop_dns_status_pulse()
        if not hasattr(self, "connection_badge"):
            return
        previous_effect = self.connection_badge.graphicsEffect()
        for existing_key, existing_animation in list(self._ui_animations.items()):
            if previous_effect is not None and existing_animation.targetObject() is previous_effect:
                self._ui_animations.pop(existing_key, None)
                existing_animation.stop()
                existing_animation.deleteLater()
        if previous_effect is not None:
            self.connection_badge.setGraphicsEffect(None)
        effect = QGraphicsOpacityEffect(self.connection_badge)
        self.connection_badge.setGraphicsEffect(effect)
        effect.setOpacity(0.58)
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(850)
        animation.setStartValue(0.58)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        animation.setLoopCount(-1)
        self._ui_animations["dns-operation-pulse"] = animation
        animation.start()

    def _stop_dns_status_pulse(self) -> None:
        animation = self._ui_animations.pop("dns-operation-pulse", None)
        badge = getattr(self, "connection_badge", None)
        pulse_effect = animation.targetObject() if animation is not None else None
        if animation is not None:
            animation.stop()
            animation.deleteLater()
        if badge is not None and pulse_effect is not None and badge.graphicsEffect() is pulse_effect:
            pulse_effect.setOpacity(1.0)
            badge.setGraphicsEffect(None)

    def _animate_opacity(
        self, widget: QWidget, key: str, start_opacity: float = 0.72, duration: int = 240
    ) -> None:
        """Run a short fade on a specific Dashboard element without blocking the UI."""
        if not hasattr(self, "_ui_animations"):
            self._ui_animations = {}
        existing_effect = widget.graphicsEffect()
        for existing_key, existing_animation in list(self._ui_animations.items()):
            same_widget_effect = existing_effect is not None and existing_animation.targetObject() is existing_effect
            if existing_key == key or same_widget_effect:
                self._ui_animations.pop(existing_key, None)
                existing_animation.stop()
                existing_animation.deleteLater()
        effect = widget.graphicsEffect()
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
        effect.setOpacity(max(0.15, min(1.0, float(start_opacity))))
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(max(120, min(600, int(duration))))
        animation.setStartValue(effect.opacity())
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._ui_animations[key] = animation

        def complete(
            animation_key: str = key,
            anim: QPropertyAnimation = animation,
            opacity_effect: QGraphicsOpacityEffect = effect,
            animated_widget: QWidget = widget,
        ) -> None:
            opacity_effect.setOpacity(1.0)
            if self._ui_animations.get(animation_key) is anim:
                self._ui_animations.pop(animation_key, None)
            # Remove the temporary effect after the transition so normal painting
            # does not keep paying for an opacity layer between animations.
            animated_widget.setGraphicsEffect(None)
            anim.deleteLater()

        animation.finished.connect(complete)
        animation.start()

    def _show_app_notification(self, title: str, message: str, kind: str = "info") -> None:
        """Show a themed, non-blocking Raider DNS toast or a tray notification when hidden."""
        if not bool(self.settings.get("notifications_enabled", True)):
            return
        if self.isVisible() and not self.isMinimized() and hasattr(self, "_notification_toast"):
            self._notification_toast.present(title, message, kind)
            return
        if self._tray_icon is not None and self._tray_icon.isVisible():
            icons = {
                "info": QSystemTrayIcon.MessageIcon.Information,
                "success": QSystemTrayIcon.MessageIcon.Information,
                "warning": QSystemTrayIcon.MessageIcon.Warning,
                "error": QSystemTrayIcon.MessageIcon.Critical,
            }
            self._tray_icon.showMessage(f"Raider DNS — {title}", message[:280], icons.get(kind, QSystemTrayIcon.MessageIcon.Information), 4500)

    def _queue_activity_log_error(self, message: str) -> None:
        """Called by the log writer thread; marshal status updates onto Qt's UI thread."""
        dispatcher = getattr(self, "_dispatcher", None)
        if dispatcher is not None:
            dispatcher.invoke.emit(self._activity_log_failed, message)

    def _activity_log_failed(self, message: str) -> None:
        self.statusBar().showMessage(f"Could not persist activity log: {message[:180]}", 5000)

    def _sync_recent_activity(self) -> None:
        if not hasattr(self, "activity_list"):
            return
        visible = self._activity[:5]
        if not visible:
            visible = ["No actions yet. System checks will appear here."]
        labels = self._recent_activity_labels
        while len(labels) > len(visible):
            label = labels.pop()
            self.activity_list.removeWidget(label)
            label.deleteLater()
        while len(labels) < len(visible):
            label = make_label("", "Muted")
            label.setWordWrap(True)
            labels.append(label)
            self.activity_list.addWidget(label)
        for index, entry in enumerate(visible):
            labels[index].setText(("•  " + entry) if entry != "No actions yet. System checks will appear here." else entry)

    def _log(self, message: str, level: str = "INFO", details: str = "") -> None:
        now = datetime.now()
        timestamp = now.isoformat(timespec="seconds")
        timestamped = f"{now.strftime('%H:%M:%S')}  {message}"
        self._activity.insert(0, timestamped)
        self._activity = self._activity[:5]
        record = {"timestamp": timestamp, "level": level.upper() if level.upper() in {"INFO", "WARNING", "ERROR"} else "INFO", "action": message[:240], "details": details[:1200]}
        self._activity_records.append(record)
        self._activity_records = self._activity_records[-self.activity_store.limit:]
        # Disk I/O is queued on a dedicated worker. Recent labels are reused.
        if self._activity_writer is not None:
            self._activity_writer.append(record)
        self._sync_recent_activity()
        if hasattr(self, "activity_table") and hasattr(self, "pages"):
            # Keep an initialized, unfiltered table current even while hidden. This
            # avoids a full rebuild the next time the Activity tab is opened.
            if self._insert_activity_row_if_fast_path(record):
                pass
            elif self.pages.currentWidget() is getattr(self, "activity_page", None):
                self._activity_table_dirty = True
                self._activity_table_refresh_timer.start(180)
            else:
                self._activity_table_dirty = True

    def _save_settings(self) -> None:
        try:
            self.store.save(self.settings)
        except OSError as exc:
            self.statusBar().showMessage(f"Could not save settings: {exc}", 8000)

    def _apply_saved_window_state(self) -> None:
        if self.settings.get("window_maximized"):
            self.showMaximized()

    def resizeEvent(self, event: Any) -> None:
        super().resizeEvent(event)
        toast = getattr(self, "_notification_toast", None)
        if toast is not None and toast.isVisible():
            toast._reposition()

    def closeEvent(self, event: Any) -> None:
        if self._tray_icon and not self._exit_requested and self.settings.get("close_to_tray", False):
            event.ignore()
            self.hide()
            self._minimized_to_tray = True
            if hasattr(self, "_tray_toggle_action"):
                self._tray_toggle_action.setText("Show window")
            self._tray_icon.showMessage("Raider DNS", "The window was hidden; choose Exit Raider DNS from the tray menu to quit.", QSystemTrayIcon.MessageIcon.Information, 2500)
            self._log("Close button hid Raider DNS to the system tray.")
            return

        # Do not start shutdown while other workers may be changing DNS, running
        # repairs, or collecting diagnostics. Their transactions must finish first.
        # Once the graceful tunnel-stop callback has succeeded, its own QRunnable
        # may still be completing its final signal delivery. No other workers were
        # active when shutdown began and periodic jobs were paused, so do not let
        # that final bookkeeping tick block the confirmed close.
        pending_workers = 0 if self._close_tunnel_shutdown_complete else len(getattr(self, "_workers", ()))
        active_threads = 0 if self._close_tunnel_shutdown_complete else (self.thread_pool.activeThreadCount() if hasattr(self, "thread_pool") else 0)
        if pending_workers or active_threads or getattr(self, "_dns_operation_in_flight", False):
            event.ignore()
            QMessageBox.warning(
                self,
                "Network operation still running",
                "Raider DNS is still performing a network operation. Keep the app open until it finishes so the result and any automatic DNS recovery can complete. Try closing again afterward.",
            )
            return

        if self._close_tunnel_shutdown_pending:
            event.ignore()
            return

        # Tunnel cleanup can take several seconds. Run it in the bounded worker
        # pool so the UI remains responsive, but do not close until Windows has
        # confirmed the non-forced sing-box shutdown path. A recovery journal is
        # also checked here in case the user closes before the startup check runs.
        needs_tunnel_recovery = (
            not self._close_tunnel_shutdown_complete
            and (self.singbox_controller.is_running or self.singbox_controller.has_recovery_record)
        )
        if needs_tunnel_recovery:
            event.ignore()
            self._close_tunnel_shutdown_pending = True
            self._pause_close_background_timers()
            self.statusBar().showMessage("Stopping sing-box safely and releasing the TUN adapter…")

            def cleanup_tunnel() -> TunnelResult:
                if self.singbox_controller.is_running:
                    return self.singbox_controller.stop(timeout=8.0)
                return self.singbox_controller.recover_previous_session(timeout=8.0)

            self._run_background(
                cleanup_tunnel,
                self._finish_close_after_tunnel_shutdown,
                lambda error: self._finish_close_after_tunnel_shutdown(
                    TunnelResult(False, "Tunnel shutdown failed", error)
                ),
            )
            return

        self._shutdown_started = True
        self._network_change_timer.stop()
        self._health_timer.stop()
        self._activity_table_refresh_timer.stop()
        self._singbox_monitor_timer.stop()
        if hasattr(self, "_tooltip_controller"):
            self._tooltip_controller._timer.stop()
        if hasattr(self, "_notification_toast"):
            self._notification_toast.hide()
        for animation in list(self._ui_animations.values()):
            animation.stop()
        self._ui_animations.clear()
        try:
            self.settings["window_maximized"] = self.isMaximized()
            if not self.isMaximized():
                self.settings["window_width"] = self.width()
                self.settings["window_height"] = self.height()
            self._save_settings()
            if self._activity_writer is not None:
                self._activity_writer.shutdown(timeout=3.0)
        finally:
            super().closeEvent(event)
            if self._exit_requested and self._tray_icon:
                self._tray_icon.hide()

