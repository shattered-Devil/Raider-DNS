from __future__ import annotations

import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from raider_dns.models import DNSProvider
from raider_dns.services.dns_probe import ProbeResult, probe_dot, probe_udp
from raider_dns.services.dns_system import WindowsDNSService
from raider_dns.storage import ConfigStore
from raider_dns.ui.theme import LIGHT_THEME_IDS, is_light_theme, stylesheet

ROOT = Path(__file__).resolve().parents[1]


class ThemeRegressionTests(unittest.TestCase):
    def test_all_light_themes_are_classified_as_light(self) -> None:
        expected = {"light", "light_mild", "paper", "warm_sand", "mist_blue"}
        self.assertEqual(set(LIGHT_THEME_IDS), expected)
        for theme in expected:
            with self.subTest(theme=theme):
                self.assertTrue(is_light_theme(theme))
                qss = stylesheet(theme)
                self.assertIn("QWidget#PageContent", qss)
                self.assertIn("background-color:", qss)
                self.assertRegex(qss, r"QWidget#PageContent \{ background-color: #[0-9a-fA-F]{6};")

    def test_dark_themes_are_not_classified_as_light(self) -> None:
        for theme in ("dark", "midnight", "ocean", "high_contrast", "unknown"):
            with self.subTest(theme=theme):
                self.assertFalse(is_light_theme(theme))

    def test_settings_store_accepts_all_new_light_themes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            store = ConfigStore(Path(temp) / "settings.json")
            for theme in sorted(LIGHT_THEME_IDS):
                with self.subTest(theme=theme):
                    settings = store.load()
                    settings["theme"] = theme
                    store.save(settings)
                    self.assertEqual(store.load()["theme"], theme)

    def test_settings_ui_uses_simple_light_label_and_no_delay_explanation(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn('("Light", "light")', source)
        self.assertNotIn("Light — redesigned", source)
        self.assertNotIn("Button description delay", source)
        self.assertNotIn('make_label("Tooltip delay")', source)
        self.assertIn("DEFAULT_DELAY_MS = 750", source)
        self.assertIn('("Mild Light", "light_mild")', source)
        self.assertIn('("Paper", "paper")', source)


class SingleInstanceAndTrayRegressionTests(unittest.TestCase):
    def test_entry_point_acquires_single_instance_guard_before_window_creation(self) -> None:
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("SingleInstanceGuard", source)
        self.assertIn("guard.acquire(timeout_seconds=wait_for_owner)", source)
        self.assertIn("guard.request_activation()", source)
        self.assertLess(source.index("guard.acquire(timeout_seconds=wait_for_owner)"), source.index("window = MainWindow()"))
        self.assertIn("--admin-handoff", source)

    def test_tray_setup_is_idempotent_and_minimize_is_guarded(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        start = source.index("    def _setup_tray(")
        end = source.index("    def _tray_activated(", start)
        tray_setup = source[start:end]
        self.assertIn("if self._tray_icon is not None:", tray_setup)
        self.assertEqual(tray_setup.count("QSystemTrayIcon(icon, self)"), 1)
        self.assertIn("and not self._minimized_to_tray", source)
        self.assertIn("def activate_from_existing_instance", source)

    def test_single_instance_guard_uses_lock_and_local_activation_ipc(self) -> None:
        source = (ROOT / "raider_dns/instance.py").read_text(encoding="utf-8")
        self.assertIn("QLockFile", source)
        self.assertIn("QLocalServer", source)
        self.assertIn("QLocalSocket", source)
        self.assertIn('socket.write(b"activate\\n")', source)
        self.assertIn("def release(self)", source)

    def test_tray_exit_keeps_icon_visible_until_close_is_accepted(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        start = source.index("    def _exit_application(")
        end = source.index("    def changeEvent(", start)
        exit_method = source[start:end]
        self.assertNotIn("self._tray_icon.hide()", exit_method)
        self.assertIn("self.close()", exit_method)
        close_start = source.index("    def closeEvent(")
        close_method = source[close_start:]
        self.assertIn("if self._exit_requested and self._tray_icon:", close_method)
        self.assertIn("self._tray_icon.hide()", close_method)

    def test_admin_handoff_passes_one_switch_and_waits_for_existing_owner(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        start = source.index("    def _relaunch_as_admin(")
        end = source.index("    # ---- System operations", start)
        method = source[start:end]
        self.assertEqual(method.count('forwarded_args.append("--admin-handoff")'), 1)
        self.assertIn("ShellExecuteW", method)
        self.assertIn("self._admin_handoff_pending = True", method)
        entry = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("_ADMIN_HANDOFF_WAIT_SECONDS = 90.0", entry)


class DNSLatencyRegressionTests(unittest.TestCase):
    @staticmethod
    def _success_response(query: bytes) -> bytes:
        transaction_id = struct.unpack("!H", query[:2])[0]
        return struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 0, 0, 0)

    def test_udp_latency_measures_the_successful_server_not_prior_timeout(self) -> None:
        provider = DNSProvider("test", "Test resolver", "", "192.0.2.1", "192.0.2.2", "Test")

        class FakeDatagramSocket:
            def __init__(self, family: int, sock_type: int) -> None:
                self.destination = None
                self.query = b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: float) -> None:
                pass

            def sendto(self, query: bytes, destination) -> None:
                self.query = query
                self.destination = destination

            def recvfrom(self, _size: int):
                if self.destination[0] == "192.0.2.1":
                    raise socket.timeout()
                return DNSLatencyRegressionTests._success_response(self.query), self.destination

        with patch("raider_dns.services.dns_probe.socket.socket", side_effect=FakeDatagramSocket), \
             patch("raider_dns.services.dns_probe.time.perf_counter", side_effect=[1.0, 10.0, 10.032]):
            result = probe_udp(provider, timeout=0.01)

        self.assertTrue(result.success, result.message)
        self.assertEqual(result.latency_ms, 32.0)

    def test_dot_latency_timer_restarts_for_each_resolver_address(self) -> None:
        provider = DNSProvider("test", "Test resolver", "", "192.0.2.1", "192.0.2.2", "Test", dot_hostname="dns.test")

        class FakeRawSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: float) -> None:
                pass

        class FakeTlsSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def sendall(self, _payload: bytes) -> None:
                pass

        fake_context = Mock()
        fake_context.wrap_socket.return_value = FakeTlsSocket()
        transaction_id = 0x2345
        response = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 0, 0, 0)
        with patch("raider_dns.services.dns_probe.socket.create_connection", side_effect=[socket.timeout(), FakeRawSocket()]), \
             patch("raider_dns.services.dns_probe.ssl.create_default_context", return_value=fake_context), \
             patch("raider_dns.services.dns_probe.secrets.randbelow", return_value=transaction_id), \
             patch("raider_dns.services.dns_probe._recv_exact", side_effect=[struct.pack("!H", len(response)), response]), \
             patch("raider_dns.services.dns_probe.time.perf_counter", side_effect=[1.0, 10.0, 10.025]):
            result = probe_dot(provider, timeout=0.01)

        self.assertTrue(result.success, result.message)
        self.assertEqual(result.latency_ms, 25.0)

    def test_configured_resolver_reachability_checks_two_servers_concurrently(self) -> None:
        barrier = threading.Barrier(2)

        def concurrent_probe(provider: DNSProvider, timeout: float = 0.9) -> ProbeResult:
            barrier.wait(timeout=2.0)
            return ProbeResult(provider.id, provider.name, "UDP / 53", True, 12.0, "DNS query succeeded.")

        with patch("raider_dns.services.dns_probe.probe_udp", side_effect=concurrent_probe):
            success, message = WindowsDNSService._probe_configured_dns_servers(
                ["192.0.2.1", "192.0.2.2"], timeout=0.1
            )
        self.assertTrue(success, message)
        self.assertIn("direct DNS query", message)

    def test_configured_resolver_reachability_caps_probe_fanout_at_two(self) -> None:
        called: list[str] = []
        barrier = threading.Barrier(2)

        def concurrent_probe(provider: DNSProvider, timeout: float = 0.9) -> ProbeResult:
            called.append(provider.primary)
            barrier.wait(timeout=2.0)
            return ProbeResult(provider.id, provider.name, "UDP / 53", True, 9.0, "ok")

        with patch("raider_dns.services.dns_probe.probe_udp", side_effect=concurrent_probe):
            success, _ = WindowsDNSService._probe_configured_dns_servers(
                ["192.0.2.1", "192.0.2.2", "192.0.2.3"], timeout=0.1
            )
        self.assertTrue(success)
        self.assertEqual(set(called), {"192.0.2.1", "192.0.2.2"})


class DonationAndMetadataTests(unittest.TestCase):
    def test_about_contains_support_action_and_correct_project_identity(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn("Donate / Support Raider DNS", source)
        self.assertIn("https://github.com/shattered-Devil/Raider-DNS", source)
        self.assertIn("Thank you for supporting Raider DNS", source)
        self.assertIn("Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil", source)

    def test_current_application_version_and_copyright_metadata_are_v020_beta(self) -> None:
        from raider_dns import __version__

        self.assertEqual(__version__, "0.2.0-beta")
        version_info = (ROOT / "installer/version_info.txt").read_text(encoding="utf-8")
        self.assertIn("filevers=(0, 2, 0, 0)", version_info)
        self.assertIn("prodvers=(0, 2, 0, 0)", version_info)
        copyright_text = "Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil"
        self.assertIn(copyright_text, version_info)
        for relative in ("installer/RaiderDNS.iss", "installer/RaiderDNS_OneFile.iss",
                         "COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt", "LICENSE_STATUS.md",
                         "THIRD_PARTY_NOTICES.md", "README.md"):
            with self.subTest(file=relative):
                self.assertIn(copyright_text, (ROOT / relative).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
