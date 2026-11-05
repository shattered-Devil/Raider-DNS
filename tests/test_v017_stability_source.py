from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
TUNNEL = (ROOT / "raider_dns" / "services" / "traffic_tunnel.py").read_text(encoding="utf-8")
DNSCRYPT = (ROOT / "raider_dns" / "services" / "dnscrypt_proxy.py").read_text(encoding="utf-8")


class V017StabilitySourceTests(unittest.TestCase):
    def test_tunnel_process_uses_hidden_console_not_create_no_window(self):
        start = TUNNEL.index("    def start(self, binary: Path, config: Path)")
        end = TUNNEL.index("    @staticmethod\n    def is_admin", start)
        method = TUNNEL[start:end]
        self.assertIn("startupinfo=startup_info", method)
        self.assertNotIn("creationflags=", method)
        self.assertIn("STARTF_USESHOWWINDOW", TUNNEL)
        self.assertIn("subprocess.SW_HIDE", TUNNEL)

    def test_unexpected_singbox_exit_is_monitored_and_reported(self):
        self.assertIn("setInterval(2500)", MAIN)
        self.assertIn("timeout.connect(self._monitor_singbox_process)", MAIN)
        self.assertIn("check_for_unexpected_exit", MAIN)
        self.assertIn("network state needs checking", MAIN)

    def test_tunnel_exit_does_not_automatically_delete_unknown_routes_or_adapters(self):
        monitor_start = MAIN.index("    def _monitor_singbox_process(self)")
        monitor_end = MAIN.index("    def _start_singbox_tunnel(self)", monitor_start)
        monitor = MAIN[monitor_start:monitor_end]
        self.assertIn("has not removed any adapters or routes automatically", monitor)
        self.assertIn("Diagnostics", monitor)

    def test_app_uses_a_private_bounded_worker_pool(self):
        self.assertIn("self.thread_pool = QThreadPool(self)", MAIN)
        self.assertIn("self.thread_pool.setMaxThreadCount(MAX_CONCURRENT_NETWORK_TASKS)", MAIN)
        self.assertNotIn("self.thread_pool = QThreadPool.globalInstance()", MAIN)

    def test_dnscrypt_stop_retains_controller_reference_on_unconfirmed_shutdown(self):
        stop_start = DNSCRYPT.index("    def stop(self, timeout: float = 3.0)")
        stop_end = DNSCRYPT.find("\n    def ", stop_start + 8)
        method = DNSCRYPT[stop_start:stop_end if stop_end >= 0 else len(DNSCRYPT)]
        self.assertIn("process reference was retained", method)
        self.assertIn("self.process = None", method)
        self.assertIn("shutdown could not be confirmed", method)


if __name__ == "__main__":
    unittest.main()
