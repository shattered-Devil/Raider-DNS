from pathlib import Path
import unittest


SOURCE = (Path(__file__).parents[1] / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")


class UILifecycleSafetyTests(unittest.TestCase):
    def test_window_close_is_refused_while_worker_or_dns_operation_is_active(self):
        start = SOURCE.index("    def closeEvent(self, event: Any)")
        method = SOURCE[start:]
        self.assertIn("pending_workers = 0 if self._close_tunnel_shutdown_complete", method)
        self.assertIn("active_threads = 0 if self._close_tunnel_shutdown_complete", method)
        self.assertIn("self._close_tunnel_shutdown_pending", method)
        self.assertIn("_dns_operation_in_flight", method)
        self.assertIn("event.ignore()", method)
        self.assertIn("automatic DNS recovery can complete", method)

    def test_dnscrypt_stop_restores_saved_configuration_and_checks_all_adapters(self):
        start = SOURCE.index("    def _stop_dnscrypt_proxy(self)")
        end = SOURCE.index("    def _browse_singbox_config(self)", start)
        method = SOURCE[start:end]
        self.assertIn("restore_previous_dns_settings", method)
        self.assertIn("has_loopback_dns_dependency", method)
        self.assertNotIn("restore_dhcp", method)
        self.assertIn("proxy was kept running", method.casefold())


    def test_tunnel_shutdown_pauses_periodic_jobs_and_restores_them_on_failure(self):
        self.assertIn("def _pause_close_background_timers(self)", SOURCE)
        self.assertIn("def _resume_after_cancelled_close(self)", SOURCE)
        self.assertIn("self._singbox_monitor_timer.stop()", SOURCE)
        self.assertIn("central.setEnabled(False)", SOURCE)
        self.assertIn("central.setEnabled(True)", SOURCE)

    def test_singbox_process_monitor_warns_without_automatic_route_deletion(self):
        start = SOURCE.index("    def _monitor_singbox_process(self)")
        end = SOURCE.index("    def _start_singbox_tunnel(self)", start)
        method = SOURCE[start:end]
        self.assertIn("check_for_unexpected_exit", method)
        self.assertIn("has not removed any adapters or routes automatically", method)
        self.assertIn("Diagnostics", method)

    def test_tunnel_stop_uses_application_owned_thread_pool(self):
        self.assertIn("self.thread_pool = QThreadPool(self)", SOURCE)
        self.assertNotIn("self.thread_pool = QThreadPool.globalInstance()", SOURCE)


if __name__ == "__main__":
    unittest.main()
