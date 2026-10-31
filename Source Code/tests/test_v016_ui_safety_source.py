from pathlib import Path
import unittest


class DNSCryptStopSafetySourceTests(unittest.TestCase):
    def test_stopping_dnscrypt_restores_previous_configuration_not_forces_dhcp(self):
        source = (Path(__file__).parents[1] / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        start = source.index("    def _stop_dnscrypt_proxy(self)")
        end = source.index("    def _browse_singbox_executable(self)", start)
        method = source[start:end]
        self.assertIn("restore_previous_dns_settings", method)
        self.assertIn("has_loopback_dns_dependency", method)
        self.assertNotIn("restore_dhcp", method)
        self.assertIn("proxy was kept running", method.casefold())


if __name__ == "__main__":
    unittest.main()
