from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class V0161DiagnosticsSourceTests(unittest.TestCase):
    def test_diagnostics_are_ordered_connectivity_then_suggestions_then_manual_repairs(self):
        source = (ROOT / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        method = source.split("def _build_diagnostics_page(self) -> QWidget:", 1)[1].split("def _set_repair_selection", 1)[0]
        connectivity = method.index("1. Connectivity test")
        suggested = method.index("2. Suggested troubleshooting")
        manual = method.index("3. Selective manual repairs")
        audit = method.index("DNS configuration audit")
        self.assertLess(connectivity, suggested)
        self.assertLess(suggested, manual)
        self.assertLess(manual, audit)
        self.assertIn("Run full connectivity test", method)
        service = (ROOT / "raider_dns" / "services" / "connectivity_diagnostics.py").read_text(encoding="utf-8")
        self.assertIn("External TCP / 53", service)

    def test_flush_dns_is_selective_manual_option_not_standalone_diagnostics_button(self):
        source = (ROOT / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        method = source.split("def _build_diagnostics_page(self) -> QWidget:", 1)[1].split("def _set_repair_selection", 1)[0]
        self.assertIn('("flush_dns", "Flush DNS cache", False)', method)
        self.assertNotIn("flush_diagnostics_button", source)

    def test_diagnostics_omits_hardware_inventory_and_driver_checks(self):
        service = (ROOT / "raider_dns" / "services" / "connectivity_diagnostics.py").read_text(encoding="utf-8")
        main = (ROOT / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        self.assertNotIn("read_windows_network_inventory", service)
        self.assertNotIn("Get-PnpDevice", service)
        self.assertNotIn("wifi_driver_state", service)
        self.assertNotIn('"driver_reset"', main)
        self.assertNotIn('"driver_reinstall"', main)

    def test_repair_operations_are_allowlisted_and_sensitive_ones_confirmed(self):
        tools = (ROOT / "raider_dns" / "services" / "network_tools.py").read_text(encoding="utf-8")
        main = (ROOT / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        for key in ("flush_dns", "register_dns", "clear_arp_cache", "release_ip", "renew_ip", "winsock_reset", "tcpip_reset", "ipv6_reset", "reset_proxy"):
            self.assertIn(f'"{key}"', tools)
        self.assertIn("selected_disruptive", main)
        self.assertIn("removes its current proxy configuration", main)


if __name__ == "__main__":
    unittest.main()
