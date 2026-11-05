from __future__ import annotations

import unittest
from unittest.mock import patch

from raider_dns.services.connectivity_diagnostics import run_connectivity_checks, suggest_repairs


class ConnectivityDiagnosticsTests(unittest.TestCase):
    def test_dns_failure_with_https_success_suggests_only_cache_flush(self) -> None:
        report = {
            "dhcp_enabled": False,
            "checks": [
                {"id": "dns_resolution", "status": "FAIL"},
                {"id": "https_connectivity", "status": "PASS"},
                {"id": "tcp_external_443", "status": "PASS"},
                {"id": "driver_state", "status": "PASS"},
            ],
        }
        self.assertEqual(suggest_repairs(report), ["flush_dns"])

    def test_dhcp_gateway_symptom_suggests_renew(self) -> None:
        report = {
            "dhcp_enabled": True,
            "checks": [
                {"id": "adapter_state", "status": "PASS"},
                {"id": "default_gateway", "status": "FAIL"},
                {"id": "gateway_ping", "status": "FAIL"},
                {"id": "dns_resolution", "status": "FAIL"},
                {"id": "https_connectivity", "status": "FAIL"},
                {"id": "tcp_external_443", "status": "FAIL"},
            ],
        }
        self.assertEqual(suggest_repairs(report), ["renew_ip"])

    def test_driver_problem_does_not_suggest_automatic_stack_or_driver_reset(self) -> None:
        report = {"checks": [{"id": "driver_state", "status": "FAIL"}]}
        self.assertEqual(suggest_repairs(report), [])

    def test_full_test_emits_connectivity_checks_without_hardware_inventory(self) -> None:
        facts = {
            "adapters": [{"Name": "Ethernet", "Status": "Up", "InterfaceIndex": 4}],
            "routes": [{"NextHop": "192.168.1.1", "InterfaceIndex": 4, "RouteMetric": 10}],
            "drivers": [{"FriendlyName": "Ethernet Controller", "Status": "OK", "Problem": 0}],
            "dhcp": [{"InterfaceAlias": "Ethernet", "Dhcp": "Enabled"}],
            "addresses": [{"InterfaceAlias": "Ethernet", "IPAddress": "192.168.1.10", "PrefixOrigin": "Dhcp"}],
        }
        with (
            patch("raider_dns.services.connectivity_diagnostics._windows_network_facts", return_value=facts),
            patch("raider_dns.services.connectivity_diagnostics._ping", return_value=(True, 2.0, "Reply")),
            patch("raider_dns.services.connectivity_diagnostics._tcp_connect", side_effect=[(True, 10.0, "TCP 443"), (True, 12.0, "TCP 53")]),
            patch("raider_dns.services.connectivity_diagnostics._resolve_system", return_value=(True, 5.0, "Resolved example.com")),
            patch("raider_dns.services.connectivity_diagnostics._https_connectivity", return_value=(True, 20.0, "HTTPS OK")),
        ):
            report = run_connectivity_checks("Ethernet")
        ids = {row["id"] for row in report["checks"]}
        self.assertTrue({"adapter_state", "default_gateway", "gateway_ping", "tcp_external_443", "tcp_dns_53", "dns_resolution", "https_connectivity"}.issubset(ids))
        self.assertFalse({"driver_state", "wifi_driver_state", "wifi_inventory"} & ids)
        self.assertEqual(report["adapter"], "Ethernet")
        self.assertEqual(report["summary"]["failed"], 0)

    def test_resolver_check_uses_timeout_bounded_powershell_on_windows(self) -> None:
        # Structural guard: the Windows implementation must use the bounded
        # subprocess path rather than an unbounded socket.getaddrinfo call.
        import inspect
        import raider_dns.services.connectivity_diagnostics as module
        source = inspect.getsource(module._resolve_system)
        self.assertIn("powershell.exe", source)
        self.assertIn("timeout=max(1.0, timeout)", source)
        self.assertIn("socket.getaddrinfo", source)  # retained only as non-Windows development fallback


if __name__ == "__main__":
    unittest.main()
