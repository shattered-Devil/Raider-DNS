from __future__ import annotations

import unittest

from raider_dns.services.network_monitor import build_network_signature, describe_network_changes


class NetworkMonitorTests(unittest.TestCase):
    def test_signature_ignores_order_and_duplicate_values(self) -> None:
        first = build_network_signature(
            ["Wi-Fi", "Ethernet", "Wi-Fi"],
            [{"adapter": "Wi-Fi", "family": "IPv4", "servers": ["1.1.1.1", "1.0.0.1"]}],
            {"private_ipv4": ["192.168.1.10"], "private_ipv6": ["fe80::2"]},
        )
        second = build_network_signature(
            ["Ethernet", "Wi-Fi"],
            [{"adapter": "Wi-Fi", "family": "IPv4", "servers": ["1.0.0.1", "1.1.1.1"]}],
            {"private_ipv4": ["192.168.1.10", "192.168.1.10"], "private_ipv6": ["fe80::2"]},
        )
        self.assertEqual(first, second)
        self.assertEqual(describe_network_changes(first, second), [])

    def test_signature_reports_adapter_dns_and_address_changes(self) -> None:
        before = build_network_signature(
            ["Wi-Fi"], [{"adapter": "Wi-Fi", "family": "IPv4", "servers": ["192.168.1.1"]}],
            {"private_ipv4": ["192.168.1.50"], "private_ipv6": []},
        )
        after = build_network_signature(
            ["Ethernet"], [{"adapter": "Ethernet", "family": "IPv4", "servers": ["9.9.9.9"]}],
            {"private_ipv4": ["10.0.0.5"], "private_ipv6": ["fd00::5"]},
        )
        changes = describe_network_changes(before, after)
        self.assertTrue(any("Active adapters changed" in item for item in changes))
        self.assertTrue(any("Private IPv4 addresses changed" in item for item in changes))
        self.assertTrue(any("Private IPv6 addresses changed" in item for item in changes))
        self.assertTrue(any("DNS servers for" in item and "IPv4" in item for item in changes))

    def test_ipv6_dns_configuration_changes_are_reported(self) -> None:
        before = build_network_signature(["Wi-Fi"], [{"adapter": "Wi-Fi", "family": "IPv6", "servers": ["2001:4860:4860::8888"]}])
        after = build_network_signature(["Wi-Fi"], [{"adapter": "Wi-Fi", "family": "IPv6", "servers": ["2606:4700:4700::1111"]}])
        self.assertTrue(any("IPv6" in item for item in describe_network_changes(before, after)))

    def test_bad_network_info_is_handled_defensively(self) -> None:
        signature = build_network_signature(["Wi-Fi"], [], {"private_ipv4": None, "private_ipv6": "bad"})
        self.assertEqual(signature[2:], ((), ()))


if __name__ == "__main__":
    unittest.main()
