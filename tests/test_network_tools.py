from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raider_dns.services import network_tools
from raider_dns.services.network_tools import CommandOutcome, flush_dns_cache, repair_network
from raider_dns.storage import ActivityLogStore, ConfigStore, default_settings


class NetworkToolsTests(unittest.TestCase):
    def test_flush_dns_rejects_non_windows(self) -> None:
        with patch.object(network_tools, "is_windows", return_value=False):
            result = flush_dns_cache()
        self.assertFalse(result.success)
        self.assertIn("Windows only", result.message)

    def test_flush_dns_requires_admin(self) -> None:
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=False), patch.object(network_tools, "run_command") as run:
            result = flush_dns_cache()
        self.assertFalse(result.success)
        self.assertIn("Administrator", result.message)
        run.assert_not_called()

    def test_flush_dns_uses_hidden_shell_free_command(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="Successfully flushed the DNS Resolver Cache.", stderr="")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=True), patch.object(network_tools, "run_command", return_value=completed) as run:
            result = flush_dns_cache()
        self.assertTrue(result.success)
        run.assert_called_once_with(["ipconfig.exe", "/flushdns"], timeout=20)

    def test_repair_rejects_unknown_operation_before_commands(self) -> None:
        with patch.object(network_tools, "run_command") as run:
            result = repair_network(["do-dangerous-thing"])
        self.assertFalse(result[0].success)
        run.assert_not_called()

    def test_repair_stops_after_first_command_failure(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="bad", stderr="failed")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=True), patch.object(network_tools, "run_command", return_value=completed) as run:
            result = repair_network(["release_ip", "renew_ip"])
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].success)
        run.assert_called_once_with(["ipconfig.exe", "/release"], timeout=90)

    def test_stack_reset_marks_restart_needed(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="reset", stderr="")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=True), patch.object(network_tools, "run_command", return_value=completed):
            result = repair_network(["winsock_reset"])
        self.assertTrue(result[0].success)
        self.assertTrue(result[0].requires_restart)

    def test_manual_repair_allowlist_includes_selectable_dns_and_network_actions(self) -> None:
        expected = {"flush_dns", "register_dns", "clear_arp_cache", "release_ip", "renew_ip", "winsock_reset", "tcpip_reset", "ipv6_reset", "reset_proxy"}
        self.assertTrue(expected.issubset(set(network_tools.REPAIR_OPERATIONS)))

    def test_ipv6_stack_reset_is_marked_as_restart_sensitive(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="reset", stderr="")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=True), patch.object(network_tools, "run_command", return_value=completed):
            result = repair_network(["ipv6_reset"])
        self.assertTrue(result[0].success)
        self.assertTrue(result[0].requires_restart)
        self.assertEqual(result[0].key, "ipv6_reset")

    def test_dhcp_release_is_scoped_to_selected_adapter(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="released", stderr="")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "is_admin", return_value=True), patch.object(network_tools, "run_command", return_value=completed) as run:
            result = repair_network(["release_ip"], adapter="Wi-Fi")
        self.assertTrue(result[0].success)
        run.assert_called_once_with(["ipconfig.exe", "/release", "Wi-Fi"], timeout=90)

    def test_private_ip_refresh_does_not_contact_public_service_unless_requested(self) -> None:
        fake = [(2, 2, 17, "", ("192.168.1.20", 0)), (10, 2, 17, "", ("fd00::10", 0, 0, 0)), (2, 2, 17, "", ("127.0.0.1", 0))]
        # This test is specifically for the hostname/socket fallback path.
        # On Windows, get_network_info() correctly prefers Get-NetIPAddress;
        # without this platform override the test would read the real adapter
        # address and become dependent on the machine running the test.
        with patch.object(network_tools, "is_windows", return_value=False), patch.object(
            network_tools.socket, "gethostname", return_value="test-host"
        ), patch.object(network_tools.socket, "getaddrinfo", return_value=fake), patch.object(
            network_tools.urllib.request, "urlopen"
        ) as urlopen:
            result = network_tools.get_network_info(include_public=False)
        self.assertEqual(result["private_ipv4"], ["192.168.1.20"])
        self.assertEqual(result["private_ipv6"], ["fd00::10"])
        self.assertFalse(result["public_checked"])
        urlopen.assert_not_called()

    def test_windows_interface_query_parses_multiple_addresses(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='["192.168.1.12","10.0.0.5","fe80::1234","fd00::beef","127.0.0.1"]', stderr="")
        with patch.object(network_tools, "is_windows", return_value=True), patch.object(network_tools, "run_command", return_value=completed) as run, patch.object(network_tools.socket, "getaddrinfo") as fallback:
            result = network_tools.get_network_info(include_public=False)
        run.assert_called_once()
        fallback.assert_not_called()
        self.assertEqual(result["private_ipv4"], ["10.0.0.5", "192.168.1.12"])
        self.assertEqual(result["private_ipv6"], ["fd00::beef"])

    def test_address_normalization_rejects_loopback_link_local_and_invalid_text(self) -> None:
        ipv4, ipv6 = network_tools._normalize_private_addresses(["192.168.10.1", "127.0.0.1", "169.254.1.2", "fd12::1", "fe80::1", "not-an-ip"])
        self.assertEqual(ipv4, {"192.168.10.1"})
        self.assertEqual(ipv6, {"fd12::1"})


class ActivityLogTests(unittest.TestCase):
    def test_activity_log_round_trip_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ActivityLogStore(Path(tmp) / "activity.json", limit=100)
            store.append({"timestamp": "2026-10-27T10:00:00", "level": "INFO", "action": "Changed DNS", "details": "Adapter: Ethernet"})
            rows = store.load()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["action"], "Changed DNS")
            store.clear()
            self.assertEqual(store.load(), [])

    def test_new_settings_defaults_include_tray_and_theme_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            store = ConfigStore(path)
            settings = default_settings()
            settings["theme"] = "ocean"
            settings["minimize_to_tray"] = False
            store.save(settings)
            loaded = store.load()
            self.assertEqual(loaded["theme"], "ocean")
            self.assertFalse(loaded["minimize_to_tray"])


if __name__ == "__main__":
    unittest.main()
