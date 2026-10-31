from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from raider_dns.services.dns_system import WindowsDNSService


class WindowsDNSServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = WindowsDNSService()

    def test_system_changes_are_rejected_outside_windows(self) -> None:
        with patch.object(self.service, "is_windows", return_value=False):
            applied = self.service.apply_dns("Ethernet", ["1.1.1.1"])
            restored = self.service.restore_dhcp("Ethernet")
        self.assertFalse(applied.success)
        self.assertIn("Windows-only", applied.message)
        self.assertFalse(restored.success)
        self.assertIn("Windows-only", restored.message)

    def test_apply_requires_admin(self) -> None:
        with patch.object(self.service, "is_windows", return_value=True), patch.object(
            self.service, "is_admin", return_value=False
        ):
            result = self.service.apply_dns("Ethernet", ["1.1.1.1"])
        self.assertFalse(result.success)
        self.assertIn("Administrator", result.message)

    def test_apply_rejects_invalid_server_address_before_powershell(self) -> None:
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_powershell") as run_ps,
        ):
            result = self.service.apply_dns("Ethernet", ["not-an-ip"])
        self.assertFalse(result.success)
        self.assertIn("Invalid DNS address", result.message)
        run_ps.assert_not_called()

    def test_apply_requires_doh_template_for_every_server(self) -> None:
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_powershell") as run_ps,
        ):
            result = self.service.apply_dns(
                "Ethernet",
                ["1.1.1.1", "1.0.0.1"],
                {"1.1.1.1": "https://cloudflare-dns.com/dns-query"},
                flush_cache=False,
            )
        self.assertFalse(result.success)
        self.assertIn("Missing DoH template", result.message)
        run_ps.assert_not_called()

    def test_apply_registers_each_doh_address_before_changing_adapter_dns(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="DOH_TEMPLATE_READY", stderr="")
        updated = subprocess.CompletedProcess(args=[], returncode=0, stdout="DNS_UPDATED_IPV4", stderr="")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_powershell", side_effect=[completed, completed, updated]) as run_ps,
        ):
            result = self.service._apply_dns_unchecked(
                "Ethernet",
                ["1.1.1.1", "1.0.0.1"],
                {
                    "1.1.1.1": "https://cloudflare-dns.com/dns-query",
                    "1.0.0.1": "https://cloudflare-dns.com/dns-query",
                },
                flush_cache=False,
            )
        self.assertTrue(result.success, result.details)
        self.assertEqual(run_ps.call_count, 3)
        scripts = [invocation.args[0] for invocation in run_ps.call_args_list]
        self.assertIn("Add-DnsClientDohServerAddress", scripts[0])
        self.assertIn("-AllowFallbackToUdp $false", scripts[0])
        self.assertIn("Add-DnsClientDohServerAddress", scripts[1])
        self.assertIn("Set-DnsClientServerAddress", scripts[2])

    def test_doh_registration_failure_prevents_interface_dns_change(self) -> None:
        rejected = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="DoH cmdlet unavailable"
        )
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_powershell", return_value=rejected) as run_ps,
        ):
            result = self.service._apply_dns_unchecked(
                "Ethernet",
                ["1.1.1.1"],
                {"1.1.1.1": "https://cloudflare-dns.com/dns-query"},
                flush_cache=False,
            )
        self.assertFalse(result.success)
        self.assertIn("DoH template", result.message)
        run_ps.assert_called_once()
        self.assertNotIn("Set-DnsClientServerAddress", run_ps.call_args.args[0])

    def test_get_dns_configuration_includes_ipv4_and_ipv6_family(self) -> None:
        payload = (
            '[{"InterfaceAlias":"Wi-Fi","AddressFamily":"IPv4","ServerAddresses":["1.1.1.1"]},'
            '{"InterfaceAlias":"Wi-Fi","AddressFamily":"IPv6","ServerAddresses":["2606:4700:4700::1111"]}]'
        )
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr="")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "_run_powershell", return_value=completed),
        ):
            rows = self.service.get_dns_configuration()
        self.assertEqual([(row["adapter"], row["family"]) for row in rows], [("Wi-Fi", "IPv4"), ("Wi-Fi", "IPv6")])
        self.assertEqual(rows[0]["servers"], ["1.1.1.1"])
        self.assertEqual(rows[1]["servers"], ["2606:4700:4700::1111"])

    def test_restore_requires_adapter_to_be_available(self) -> None:
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_all_adapters", return_value=["Wi-Fi"]),
            patch.object(self.service, "_run_powershell") as run_ps,
        ):
            result = self.service.restore_dhcp("Ethernet", flush_cache=False)
        self.assertFalse(result.success)
        self.assertIn("adapter", result.message.lower())
        run_ps.assert_not_called()


    def test_dot_applies_ipv4_and_ipv6_servers_with_family_specific_objects(self) -> None:
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="OK", stderr="")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_netsh", return_value=success),
            patch.object(self.service, "_run_powershell", side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="DNS_UPDATED_IPV4", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout="DNS_UPDATED_IPV6", stderr=""),
            ]) as run_ps,
        ):
            result = self.service._apply_dot_unchecked(
                "Ethernet", ["1.1.1.1", "2606:4700:4700::1111"], "cloudflare-dns.com", flush_cache=False
            )
        self.assertTrue(result.success, result.details)
        self.assertEqual(run_ps.call_count, 2)
        scripts = [call.args[0] for call in run_ps.call_args_list]
        self.assertIn("-AddressFamily 'IPv4'", scripts[0])
        self.assertIn("Set-DnsClientServerAddress -ServerAddresses", scripts[0])
        self.assertIn("-AddressFamily 'IPv6'", scripts[1])
        self.assertNotIn("Set-DnsClientServerAddress -InterfaceAlias", scripts[0])
        self.assertNotIn("Set-DnsClientServerAddress -AddressFamily", "\n".join(scripts))

    def test_restore_adapter_addresses_uses_family_scoped_cim_objects(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="DNS_RECOVERY_ADDRESSES_RESTORED", stderr="")
        snapshot = {"families": {
            "IPv4": {"mode": "manual", "servers": ["192.0.2.53"]},
            "IPv6": {"mode": "manual", "servers": ["2001:db8::53"]},
        }}
        with patch.object(self.service, "_run_powershell", return_value=completed) as run_ps:
            restored, detail = self.service._restore_adapter_addresses("Ethernet", snapshot)
        self.assertTrue(restored, detail)
        script = run_ps.call_args.args[0]
        self.assertIn("Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily 'IPv4'", script)
        self.assertIn("Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily 'IPv6'", script)
        self.assertNotIn("Set-DnsClientServerAddress -AddressFamily", script)
        self.assertEqual(script.count("| Set-DnsClientServerAddress -ServerAddresses"), 2)

    def test_friendly_command_error_strips_clixml(self) -> None:
        raw = "#< CLIXML\n<Objs Version='1.1.0.1'><S S='Error'>DNS_RESOLUTION_VERIFICATION_FAILED: no test hostname resolved</S></Objs>"
        friendly = self.service._friendly_command_error(raw, "fallback")
        self.assertIn("DNS_RESOLUTION_VERIFICATION_FAILED", friendly)
        self.assertNotIn("CLIXML", friendly)
        self.assertNotIn("<Objs", friendly)

    def test_dns_verification_failure_is_clean_and_never_returns_raw_clixml(self) -> None:
        failed = subprocess.CompletedProcess(args=[], returncode=0, stdout=(
            "DNS_VERIFY=FAIL\nHTTPS_VERIFY=NOT_RUN\n"
            "VERIFY_DETAIL=Windows could not resolve the diagnostic hostnames through the active DNS client.\n"
        ), stderr="")
        with patch.object(self.service, "is_windows", return_value=True), patch.object(self.service, "_run_powershell", return_value=failed):
            okay, detail = self.service.verify_dns_and_https()
        self.assertFalse(okay)
        self.assertIn("could not resolve", detail.casefold())
        self.assertNotIn("CLIXML", detail)
        self.assertNotIn("<Objs", detail)

    def test_powershell_string_quoting_escapes_single_quotes(self) -> None:
        self.assertEqual(WindowsDNSService._quote_ps("Network's Adapter"), "'Network''s Adapter'")

    def test_doh_preflight_bypass_skips_repeating_the_network_probe(self):
        from raider_dns.services.dns_system import DNSOperationResult
        with (
            patch.object(self.service, "_run_transaction", return_value=DNSOperationResult(True, "applied")) as transaction,
            patch("raider_dns.services.dns_probe.probe_doh_endpoint") as probe,
        ):
            result = self.service.apply_dns(
                "Ethernet", ["8.8.8.8"], "https://dns.google/dns-query",
                allow_unverified_doh_preflight=True,
            )
        self.assertTrue(result.success)
        probe.assert_not_called()
        self.assertFalse(transaction.call_args.kwargs["connectivity_check"]()[0])
        self.assertIn("bypassed after explicit user confirmation", transaction.call_args.kwargs["connectivity_check"]()[1])
        transaction.assert_called_once()

    def test_dot_preflight_bypass_skips_repeating_the_network_probe(self):
        from raider_dns.services.dns_system import DNSOperationResult
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "_run_transaction", return_value=DNSOperationResult(True, "applied")) as transaction,
            patch("raider_dns.services.dns_probe.probe_dot") as probe,
        ):
            result = self.service.apply_dot(
                "Ethernet", ["8.8.8.8"], "dns.google", allow_unverified_preflight=True,
            )
        self.assertTrue(result.success)
        probe.assert_not_called()
        self.assertIn("bypassed after explicit user confirmation", result.details)
        transaction.assert_called_once()


if __name__ == "__main__":
    unittest.main()
