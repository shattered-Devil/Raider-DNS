from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raider_dns.models import DNSProvider
from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController, MINISIGN_PUBLIC_KEY
from raider_dns.services.dns_system import DNSOperationResult, WindowsDNSService
from raider_dns.services.traffic_tunnel import validate_singbox_config


class NativeDoTTests(unittest.TestCase):
    def setUp(self):
        self.service = WindowsDNSService()

    def test_dot_requires_windows_admin_adapter_and_host(self):
        with patch.object(self.service, "is_windows", return_value=False):
            self.assertFalse(self.service.apply_dot("Ethernet", ["1.1.1.1"], "one.one.one.one").success)
        with patch.object(self.service, "is_windows", return_value=True), patch.object(self.service, "is_admin", return_value=False):
            result = self.service.apply_dot("Ethernet", ["1.1.1.1"], "one.one.one.one")
        self.assertFalse(result.success)
        self.assertIn("Administrator", result.message)

    def test_dot_rejects_bad_hostname_before_commands(self):
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_netsh") as run_netsh,
        ):
            result = self.service._apply_dot_unchecked("Ethernet", ["1.1.1.1"], "https://bad.example/dns")
        self.assertFalse(result.success)
        self.assertIn("hostname", result.message.casefold())
        run_netsh.assert_not_called()

    def test_public_dot_preflight_failure_refuses_to_start_transaction(self):
        from raider_dns.services.dns_probe import ProbeResult
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch("raider_dns.services.dns_probe.probe_dot", return_value=ProbeResult("x", "DoT preflight", "DNS-over-TLS", False, None, "certificate mismatch")),
            patch.object(self.service, "_run_transaction") as transaction,
        ):
            result = self.service.apply_dot("Ethernet", ["1.1.1.1"], "one.one.one.one")
        self.assertFalse(result.success)
        self.assertIn("preflight", result.message.casefold())
        self.assertIn("certificate mismatch", result.details)
        transaction.assert_not_called()

    def test_public_dot_invokes_transaction_only_after_authenticated_preflight(self):
        from raider_dns.services.dns_probe import ProbeResult
        expected = DNSOperationResult(True, "configured", "transaction verified", verified=True)
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch("raider_dns.services.dns_probe.probe_dot", return_value=ProbeResult("x", "DoT preflight", "DNS-over-TLS", True, 24.5, "TLS certificate and DNS response verified")),
            patch.object(self.service, "_run_transaction", return_value=expected) as transaction,
        ):
            result = self.service.apply_dot("Ethernet", ["1.1.1.1"], "one.one.one.one")
        self.assertTrue(result.success)
        self.assertIn("24.5 ms", result.details)
        transaction.assert_called_once()

    def test_dot_accepts_valid_ipv6_resolver_address(self):
        netsh_ok = subprocess.CompletedProcess([], 0, "OK", "")
        powershell_ok = subprocess.CompletedProcess([], 0, "DNS_UPDATED_IPV6", "")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_netsh", return_value=netsh_ok) as netsh,
            patch.object(self.service, "_run_powershell", return_value=powershell_ok) as powershell,
        ):
            result = self.service._apply_dot_unchecked("Ethernet", ["2606:4700:4700::1111"], "one.one.one.one", flush_cache=False)
        self.assertTrue(result.success, result.details)
        commands = [call.args[0] for call in netsh.call_args_list]
        self.assertTrue(any("server=2606:4700:4700::1111" in args for args in commands))
        self.assertIn("2606:4700:4700::1111", powershell.call_args.args[0])

    def test_dnscrypt_loopback_requires_admin_and_sets_both_families(self):
        with patch.object(self.service, "is_windows", return_value=True), patch.object(self.service, "is_admin", return_value=False):
            denied = self.service.apply_dnscrypt_loopback("Ethernet", flush_cache=False)
        self.assertFalse(denied.success)
        self.assertIn("Administrator", denied.message)
        powershell_ok = subprocess.CompletedProcess([], 0, "DNSCRYPT_LOOPBACK_UPDATED", "")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_powershell", return_value=powershell_ok) as powershell,
        ):
            result = self.service._apply_dnscrypt_loopback_unchecked("Ethernet", flush_cache=False)
        self.assertTrue(result.success, result.details)
        script = powershell.call_args.args[0]
        self.assertIn("127.0.0.1", script)
        self.assertIn("::1", script)
        self.assertIn("Get-DnsClientServerAddress", script)
        self.assertIn("-AddressFamily IPv4", script)
        self.assertIn("-AddressFamily IPv6", script)

    def test_dot_configures_native_client_and_disables_plaintext_fallback(self):
        failed_set = subprocess.CompletedProcess([], 1, "", "not present")
        netsh_ok = subprocess.CompletedProcess([], 0, "OK", "")
        powershell_ok = subprocess.CompletedProcess([], 0, "DNS_UPDATED_IPV4", "")
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_run_netsh", side_effect=[failed_set, netsh_ok, netsh_ok]) as netsh,
            patch.object(self.service, "_run_powershell", return_value=powershell_ok) as powershell,
        ):
            result = self.service._apply_dot_unchecked("Ethernet", ["1.1.1.1"], "one.one.one.one", flush_cache=False)
        self.assertTrue(result.success, result.details)
        commands = [call.args[0] for call in netsh.call_args_list]
        self.assertTrue(any("dothost=one.one.one.one:853" in args for args in commands))
        self.assertTrue(any("udpfallback=no" in args for args in commands))
        self.assertIn("dot=yes", commands[-1])
        self.assertIn("Set-DnsClientServerAddress", powershell.call_args.args[0])


class DNSCryptConfigTests(unittest.TestCase):
    def test_generated_config_is_loopback_only_dnscrypt_only_and_validates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            okay, reason = DNSCryptProxyController.validate_config(path)
            self.assertTrue(okay, reason)
            text = path.read_text(encoding="utf-8")
            self.assertIn("listen_addresses = ['127.0.0.1:53', '[::1]:53']", text)
            self.assertIn("doh_servers = false", text)
            self.assertIn("server_names = []", text)
            self.assertIn("require_dnssec = true", text)
            self.assertIn("require_nolog = true", text)
            self.assertIn("lb_strategy = 'wp2'", text)
            self.assertIn("pqdnscrypt = true", text)
            self.assertIn(MINISIGN_PUBLIC_KEY, text)

    def test_config_rejects_non_loopback_listener(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            text = path.read_text(encoding="utf-8").replace("127.0.0.1:53", "0.0.0.0:53")
            path.write_text(text, encoding="utf-8")
            okay, reason = DNSCryptProxyController.validate_config(path)
        self.assertFalse(okay)
        self.assertIn("127.0.0.1", reason)

    def test_config_rejects_pinned_server_names_to_preserve_security_filters(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            path.write_text(path.read_text(encoding="utf-8").replace("server_names = []", "server_names = ['unverified-resolver']"), encoding="utf-8")
            okay, reason = DNSCryptProxyController.validate_config(path)
        self.assertFalse(okay)
        self.assertIn("server_names must be empty", reason)


    def test_config_rejects_disabled_post_quantum_dnscrypt(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            path.write_text(path.read_text(encoding="utf-8").replace("pqdnscrypt = true", "pqdnscrypt = false"), encoding="utf-8")
            okay, reason = DNSCryptProxyController.validate_config(path)
        self.assertFalse(okay)
        self.assertIn("Post-quantum", reason)

    def test_config_rejects_malformed_timeout_without_exception(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            path.write_text(path.read_text(encoding="utf-8").replace("timeout = 5000", "timeout = 'fast'"), encoding="utf-8")
            okay, reason = DNSCryptProxyController.validate_config(path)
        self.assertFalse(okay)
        self.assertIn("timeout", reason.casefold())

    def test_config_rejects_malformed_resolver_source_table_without_exception(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dnscrypt.toml"
            DNSCryptProxyController.generate_config(path)
            text = path.read_text(encoding="utf-8")
            text = text.split("\n[sources.public-resolvers]", 1)[0]
            text += "\n[sources]\npublic-resolvers = 'not-a-table'\n"
            path.write_text(text, encoding="utf-8")
            okay, reason = DNSCryptProxyController.validate_config(path)
        self.assertFalse(okay)
        self.assertIn("TOML table", reason)


class FullTrafficTunnelConfigTests(unittest.TestCase):
    def test_accepts_tun_with_explicit_proxy_default_route(self):
        config = {
            "inbounds": [{"type": "tun", "auto_route": True, "strict_route": True}],
            "outbounds": [{"type": "vless", "tag": "proxy", "server": "proxy.example", "server_port": 443}],
            "route": {"final": "proxy", "auto_detect_interface": True},
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertTrue(result.success, result.details)

    def test_rejects_missing_auto_route(self):
        config = {"inbounds": [{"type": "tun", "strict_route": True}], "outbounds": [{"type": "vless", "tag": "proxy", "server": "proxy.example"}], "route": {"final": "proxy", "auto_detect_interface": True}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertFalse(result.success)
        self.assertIn("auto_route", result.details)

    def test_rejects_direct_as_tunnel_default(self):
        config = {"inbounds": [{"type": "tun", "auto_route": True, "strict_route": True}], "outbounds": [{"type": "direct", "tag": "direct", "server": "unused"}], "route": {"final": "direct", "auto_detect_interface": True}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertFalse(result.success)
        self.assertIn("not a proxy", result.message)

    def test_rejects_selector_with_direct_choice_that_can_bypass_tunnel(self):
        config = {
            "inbounds": [{"type": "tun", "auto_route": True, "strict_route": True}],
            "outbounds": [
                {"type": "selector", "tag": "proxy-choice", "outbounds": ["remote", "direct"]},
                {"type": "vless", "tag": "remote", "server": "proxy.example", "server_port": 443},
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": "proxy-choice", "auto_detect_interface": True},
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertFalse(result.success)
        self.assertIn("bypass", result.message.casefold())

    def test_warns_when_explicit_route_rule_uses_direct_outbound(self):
        config = {
            "inbounds": [{"type": "tun", "auto_route": True, "strict_route": True}],
            "outbounds": [
                {"type": "vless", "tag": "proxy", "server": "proxy.example", "server_port": 443},
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": "proxy", "auto_detect_interface": True, "rules": [{"domain_suffix": ["local"], "outbound": "direct"}]},
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertTrue(result.success, result.details)
        self.assertIn("bypass the tunnel", result.details)
        self.assertIn("DNS queries are also routed", result.details)

    def test_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text("{not json", encoding="utf-8")
            result = validate_singbox_config(path)
        self.assertFalse(result.success)
        self.assertIn("Invalid", result.message)


class V0151UIStructureTests(unittest.TestCase):
    def test_connection_has_doh_dot_dnscrypt_and_full_tun_section(self):
        ui = (Path(__file__).parents[1] / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn('("dot", "DNS over TLS"', ui)
        self.assertIn('("dnscrypt", "DNSCrypt Proxy"', ui)
        self.assertIn('"Full Application Traffic Tunneling"', ui)
        self.assertIn('self.singbox_controller.start(*paths)', ui)
        self.assertIn('DNSCryptProxyController.generate_config', ui)

    def test_no_wireguard_or_old_wiresock_in_active_source(self):
        root = Path(__file__).parents[1]
        active = "\n".join(p.read_text(encoding="utf-8") for p in [root / "main.py", *list((root / "raider_dns").rglob("*.py"))])
        self.assertNotIn("WireGuard", active)
        self.assertNotIn("WireSock", active)


if __name__ == "__main__":
    unittest.main()
