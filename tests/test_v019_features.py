from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raider_dns.models import DNSProvider, PROVIDERS
from raider_dns.services.advanced_benchmark import _stats
from raider_dns.services.dnscrypt_management import (
    DNSCryptFeatureManager,
    normalize_domain,
    normalize_forwarding_rule,
    normalize_name_pattern,
    parse_query_log,
    parse_rule_text,
)
from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController
from raider_dns.services.connectivity_diagnostics import run_connectivity_checks
from raider_dns.services.network_profiles import NetworkProfileStore
from raider_dns.services.network_recovery_intelligence import NetworkRecoveryIntelligence
from raider_dns.services.resolver_pools import ResolverFailoverController

ROOT = Path(__file__).resolve().parents[1]


class WiFiDiagnosticsTests(unittest.TestCase):
    def _run_report(self, wifi_row):
        facts = {
            "adapters": [{"Name": "Wi-Fi", "Status": "Up", "InterfaceIndex": 7}],
            "routes": [{"NextHop": "192.168.1.1", "InterfaceIndex": 7, "RouteMetric": 10}],
            "dhcp": [{"InterfaceAlias": "Wi-Fi", "Dhcp": "Enabled"}],
            "addresses": [{"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.20"}],
            "drivers": [{"FriendlyName": "Wi-Fi Adapter", "Status": "OK", "Problem": 0}],
            "wifi_adapters": [wifi_row],
            "wlan_service": "Running",
            "wlan_interfaces": [{"name": "Wi-Fi", "state": "Connected", "ssid": "HomeNet"}],
        }
        with patch("raider_dns.services.connectivity_diagnostics._windows_network_facts", return_value=facts), \
             patch("raider_dns.services.connectivity_diagnostics._ping", return_value=(True, 1.0, "ok")), \
             patch("raider_dns.services.connectivity_diagnostics._tcp_connect", return_value=(True, 2.0, "ok")), \
             patch("raider_dns.services.connectivity_diagnostics._resolve_system", return_value=(True, 3.0, "ok")), \
             patch("raider_dns.services.connectivity_diagnostics._https_connectivity", return_value=(True, 4.0, "ok")):
            return run_connectivity_checks(adapter="Wi-Fi")

    def test_diagnostics_ignores_legacy_wifi_driver_inventory_payload(self) -> None:
        report = self._run_report({"name": "Wi-Fi", "driver_version": "23.80", "pnp_status": "Error", "problem_code": 10})
        identifiers = {item["id"] for item in report["checks"]}
        self.assertFalse({"wifi_driver_state", "driver_state", "wifi_inventory"} & identifiers)


class NetworkProfileTests(unittest.TestCase):
    def profile(self, **overrides):
        row = {
            "id": "home", "name": "Home", "ssid": "Home WiFi", "adapter_name": "Wi-Fi",
            "provider_id": "cloudflare", "servers": ["1.1.1.1", "1.0.0.1"],
            "dns_mode": "standard", "enabled": True, "auto_apply": True,
        }
        row.update(overrides)
        return row

    def test_profile_matches_exact_ssid_and_adapter(self) -> None:
        match = NetworkProfileStore.find_match([self.profile()], "  HOME   WIFI ", "Wi-Fi")
        self.assertIsNotNone(match)
        self.assertEqual(match["id"], "home")

    def test_profile_does_not_match_another_ssid(self) -> None:
        self.assertIsNone(NetworkProfileStore.find_match([self.profile()], "Guest", "Wi-Fi"))

    def test_adapter_only_ethernet_profile_matches_its_adapter(self) -> None:
        profile = self.profile(ssid="", adapter_name="Ethernet")
        self.assertIsNotNone(NetworkProfileStore.find_match([profile], "", "Ethernet"))
        self.assertIsNone(NetworkProfileStore.find_match([profile], "", "Wi-Fi"))

    def test_wifi_profile_cannot_be_saved_without_ssid_or_adapter_binding(self) -> None:
        self.assertIsNone(NetworkProfileStore.validate_profile(self.profile(ssid="", adapter_name="")))

    def test_profile_rejects_malformed_ip_addresses(self) -> None:
        self.assertIsNone(NetworkProfileStore.validate_profile(self.profile(servers=["999.999.999.999"])) )

    def test_adapter_bound_ssid_profile_does_not_match_when_adapter_identity_is_missing(self) -> None:
        self.assertIsNone(NetworkProfileStore.find_match([self.profile()], "Home WiFi", ""))


class NetworkRecoveryIntelligenceTests(unittest.TestCase):
    def test_capture_is_local_bounded_and_keeps_only_last_thirty_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = NetworkRecoveryIntelligence(Path(temp) / "network-intelligence.json")
            for index in range(35):
                store.capture({"adapter": f"Ethernet {index}", "checks": [], "summary": {"passed": 1}})
            history = store.history()
            self.assertEqual(len(history), 30)
            self.assertNotIn("adapter", history[0])
            self.assertNotIn("gateway", history[0])
            self.assertEqual(history[0]["adapter_status"], "Unknown")
            self.assertTrue(Path(temp, "network-intelligence.json").is_file())

    def test_compare_reports_network_context_and_check_status_changes(self) -> None:
        previous = {
            "adapter_status": "Up", "dhcp_enabled": True,
            "gateway": "192.168.1.1", "wifi_ssid": "HomeNet", "wifi_driver_version": "23.70",
            "checks": [{"id": "dns_resolution", "title": "System DNS", "status": "PASS"}],
        }
        current = {
            "adapter_status": "Down", "dhcp_enabled": False,
            "gateway": "192.168.50.1", "wifi_ssid": "GuestNet", "wifi_driver_version": "23.80",
            "checks": [{"id": "dns_resolution", "title": "System DNS", "status": "FAIL"}],
        }
        changes = NetworkRecoveryIntelligence.compare(previous, current)
        changed_fields = {row["field"] for row in changes}
        self.assertIn("adapter_status", changed_fields)
        self.assertIn("dhcp_enabled", changed_fields)
        self.assertNotIn("gateway", changed_fields)
        self.assertNotIn("wifi_ssid", changed_fields)
        self.assertNotIn("wifi_driver_version", changed_fields)
        self.assertIn("check:dns_resolution", changed_fields)

    def test_capture_includes_previous_snapshot_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = NetworkRecoveryIntelligence(Path(temp) / "network-intelligence.json")
            store.capture({"adapter": "Wi-Fi", "adapter_status": "Up", "dhcp_enabled": True, "gateway": "192.168.1.1", "wifi_ssid": "Home", "checks": []})
            second = store.capture({"adapter": "Wi-Fi", "adapter_status": "Down", "dhcp_enabled": False, "gateway": "192.168.2.1", "wifi_ssid": "Guest", "checks": []})
            labels = {row["label"] for row in second["changes_from_previous"]}
            self.assertIn("Link status", labels)
            self.assertIn("DHCP setting", labels)
            self.assertNotIn("Default gateway", labels)
            self.assertNotIn("Wi-Fi network (SSID)", labels)

    def test_assessment_advises_non_destructive_link_checks(self) -> None:
        report = {"checks": [{"id": "adapter_state", "status": "FAIL", "details": "Link is down"}]}
        findings = NetworkRecoveryIntelligence.assess(report)
        self.assertTrue(any("network adapter is not up" in row["title"].casefold() for row in findings))
        advice = " ".join(row["recommendation"] for row in findings)
        self.assertIn("physical connection", advice)
        self.assertNotIn("driver reset", advice.casefold())

    def test_assessment_does_not_report_dns_fault_when_dns_and_transport_pass(self) -> None:
        report = {"checks": [
            {"id": "dns_resolution", "status": "PASS"},
            {"id": "tcp_external_443", "status": "PASS"},
            {"id": "https_connectivity", "status": "PASS"},
        ]}
        findings = NetworkRecoveryIntelligence.assess(report)
        self.assertEqual(findings[0]["severity"], "success")


class DNSCryptManagementTests(unittest.TestCase):
    def test_domain_and_rule_parsers_normalize_inputs(self) -> None:
        self.assertEqual(normalize_domain("BÜCHER.example."), "xn--bcher-kva.example")
        self.assertEqual(normalize_name_pattern("*.Tracking.Example"), "*.tracking.example")
        self.assertEqual(normalize_name_pattern("=login.example"), "=login.example")
        self.assertEqual(normalize_forwarding_rule("corp.example", "10.0.0.53,[2001:db8::53]:5353"), "corp.example 10.0.0.53,[2001:db8::53]:5353")
        self.assertEqual(parse_rule_text("ads.example\n*.ads.example\nads.example", "names"), ["ads.example", "*.ads.example"])

    def test_rule_parser_rejects_invalid_upstream_hostnames_and_interior_globs(self) -> None:
        with self.assertRaises(ValueError):
            normalize_forwarding_rule("corp.example", "dns.internal")
        with self.assertRaises(ValueError):
            normalize_name_pattern("ad*.example")

    def test_dnscrypt_feature_config_validates_and_uses_rule_file_hot_reload_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = DNSCryptProxyController.generate_config(root / "dnscrypt-proxy.generated.toml")
            manager = DNSCryptFeatureManager(config)
            result = manager.configure(
                query_monitor_enabled=True,
                filtering_enabled=True,
                split_dns_enabled=True,
                blocked_rules="ads.example\n*.track.example",
                allowed_rules="trusted.example",
                forwarding_rules="corp.example 10.0.0.53",
            )
            valid, message = DNSCryptProxyController.validate_config(config)
            self.assertTrue(valid, message)
            self.assertTrue(result["hot_reload_enabled"])
            self.assertEqual(manager.status()["blocked_rules"], 2)
            self.assertEqual(manager.status()["forwarding_rules"], 1)
            self.assertTrue((root / "blocked-names.txt").exists())
            self.assertTrue((root / "allowed-names.txt").exists())
            self.assertTrue((root / "forwarding-rules.txt").exists())

    def test_filtering_requires_at_least_one_block_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = DNSCryptProxyController.generate_config(Path(temp) / "dnscrypt-proxy.generated.toml")
            manager = DNSCryptFeatureManager(config)
            with self.assertRaisesRegex(ValueError, "blocklist is empty"):
                manager.configure(query_monitor_enabled=False, filtering_enabled=True, split_dns_enabled=False, allowed_rules="trusted.example")

    def test_query_logging_alone_does_not_enable_rule_file_hot_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = DNSCryptProxyController.generate_config(root / "dnscrypt-proxy.generated.toml")
            manager = DNSCryptFeatureManager(config)
            result = manager.configure(query_monitor_enabled=True, filtering_enabled=False, split_dns_enabled=False)
            self.assertFalse(result["hot_reload_enabled"])
            valid, message = DNSCryptProxyController.validate_config(config)
            self.assertTrue(valid, message)

    def test_invalid_rule_update_does_not_modify_existing_managed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = DNSCryptProxyController.generate_config(root / "dnscrypt-proxy.generated.toml")
            manager = DNSCryptFeatureManager(config)
            manager.configure(query_monitor_enabled=False, filtering_enabled=True, split_dns_enabled=False, blocked_rules="ads.example")
            original_config = config.read_text(encoding="utf-8")
            original_rules = manager.blocked_path.read_text(encoding="utf-8")
            with self.assertRaises(ValueError):
                manager.configure(query_monitor_enabled=False, filtering_enabled=True, split_dns_enabled=True, blocked_rules="*.ads.example", forwarding_rules="corp.example hostname.local")
            self.assertEqual(config.read_text(encoding="utf-8"), original_config)
            self.assertEqual(manager.blocked_path.read_text(encoding="utf-8"), original_rules)

    def test_query_log_parser_limits_rows_and_parses_tsv(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "query.log"
            path.write_text("2026-11-03T10:00:00Z\t127.0.0.1\texample.com\tA\tNOERROR\t12ms\tresolver\t\n", encoding="utf-8")
            rows = parse_query_log(path, limit=1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["query_name"], "example.com")

    def test_status_handles_unreadable_rule_file_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = DNSCryptProxyController.generate_config(root / "dnscrypt-proxy.generated.toml")
            manager = DNSCryptFeatureManager(config)
            manager.blocked_path.write_bytes(b"\xff\xfeinvalid-utf8")
            status = manager.status()
            self.assertTrue(status["configured"])
            self.assertEqual(status["blocked_rules"], 0)

    def test_status_handles_valid_toml_with_wrong_table_types(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "dnscrypt-proxy.generated.toml"
            config.write_text('query_log = "not-a-table"\nblocked_names = "not-a-table"\nallowed_names = []\n', encoding="utf-8")
            manager = DNSCryptFeatureManager(config)
            status = manager.status()
            self.assertTrue(status["configured"])
            self.assertFalse(status["query_monitor_enabled"])
            self.assertFalse(status["filtering_enabled"])


class AdvancedBenchmarkExecutionTests(unittest.TestCase):
    def test_warm_cache_samples_include_an_unmeasured_warmup_query(self) -> None:
        from raider_dns.services.advanced_benchmark import run_advanced_benchmark
        from raider_dns.services.dns_probe import ProbeResult
        provider = PROVIDERS[0]
        probe_result = ProbeResult(provider.id, provider.name, "UDP / 53", True, 2.0, "ok")
        with patch("raider_dns.services.advanced_benchmark.probe_udp", return_value=probe_result) as warm_probe, \
             patch("raider_dns.services.advanced_benchmark._probe_dns_response", return_value=(True, 4.0, "ok")):
            result = run_advanced_benchmark(provider, domain="example.com", rounds=3, timeout=1.0)
        self.assertEqual(warm_probe.call_count, 4)  # one unmeasured cache prime + three samples
        self.assertEqual(result["warm"]["total"], 3)
        self.assertEqual(result["warm"]["successes"], 3)

    def test_benchmark_uses_unique_names_for_uncached_samples(self) -> None:
        from raider_dns.services.advanced_benchmark import run_advanced_benchmark
        from raider_dns.services.dns_probe import ProbeResult
        provider = PROVIDERS[0]
        probe_result = ProbeResult(provider.id, provider.name, "UDP / 53", True, 2.0, "ok")
        with patch("raider_dns.services.advanced_benchmark.probe_udp", return_value=probe_result), \
             patch("raider_dns.services.advanced_benchmark._probe_dns_response", return_value=(True, 4.0, "ok")) as cold_probe:
            run_advanced_benchmark(provider, domain="example.com", rounds=3, timeout=1.0)
        names = [call.args[1] for call in cold_probe.call_args_list]
        self.assertEqual(len(names), 3)
        self.assertEqual(len(set(names)), 3)

class BenchmarkStatisticsTests(unittest.TestCase):
    def test_advanced_benchmark_stats_include_percentile_jitter_and_reliability(self) -> None:
        result = _stats([10.0, 20.0, 15.0, 30.0], successes=4, total=5)
        self.assertEqual(result["median_ms"], 17.5)
        self.assertEqual(result["p95_ms"], 30.0)
        self.assertEqual(result["success_rate"], 80.0)
        self.assertEqual(result["successes"], 4)
        self.assertEqual(result["total"], 5)


class ResolverFailoverTests(unittest.TestCase):
    def test_failover_requires_three_consecutive_primary_failures_and_live_fallback(self) -> None:
        controller = ResolverFailoverController("primary", "fallback", failure_threshold=3, recovery_threshold=2)
        self.assertEqual(controller.record(False, True).action, "none")
        self.assertEqual(controller.record(False, True).action, "none")
        decision = controller.record(False, True)
        self.assertEqual(decision.action, "switch_to_fallback")
        self.assertEqual(decision.active_provider_id, "fallback")

    def test_failover_never_switches_when_both_resolvers_fail(self) -> None:
        controller = ResolverFailoverController("primary", "fallback")
        for _ in range(3):
            decision = controller.record(False, False)
        self.assertEqual(decision.action, "none")
        self.assertEqual(decision.active_provider_id, "primary")

    def test_return_to_primary_requires_two_successful_recovery_checks(self) -> None:
        controller = ResolverFailoverController("primary", "fallback", active_provider_id="fallback")
        self.assertEqual(controller.record(True, True).action, "none")
        decision = controller.record(True, True)
        self.assertEqual(decision.action, "restore_primary")
        self.assertEqual(decision.active_provider_id, "primary")

    def test_invalid_duplicate_resolver_pool_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ResolverFailoverController("same", "same")


class V019IntegrationSourceTests(unittest.TestCase):
    def test_feature_services_are_connected_to_main_window(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        for expected in (
            "_refresh_dashboard_network_context", "_build_dns_tools_page", "run_advanced_benchmark",
            "probe_resolver_pair", "NetworkProfileStore.find_match", "_refresh_engine_supervisor",
            "_resolver_pool_probe_finished", "_refresh_dnscrypt_queries",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)
        self.assertNotIn("_build_network_intelligence_page", source)
        self.assertNotIn("_build_profiles_page", source)

    def test_auto_network_profile_does_not_prompt_for_uac_in_background(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        start = source.index("    def _maybe_auto_apply_network_profile(")
        end = source.index("    def _network_profile_apply_finished(", start)
        method = source[start:end]
        self.assertIn("not self.system_dns.is_admin()", method)
        self.assertIn("_auto_profile_admin_notice_shown", method)

    def test_dnscrypt_ui_describes_restart_requirement_and_uses_slow_query_poll(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn("self.dnscrypt_query_timer.setInterval(5000)", source)
        self.assertIn("Main TOML changes such as query logging and load-balancing strategy require a DNSCrypt Proxy restart", source)

    def test_plasma_visual_density_is_preserved(self) -> None:
        import ast
        source_path = ROOT / "raider_dns/ui/main_window.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignments = {
            target.id: node.value
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name)
        }
        visual_constants = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "paintEvent":
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and target.id in {"ribbon_specs", "offsets"}:
                                visual_constants[target.id] = child.value
        self.assertEqual(len(ast.literal_eval(visual_constants["ribbon_specs"])), 4)
        self.assertEqual(len(ast.literal_eval(visual_constants["offsets"])), 11)
        self.assertIn("ribbon_alphas = (66, 82, 72, 54)", source)


if __name__ == "__main__":
    unittest.main()
