from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raider_dns.models import PROVIDERS
from raider_dns.services.dns_probe import (
    DNS_QUERY_TYPES,
    ProbeResult,
    benchmark_provider_metrics,
    build_dns_query,
)
from raider_dns.services.health_monitor import DNSHealthStateTracker
from raider_dns.services.network_monitor import build_network_signature, classify_network_transition
from raider_dns.storage import ConfigStore, default_settings


class DNSHealthStateTrackerTests(unittest.TestCase):
    def test_consecutive_failures_are_required_before_unhealthy(self) -> None:
        tracker = DNSHealthStateTracker()
        self.assertFalse(tracker.record(False, failure_threshold=3).changed)
        self.assertFalse(tracker.record(False, failure_threshold=3).changed)
        transition = tracker.record(False, failure_threshold=3)
        self.assertTrue(transition.changed)
        self.assertEqual(transition.previous, "unknown")
        self.assertEqual(transition.current, "unhealthy")
        self.assertEqual(transition.failures, 3)

    def test_recovery_requires_consecutive_successes(self) -> None:
        tracker = DNSHealthStateTracker()
        for _ in range(3):
            tracker.record(False, failure_threshold=3, recovery_threshold=2)
        self.assertFalse(tracker.record(True, failure_threshold=3, recovery_threshold=2).changed)
        transition = tracker.record(True, failure_threshold=3, recovery_threshold=2)
        self.assertTrue(transition.changed)
        self.assertEqual(transition.previous, "unhealthy")
        self.assertEqual(transition.current, "healthy")
        self.assertEqual(transition.failures, 0)

    def test_one_transient_failure_does_not_flip_healthy_state(self) -> None:
        tracker = DNSHealthStateTracker()
        tracker.record(True)
        transition = tracker.record(False, failure_threshold=3)
        self.assertFalse(transition.changed)
        self.assertEqual(transition.current, "healthy")
        self.assertEqual(transition.failures, 1)

    def test_reset_returns_to_unknown(self) -> None:
        tracker = DNSHealthStateTracker()
        tracker.record(True)
        tracker.reset()
        self.assertEqual(tracker.state, "unknown")
        self.assertEqual(tracker.consecutive_successes, 0)
        self.assertEqual(tracker.consecutive_failures, 0)


class NetworkTransitionTests(unittest.TestCase):
    def test_disconnect_and_reconnect_are_classified(self) -> None:
        connected = build_network_signature(["Ethernet"], [], {})
        disconnected = build_network_signature([], [], {})
        self.assertEqual(classify_network_transition(connected, disconnected), "disconnected")
        self.assertEqual(classify_network_transition(disconnected, connected), "reconnected")

    def test_dns_or_address_change_is_classified_as_changed(self) -> None:
        before = build_network_signature(["Ethernet"], [{"adapter": "Ethernet", "family": "IPv4", "servers": ["1.1.1.1"]}], {"private_ipv4": ["192.168.1.2"]})
        after = build_network_signature(["Ethernet"], [{"adapter": "Ethernet", "family": "IPv4", "servers": ["9.9.9.9"]}], {"private_ipv4": ["192.168.1.2"]})
        self.assertEqual(classify_network_transition(before, after), "changed")

    def test_initial_signature_does_not_generate_a_transition(self) -> None:
        current = build_network_signature(["Wi-Fi"], [], {})
        self.assertIsNone(classify_network_transition(None, current))
        self.assertIsNone(classify_network_transition(current, current))


class AdvancedBenchmarkTests(unittest.TestCase):
    def test_dns_query_type_map_and_query_packet(self) -> None:
        self.assertEqual(DNS_QUERY_TYPES["AAAA"], 28)
        packet = build_dns_query("status.example", qtype=DNS_QUERY_TYPES["AAAA"], transaction_id=0x1234)
        self.assertEqual(struct.unpack("!H", packet[:2])[0], 0x1234)
        self.assertEqual(packet[-4:], struct.pack("!HH", 28, 1))

    def test_custom_query_settings_are_passed_to_each_fresh_probe(self) -> None:
        provider = PROVIDERS[0]
        samples = [5.0, 20.0, 10.0]
        results = [ProbeResult(provider.id, provider.name, "UDP / 53", True, latency, "ok") for latency in samples]
        with patch("raider_dns.services.dns_probe.probe_udp", side_effect=results) as query_probe:
            result = benchmark_provider_metrics(
                provider,
                rounds=3,
                timeout=1.25,
                measurements=("query",),
                domain="status.example",
                query_type=28,
            )
        self.assertEqual(query_probe.call_count, 3)
        for call in query_probe.call_args_list:
            self.assertEqual(call.kwargs["timeout"], 1.25)
            self.assertEqual(call.kwargs["domain"], "status.example")
            self.assertEqual(call.kwargs["qtype"], 28)
        self.assertEqual(result["query_median_ms"], 10.0)
        self.assertEqual(result["query_min_ms"], 5.0)
        self.assertEqual(result["query_max_ms"], 20.0)
        self.assertEqual(result["query_p95_ms"], 20.0)
        self.assertEqual(result["query_jitter_ms"], 12.5)
        self.assertEqual(result["query_success_rate"], 100.0)

    def test_probe_failures_are_counted_without_fabricating_latency(self) -> None:
        provider = PROVIDERS[0]
        failure = ProbeResult(provider.id, provider.name, "UDP / 53", False, None, "timeout")
        with patch("raider_dns.services.dns_probe.probe_udp", return_value=failure):
            result = benchmark_provider_metrics(provider, rounds=3, measurements=("query",))
        self.assertIsNone(result["query_median_ms"])
        self.assertIsNone(result["query_p95_ms"])
        self.assertEqual(result["query_success_rate"], 0.0)
        self.assertEqual(result["query_successes"], 0)


class V014SettingsTests(unittest.TestCase):
    def test_new_settings_defaults_are_safe(self) -> None:
        settings = default_settings()
        self.assertTrue(settings["notifications_enabled"])
        self.assertFalse(settings["health_monitor_enabled"])
        self.assertEqual(settings["health_interval_seconds"], 30)
        self.assertEqual(settings["health_timeout_seconds"], 2.5)
        self.assertEqual(settings["health_failure_threshold"], 3)
        self.assertEqual(settings["health_recovery_threshold"], 2)
        self.assertEqual(settings["network_poll_interval_seconds"], 20)

    def test_invalid_new_settings_are_normalized_without_losing_other_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "settings.json"
            settings_path.write_text(json.dumps({
                "theme": "light",
                "notifications_enabled": False,
                "health_monitor_enabled": True,
                "health_interval_seconds": 17,
                "health_timeout_seconds": 4.4,
                "health_failure_threshold": 99,
                "health_recovery_threshold": 0,
                "network_poll_interval_seconds": 7,
                "tooltip_delay_ms": 999,
                "benchmark_rounds": 2,
            }), encoding="utf-8")
            loaded = ConfigStore(settings_path).load()
        self.assertEqual(loaded["theme"], "light")
        self.assertFalse(loaded["notifications_enabled"])
        self.assertTrue(loaded["health_monitor_enabled"])
        self.assertEqual(loaded["health_interval_seconds"], 30)
        self.assertEqual(loaded["health_timeout_seconds"], 2.5)
        self.assertEqual(loaded["health_failure_threshold"], 3)
        self.assertEqual(loaded["health_recovery_threshold"], 2)
        self.assertEqual(loaded["network_poll_interval_seconds"], 20)
        self.assertNotIn("tooltip_delay_ms", loaded)
        self.assertEqual(loaded["benchmark_rounds"], 3)

    def test_valid_network_poll_interval_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({"network_poll_interval_seconds": 60}), encoding="utf-8")
            self.assertEqual(ConfigStore(path).load()["network_poll_interval_seconds"], 60)


class V014UIStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (Path(__file__).parents[1] / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")

    def test_navigation_places_security_center_under_providers(self) -> None:
        nav = self.source[self.source.index("NAV_ITEMS = ["):self.source.index("def __init__(self)", self.source.index("NAV_ITEMS = ["))]
        providers = nav.index('("DNS Providers"')
        security = nav.index('("DNS Security Center"')
        benchmark = nav.index('("Benchmark Lab"')
        self.assertLess(providers, security)
        self.assertLess(security, benchmark)

    def test_soft_tooltips_have_delay_and_fade(self) -> None:
        tooltip = self.source[self.source.index("class DelayedToolTipController"):self.source.index("class AppNotificationToast")]
        self.assertIn("setInterval(self.delay_ms)", tooltip)
        self.assertIn("setDuration(150)", tooltip)
        self.assertIn("OutCubic", tooltip)
        self.assertIn("_auto_description", tooltip)

    def test_provider_context_menu_exposes_real_delete_and_modify_actions(self) -> None:
        method = self.source[self.source.index("def _show_provider_context_menu"):self.source.index("def _delete_custom_provider")]
        self.assertIn('menu.addAction("Delete DNS")', method)
        self.assertIn('menu.addAction("Modify DNS")', method)
        self.assertIn("else \"Favorite DNS\"", method)
        self.assertIn('delete_action.setEnabled(len(self._all_providers()) > 1)', method)
        self.assertIn('self._delete_provider(provider_id)', method)
        self.assertIn('self._provider_editor_dialog(provider_id)', method)

    def test_activity_refresh_uses_memory_cache_and_debounce(self) -> None:
        method = self.source[self.source.index("def _refresh_activity_table"):self.source.index("def _insert_activity_row_if_fast_path")]
        self.assertIn("list(self._activity_records)", method)
        self.assertNotIn("activity_store.load()", method)
        self.assertIn("setUpdatesEnabled(False)", method)
        self.assertIn("_activity_table_refresh_timer.start(180)", self.source)

    def test_security_and_benchmark_pages_include_real_query_metrics(self) -> None:
        self.assertIn('"DNS Security Center"', self.source)
        self.assertIn('"Advanced DNS Benchmark Lab"', self.source)
        self.assertIn('"query_p95_ms"', self.source)
        self.assertIn('"query_jitter_ms"', self.source)
        self.assertIn("benchmark_provider_metrics(", self.source)

    def test_health_monitor_has_failure_and_recovery_settings_and_app_toasts(self) -> None:
        self.assertIn('"health_failure_threshold"', self.source)
        self.assertIn('"health_recovery_threshold"', self.source)
        self.assertIn('"network_poll_interval_seconds"', self.source)
        self.assertIn('title = "Network disconnected"', self.source)
        self.assertIn('self._show_app_notification(title, body, kind)', self.source)
        self.assertIn('notification_title = "DNS configuration verified"', self.source)
        self.assertIn('self._show_app_notification(notification_title', self.source)
        self.assertIn('self._show_app_notification("DNS health recovered"', self.source)


if __name__ == "__main__":
    unittest.main()
