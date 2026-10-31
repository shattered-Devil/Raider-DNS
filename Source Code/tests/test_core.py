from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from raider_dns.models import PROVIDERS
from raider_dns.services.dns_probe import ProbeResult, benchmark_provider, benchmark_provider_metrics, build_dns_query, parse_icmp_reply_latency, rank_benchmark_results, _valid_dns_response, probe_dot
from raider_dns.storage import ConfigStore, default_settings


class DNSProbeTests(unittest.TestCase):
    def test_provider_addresses_are_valid_ipv4(self) -> None:
        from ipaddress import ip_address
        for provider in PROVIDERS:
            provider.validate()
            for address in provider.servers:
                self.assertEqual(ip_address(address).version, 4)

    def test_build_dns_query_header_and_question(self) -> None:
        query = build_dns_query("example.com", transaction_id=0x1234)
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", query[:12])
        self.assertEqual(txid, 0x1234)
        self.assertEqual(flags, 0x0100)
        self.assertEqual(qdcount, 1)
        self.assertEqual((ancount, nscount, arcount), (0, 0, 0))
        self.assertTrue(query.endswith(struct.pack("!HH", 1, 1)))

    def test_dns_response_validator_accepts_success(self) -> None:
        transaction_id = 0xCAFE
        response = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
        okay, message = _valid_dns_response(response, transaction_id)
        self.assertTrue(okay)
        self.assertIn("succeeded", message)

    def test_dns_response_validator_rejects_mismatched_id(self) -> None:
        response = struct.pack("!HHHHHH", 2, 0x8180, 1, 1, 0, 0)
        okay, message = _valid_dns_response(response, 1)
        self.assertFalse(okay)
        self.assertIn("ID", message)

    def test_empty_domain_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_dns_query("")

    def test_dot_probe_reports_missing_provider_metadata_without_network(self) -> None:
        provider = next(item for item in PROVIDERS if item.dot_hostname is None)
        result = probe_dot(provider)
        self.assertFalse(result.success)
        self.assertIn("no configured DoT hostname", result.message)

    def test_benchmark_uses_median_and_success_rate(self) -> None:
        provider = PROVIDERS[0]
        results = [
            ProbeResult(provider.id, provider.name, "UDP / 53", True, 10.0, "ok"),
            ProbeResult(provider.id, provider.name, "UDP / 53", False, None, "timeout"),
            ProbeResult(provider.id, provider.name, "UDP / 53", True, 20.0, "ok"),
        ]
        from unittest.mock import patch
        with patch("raider_dns.services.dns_probe.probe_udp", side_effect=results):
            benchmark = benchmark_provider(provider, rounds=3)
        self.assertEqual(benchmark["success_rate"], 66.7)
        self.assertEqual(benchmark["median_ms"], 15.0)
        self.assertEqual(benchmark["successes"], 2)

    def test_metric_benchmark_reports_independent_medians(self) -> None:
        from unittest.mock import patch
        provider = PROVIDERS[0]
        icmp = [ProbeResult(provider.id, provider.name, "ICMP ping", True, n, "ok") for n in (9, 5, 7)]
        tcp = [ProbeResult(provider.id, provider.name, "TCP / 53", True, n, "ok") for n in (3, 6, 4)]
        query = [ProbeResult(provider.id, provider.name, "UDP / 53", True, n, "ok") for n in (13, 11, 15)]
        with patch("raider_dns.services.dns_probe.probe_icmp", side_effect=icmp), \
             patch("raider_dns.services.dns_probe.probe_tcp53", side_effect=tcp), \
             patch("raider_dns.services.dns_probe.probe_udp", side_effect=query):
            result = benchmark_provider_metrics(provider, rounds=3, measurements=("median", "tcp", "query"))
        self.assertEqual(result["median_ms"], 7.0)
        self.assertEqual(result["tcp_median_ms"], 4.0)
        self.assertEqual(result["query_median_ms"], 13.0)
        self.assertEqual(result["median_success_rate"], 100.0)
        self.assertEqual(result["query_successes"], 3)

    def test_benchmark_rank_defaults_to_actual_dns_query_and_keeps_missing_last(self) -> None:
        results = [
            {"provider_name": "ICMP winner", "median_ms": 2.0, "query_median_ms": 40.0, "query_success_rate": 100.0},
            {"provider_name": "DNS winner", "median_ms": 30.0, "query_median_ms": 10.0, "query_success_rate": 66.7},
            {"provider_name": "Unknown", "median_ms": 1.0, "query_median_ms": None, "query_success_rate": 0.0},
        ]
        ranked = rank_benchmark_results(results)
        self.assertEqual([row["provider_name"] for row in ranked], ["DNS winner", "ICMP winner", "Unknown"])
        descending = rank_benchmark_results(results, metric="median", ascending=False)
        self.assertEqual([row["provider_name"] for row in descending], ["DNS winner", "ICMP winner", "Unknown"])

    def test_benchmark_rank_can_use_tcp_or_query_metrics(self) -> None:
        results = [
            {"provider_name": "Alpha", "tcp_median_ms": 12.0, "query_median_ms": 5.0},
            {"provider_name": "Beta", "tcp_median_ms": 4.0, "query_median_ms": 22.0},
        ]
        self.assertEqual([row["provider_name"] for row in rank_benchmark_results(results, "tcp")], ["Beta", "Alpha"])
        self.assertEqual([row["provider_name"] for row in rank_benchmark_results(results, "query")], ["Alpha", "Beta"])

    def test_parse_icmp_reply_latency_supports_common_ping_formats(self) -> None:
        self.assertEqual(parse_icmp_reply_latency("Reply from 1.1.1.1: bytes=32 time=12ms TTL=55"), 12.0)
        self.assertEqual(parse_icmp_reply_latency("Antwort von 1.1.1.1: Zeit=1,5ms"), 1.5)
        self.assertEqual(parse_icmp_reply_latency("Reply from 1.1.1.1: time<1ms"), 1.0)
        self.assertIsNone(parse_icmp_reply_latency("Request timed out."))

    def test_metric_benchmark_only_runs_selected_measurements(self) -> None:
        from unittest.mock import patch
        provider = PROVIDERS[0]
        tcp = ProbeResult(provider.id, provider.name, "TCP / 53", True, 4.0, "ok")
        with patch("raider_dns.services.dns_probe.probe_icmp") as icmp, \
             patch("raider_dns.services.dns_probe.probe_tcp53", return_value=tcp) as tcp_probe, \
             patch("raider_dns.services.dns_probe.probe_udp") as query:
            result = benchmark_provider_metrics(provider, rounds=1, measurements=("tcp",))
        icmp.assert_not_called()
        tcp_probe.assert_called_once()
        query.assert_not_called()
        self.assertEqual(result["tcp_median_ms"], 4.0)
        self.assertIsNone(result["median_ms"])
        self.assertIsNone(result["query_median_ms"])


class StorageTests(unittest.TestCase):
    def test_defaults_are_returned_if_file_does_not_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp) / "settings.json")
            self.assertEqual(store.load(), default_settings())

    def test_save_and_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp) / "settings.json")
            settings = default_settings()
            settings["theme"] = "light"
            settings["favorites"] = ["google", "quad9"]
            store.save(settings)
            self.assertEqual(store.load()["theme"], "light")
            self.assertEqual(store.load()["favorites"], ["google", "quad9"])

    def test_invalid_json_is_preserved_and_defaults_returned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text("{bad", encoding="utf-8")
            store = ConfigStore(path)
            self.assertEqual(store.load(), default_settings())
            self.assertTrue((Path(tmp) / "settings.corrupt.json").exists())

    def test_custom_provider_and_order_are_persisted_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            settings = default_settings()
            settings["custom_providers"] = [{
                "id": "custom-home-dns-123abc45", "name": "Home DNS", "description": "Private resolver",
                "primary": "192.0.2.53", "secondary": "192.0.2.54", "category": "Home",
                "doh_url": "https://dns.example/dns-query", "dot_hostname": "dns.example", "website": "https://dns.example/",
            }]
            settings["provider_order"] = ["google", "custom-home-dns-123abc45", "cloudflare"]
            settings["selected_provider"] = "custom-home-dns-123abc45"
            settings["connection_dns_provider"] = "custom-home-dns-123abc45"
            store = ConfigStore(path)
            store.save(settings)
            loaded = store.load()
            self.assertEqual(loaded["custom_providers"][0]["name"], "Home DNS")
            self.assertEqual(loaded["provider_order"][0], "google")
            self.assertEqual(loaded["selected_provider"], "custom-home-dns-123abc45")
            self.assertEqual(loaded["connection_dns_provider"], "custom-home-dns-123abc45")

    def test_malformed_custom_provider_urls_are_dropped_without_resetting_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({
                "theme": "light",
                "custom_providers": [{
                    "id": "custom-bad-url-123abc45",
                    "name": "Broken endpoint",
                    "primary": "192.0.2.53",
                    "secondary": "",
                    "doh_url": "https://[invalid",
                    "website": "https://[invalid",
                }],
            }), encoding="utf-8")
            loaded = ConfigStore(path).load()
            self.assertEqual(loaded["theme"], "light")
            self.assertEqual(len(loaded["custom_providers"]), 1)
            self.assertIsNone(loaded["custom_providers"][0]["doh_url"])
            self.assertEqual(loaded["custom_providers"][0]["website"], "")

    def test_malformed_settings_values_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({
                "theme": "neon",
                "selected_provider": "not-a-provider",
                "fallback_provider": "unknown",
                "window_width": "too wide",
                "favorites": ["google", {}, "unknown"],
                "profiles": [
                    {"id": "bad", "name": "Bad", "servers": ["not-an-ip"]},
                    {"id": "ok", "name": "Good", "servers": ["9.9.9.9"]},
                ],
            }), encoding="utf-8")
            loaded = ConfigStore(path).load()
            self.assertEqual(loaded["theme"], "dark")
            self.assertEqual(loaded["selected_provider"], "cloudflare")
            self.assertEqual(loaded["fallback_provider"], "quad9")
            self.assertEqual(loaded["window_width"], default_settings()["window_width"])
            self.assertEqual(loaded["favorites"], ["google"])
            self.assertEqual([p["name"] for p in loaded["profiles"]], ["Good"])


if __name__ == "__main__":
    unittest.main()
