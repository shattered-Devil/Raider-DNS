from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from raider_dns.services.provider_cache import ProviderMetadataCache
from raider_dns.services.timeouts import (
    BENCHMARK_PROBE_TIMEOUT_SECONDS,
    DOH_TIMEOUT_SECONDS,
    DOT_TIMEOUT_SECONDS,
    ICMP_TIMEOUT_SECONDS,
    MAX_CONCURRENT_NETWORK_TASKS,
    TCP_DNS_TIMEOUT_SECONDS,
    UDP_DNS_TIMEOUT_SECONDS,
)
from raider_dns.storage import ActivityLogStore, BackgroundActivityLogger
from raider_dns.ui.theme import stylesheet


class ProviderMetadataCacheTests(unittest.TestCase):
    def test_reuses_provider_metadata_until_signature_changes(self) -> None:
        cache: ProviderMetadataCache[str] = ProviderMetadataCache()
        calls = 0

        def build() -> list[str]:
            nonlocal calls
            calls += 1
            return ["Cloudflare", "Quad9"]

        first = cache.get("stable-v1", build)
        second = cache.get("stable-v1", build)
        self.assertEqual(first, ["Cloudflare", "Quad9"])
        self.assertEqual(second, first)
        self.assertEqual(calls, 1)

        changed = cache.get("stable-v2", lambda: ["Cloudflare", "Quad9", "Custom DNS"])
        self.assertEqual(changed[-1], "Custom DNS")
        self.assertEqual(calls, 1)

    def test_returned_list_cannot_mutate_cache(self) -> None:
        cache: ProviderMetadataCache[str] = ProviderMetadataCache()
        result = cache.get("v1", lambda: ["Cloudflare"])
        result.append("Injected provider")
        self.assertEqual(cache.get("v1", lambda: []), ["Cloudflare"])


class BackgroundActivityLoggerTests(unittest.TestCase):
    def test_appends_are_ordered_and_persisted_off_the_calling_thread(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ActivityLogStore(Path(tmp) / "activity.json")
            logger = BackgroundActivityLogger(store)
            logger.append({"timestamp": "t1", "level": "INFO", "action": "first", "details": ""})
            logger.append({"timestamp": "t2", "level": "INFO", "action": "second", "details": ""})
            self.assertTrue(logger.flush(timeout=3.0))
            self.assertEqual([r["action"] for r in store.load()], ["first", "second"])
            self.assertTrue(logger.shutdown(timeout=3.0))

    def test_clear_then_append_preserves_newer_log_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ActivityLogStore(Path(tmp) / "activity.json")
            logger = BackgroundActivityLogger(store)
            logger.append({"timestamp": "t1", "level": "INFO", "action": "old", "details": ""})
            logger.clear()
            logger.append({"timestamp": "t2", "level": "WARNING", "action": "cleared", "details": ""})
            self.assertTrue(logger.flush(timeout=3.0))
            self.assertEqual([r["action"] for r in store.load()], ["cleared"])
            self.assertTrue(logger.shutdown(timeout=3.0))

    def test_store_batch_persists_many_activity_rows_with_one_atomic_write(self) -> None:
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            store = ActivityLogStore(Path(tmp) / "activity.json")
            rows = [
                {"timestamp": f"t{i}", "level": "INFO", "action": f"row-{i}", "details": ""}
                for i in range(10)
            ]
            with patch.object(store, "_write", wraps=store._write) as write:
                store.append_many(rows)
            write.assert_called_once()
            self.assertEqual([row["action"] for row in store.load()], [f"row-{i}" for i in range(10)])


class ThemeSurfaceTests(unittest.TestCase):
    def test_every_theme_has_explicit_page_surface_color(self) -> None:
        expected = {
            "dark": "#0b1019",
            "light": "#eef2f7",
            "midnight": "#100d1b",
            "ocean": "#071722",
            "high_contrast": "#000000",
        }
        for theme, color in expected.items():
            with self.subTest(theme=theme):
                qss = stylesheet(theme)
                self.assertIn(f"QWidget#PageContent {{ background-color: {color}; }}", qss)
                self.assertIn(f"QScrollArea#PageScrollArea {{ background-color: {color}; border: none; }}", qss)


class TimeoutPolicyTests(unittest.TestCase):
    def test_network_timeouts_are_positive_and_concurrency_is_bounded(self) -> None:
        for timeout in (
            UDP_DNS_TIMEOUT_SECONDS,
            TCP_DNS_TIMEOUT_SECONDS,
            ICMP_TIMEOUT_SECONDS,
            DOH_TIMEOUT_SECONDS,
            DOT_TIMEOUT_SECONDS,
            BENCHMARK_PROBE_TIMEOUT_SECONDS,
        ):
            self.assertGreater(timeout, 0)
        self.assertGreaterEqual(MAX_CONCURRENT_NETWORK_TASKS, 1)
        self.assertLessEqual(MAX_CONCURRENT_NETWORK_TASKS, 8)


if __name__ == "__main__":
    unittest.main()
