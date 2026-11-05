from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from raider_dns.services.dns_recovery import DNSRecoveryStore
from raider_dns.services.dns_system import DNSOperationResult, WindowsDNSService


def snapshot(*, ipv4_mode="automatic", ipv4_servers=None, ipv6_mode="automatic", ipv6_servers=None, doh=None, dot=None, dot_global=False):
    return {
        "adapter": "Ethernet",
        "interface_guid": "{11111111-2222-3333-4444-555555555555}",
        "families": {
            "IPv4": {"mode": ipv4_mode, "servers": list(ipv4_servers or []), "effective": list(ipv4_servers or [])},
            "IPv6": {"mode": ipv6_mode, "servers": list(ipv6_servers or []), "effective": list(ipv6_servers or [])},
        },
        "doh_supported": True,
        "doh_by_server": dict(doh or {}),
        "dot_by_server": dict(dot or {}),
        "dot_global": dot_global,
        "netsh_dump_available": True,
    }


class DNSRecoveryStoreTests(unittest.TestCase):
    def test_pending_snapshot_survives_process_restart_and_failed_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dns-recovery.json"
            store = DNSRecoveryStore(path)
            original = snapshot()
            store.begin_transaction("Ethernet", original)
            # A new store instance models a later app launch after a crash.
            reopened = DNSRecoveryStore(path)
            target = reopened.get_restore_target("Ethernet")
            self.assertIsNotNone(target)
            self.assertTrue(target[2])
            self.assertEqual(target[0]["families"]["IPv4"]["mode"], "automatic")
            reopened.finish_rollback("Ethernet", None, success=False)
            self.assertTrue(DNSRecoveryStore(path).has_previous_settings("Ethernet"))
            self.assertTrue(path.is_file())

    def test_committed_change_keeps_original_baseline_available(self):
        with tempfile.TemporaryDirectory() as temp:
            store = DNSRecoveryStore(Path(temp) / "dns-recovery.json")
            original = snapshot()
            configured = snapshot(ipv4_mode="manual", ipv4_servers=["1.1.1.1"])
            store.begin_transaction("Ethernet", original)
            store.commit_transaction("Ethernet", configured)
            self.assertTrue(store.has_previous_settings("Ethernet"))
            target, record, is_pending = store.get_restore_target("Ethernet")
            self.assertFalse(is_pending)
            self.assertEqual(target, original)
            self.assertEqual(record["active_signature"], store.signature(configured))

    def test_corrupted_recovery_file_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dns-recovery.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                DNSRecoveryStore(path).get_record("Ethernet")
            self.assertTrue(path.exists())
            self.assertTrue(path.with_name("dns-recovery.corrupt.json").exists())

    def test_registered_doh_metadata_is_part_of_signature_when_touched(self):
        before = snapshot(doh={"1.1.1.1": {"template": "https://example.test/dns-query", "auto_upgrade": True, "fallback": False}})
        after = snapshot(doh={"1.1.1.1": {"template": "https://other.test/dns-query", "auto_upgrade": True, "fallback": False}})
        self.assertNotEqual(DNSRecoveryStore.signature(before, ["1.1.1.1"]), DNSRecoveryStore.signature(after, ["1.1.1.1"]))


class DNSTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = DNSRecoveryStore(Path(self.temp.name) / "dns-recovery.json")
        self.service = WindowsDNSService(recovery_store=self.store)
        self.before = snapshot()
        self.after = snapshot(ipv4_mode="manual", ipv4_servers=["1.1.1.1"])

    def tearDown(self):
        self.temp.cleanup()

    def _base_patches(self):
        return (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_capture_adapter_snapshot", side_effect=[(self.before, ""), (self.after, "")]),
            patch.object(self.service, "_flush_cache_strict", return_value=(True, "cache flushed")),
            patch.object(self.service, "verify_dns_and_https", return_value=(True, "DNS and HTTPS verified")),
        )

    def test_persists_recovery_before_system_operation_and_commits_only_after_verification(self):
        is_windows, is_admin, adapters, capture, flush, verify = self._base_patches()
        operation_called = []
        def operation():
            operation_called.append(True)
            rec = self.store.get_record("Ethernet")
            self.assertIsInstance(rec.get("pending"), dict, "Recovery record must be durable before mutation")
            return DNSOperationResult(True, "Configured")
        with is_windows, is_admin, adapters, capture, flush, verify:
            result = self.service._run_transaction("Ethernet", operation, expected_servers=["1.1.1.1"])
        self.assertTrue(result.success, result.details)
        self.assertTrue(result.verified)
        self.assertEqual(operation_called, [True])
        record = self.store.get_record("Ethernet")
        self.assertIsNone(record.get("pending"))
        self.assertTrue(self.store.has_previous_settings("Ethernet"))

    def test_adapter_readback_mismatch_rolls_back_even_when_connectivity_is_unavailable(self):
        wrong_after = snapshot(ipv4_mode="manual", ipv4_servers=["9.9.9.9"])
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_capture_adapter_snapshot", side_effect=[(self.before, ""), (wrong_after, "")]),
            patch.object(self.service, "_flush_cache_strict", return_value=(True, "cache flushed")),
            patch.object(self.service, "_restore_snapshot", return_value=(True, "snapshot restored", self.before)) as restore,
            patch.object(self.service, "verify_dns_and_https", return_value=(False, "connectivity unavailable")),
        ):
            result = self.service._run_transaction(
                "Ethernet", lambda: DNSOperationResult(True, "Configured"), expected_servers=["1.1.1.1"]
            )
        self.assertFalse(result.success)
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        restore.assert_called_once()
        record = self.store.get_record("Ethernet")
        self.assertIsNone(record.get("pending"))
        self.assertIn("automatically restored", result.details)

    def test_unreachable_resolver_keeps_matching_dns_settings_and_recovery_point(self):
        is_windows, is_admin, adapters, capture, flush, _verify = self._base_patches()
        with (
            is_windows, is_admin, adapters, capture, flush,
            patch.object(self.service, "verify_dns_and_https", return_value=(False, "no diagnostic hostname resolved")),
            patch.object(self.service, "_restore_snapshot") as restore,
        ):
            result = self.service._run_transaction(
                "Ethernet", lambda: DNSOperationResult(True, "Configured"), expected_servers=["1.1.1.1"]
            )
        self.assertTrue(result.success, result.details)
        self.assertFalse(result.verified)
        self.assertFalse(result.rollback_attempted)
        restore.assert_not_called()
        record = self.store.get_record("Ethernet")
        self.assertIsNone(record.get("pending"))
        self.assertTrue(self.store.has_previous_settings("Ethernet"))
        self.assertIn("settings were applied and read back successfully", result.details)

    def test_cache_flush_failure_is_warning_when_adapter_dns_readback_matches(self):
        is_windows, is_admin, adapters, capture, _flush, _verify = self._base_patches()
        with (
            is_windows, is_admin, adapters, capture,
            patch.object(self.service, "_flush_cache_strict", return_value=(False, "cache service unavailable")),
            patch.object(self.service, "verify_dns_and_https", return_value=(True, "resolver responded")),
            patch.object(self.service, "_restore_snapshot") as restore,
        ):
            result = self.service._run_transaction(
                "Ethernet", lambda: DNSOperationResult(True, "Configured"), expected_servers=["1.1.1.1"]
            )
        self.assertTrue(result.success, result.details)
        self.assertFalse(result.verified)
        self.assertFalse(result.rollback_attempted)
        self.assertIn("DNS cache flush was not confirmed", result.details)
        restore.assert_not_called()

    def test_dnscrypt_loopback_requires_local_resolver_response(self):
        before = self.before
        after = snapshot(
            ipv4_mode="manual", ipv4_servers=["127.0.0.1"],
            ipv6_mode="manual", ipv6_servers=["::1"],
        )
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_capture_adapter_snapshot", side_effect=[(before, ""), (after, "")]),
            patch.object(self.service, "_flush_cache_strict", return_value=(True, "cache flushed")),
            patch.object(self.service, "_restore_snapshot", return_value=(True, "snapshot restored", before)) as restore,
        ):
            result = self.service._run_transaction(
                "Ethernet", lambda: DNSOperationResult(True, "DNSCrypt loopback configured"),
                expect_dnscrypt_loopback=True,
                connectivity_check=lambda: (False, "127.0.0.1 did not answer"),
                require_connectivity=True,
            )
        self.assertFalse(result.success)
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        restore.assert_called_once()

    def test_recovery_store_write_failure_prevents_any_dns_mutation(self):
        is_windows, is_admin, adapters, capture, flush, verify = self._base_patches()
        with (
            is_windows, is_admin, adapters, capture, flush, verify,
            patch.object(self.store, "begin_transaction", side_effect=OSError("disk unavailable")),
        ):
            operation = unittest.mock.Mock(return_value=DNSOperationResult(True, "Configured"))
            result = self.service._run_transaction("Ethernet", operation, expected_servers=["1.1.1.1"])
        self.assertFalse(result.success)
        self.assertIn("No DNS changes were made", result.details)
        operation.assert_not_called()

    def test_cross_process_mutex_failure_fails_closed_before_snapshot_or_mutation(self):
        @contextmanager
        def unavailable_mutex():
            yield False
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "_system_dns_mutex", unavailable_mutex),
            patch.object(self.service, "_capture_adapter_snapshot") as capture,
        ):
            result = self.service._run_transaction("Ethernet", lambda: DNSOperationResult(True, "Configured"), expected_servers=["1.1.1.1"])
        self.assertFalse(result.success)
        self.assertIn("lock system dns", result.message.casefold())
        capture.assert_not_called()

    def test_restore_previous_accepts_disconnected_but_still_installed_adapter(self):
        original = snapshot()
        current = snapshot(ipv4_mode="manual", ipv4_servers=["1.1.1.1"])
        self.store.begin_transaction("Ethernet", original)
        self.store.commit_transaction("Ethernet", current)
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_all_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "get_adapters", return_value=[]),
            patch.object(self.service, "_capture_adapter_snapshot", return_value=(current, "")),
            patch.object(self.service, "_restore_snapshot", return_value=(True, "restored", original)) as restore,
            patch.object(self.service, "verify_dns_and_https", return_value=(True, "connectivity verified")),
        ):
            result = self.service.restore_previous_dns_settings("Ethernet")
        self.assertTrue(result.success, result.details)
        self.assertTrue(result.verified)
        restore.assert_called_once()
        self.assertIsNone(self.store.get_record("Ethernet"))

    def test_restore_dhcp_does_not_destroy_existing_manual_restore_point(self):
        original = snapshot(ipv4_mode="manual", ipv4_servers=["192.0.2.53"])
        configured = snapshot(ipv4_mode="manual", ipv4_servers=["1.1.1.1"])
        self.store.begin_transaction("Ethernet", original)
        self.store.commit_transaction("Ethernet", configured)
        # The service's DHCP action now retains its pre-change restore point.
        self.assertTrue(self.store.has_previous_settings("Ethernet"))
        # Structural assertion avoids running a real Windows command in headless tests.
        import inspect
        source = inspect.getsource(WindowsDNSService.restore_dhcp)
        self.assertIn("clear_restore_after_commit=False", source)

    def test_registered_doh_templates_are_reported_separately(self):
        import subprocess
        payload = json.dumps({
            "supported": True,
            "entries": [{"server": "1.1.1.1", "template": "https://cloudflare-dns.com/dns-query", "auto_upgrade": True, "fallback": False}],
        })
        completed = subprocess.CompletedProcess([], 0, payload, "")
        with patch.object(self.service, "is_windows", return_value=True), patch.object(self.service, "_run_powershell", return_value=completed):
            result = self.service.get_doh_template_registrations()
        self.assertTrue(result["supported"])
        self.assertEqual(result["entries"][0]["server"], "1.1.1.1")
        self.assertTrue(result["entries"][0]["auto_upgrade"])
        self.assertFalse(result["entries"][0]["fallback"])

    def test_restore_snapshot_does_not_confirm_restore_if_cache_flush_fails(self):
        original = snapshot()
        with (
            patch.object(self.service, "_capture_adapter_snapshot", side_effect=[(original, "")]) as capture,
            patch.object(self.service, "_restore_doh_entries", return_value=(True, "DoH restored")),
            patch.object(self.service, "_restore_dot_entries", return_value=(True, "DoT restored")),
            patch.object(self.service, "_restore_adapter_addresses", return_value=(True, "DNS addresses restored")),
            patch.object(self.service, "_flush_cache_strict", return_value=(False, "cache flush failed")),
        ):
            restored, detail, verified_snapshot = self.service._restore_snapshot("Ethernet", original)
        self.assertFalse(restored)
        self.assertIsNone(verified_snapshot)
        self.assertIn("cache flush failed", detail)
        # The cache failure must prevent the final read-back from being mistaken for a complete rollback.
        capture.assert_called_once()

    def test_dot_plaintext_fallback_mismatch_forces_rollback(self):
        before = snapshot(dot_global=False)
        after = snapshot(
            ipv4_mode="manual", ipv4_servers=["1.1.1.1"], dot_global=True,
            dot={"1.1.1.1": {"doh_template": ":", "dot_host": "one.one.one.one:853", "auto_upgrade": True, "udp_fallback": True}},
        )
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_capture_adapter_snapshot", side_effect=[(before, ""), (after, "")]),
            patch.object(self.service, "_flush_cache_strict", return_value=(True, "cache flushed")),
            patch.object(self.service, "_restore_snapshot", return_value=(True, "restored previous DoT/DNS", before)) as restore,
            patch.object(self.service, "verify_dns_and_https", return_value=(False, "connectivity unavailable")),
        ):
            result = self.service._run_transaction(
                "Ethernet", lambda: DNSOperationResult(True, "DoT configured"),
                expected_servers=["1.1.1.1"], dot_servers=["1.1.1.1"], changes_dot_global=True,
            )
        self.assertFalse(result.success)
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        self.assertIn("fallback disabled", result.message.casefold())
        restore.assert_called_once()

    def test_get_all_adapters_includes_disconnected_adapters(self):
        import subprocess
        completed = subprocess.CompletedProcess([], 0, '["Ethernet", "Wi-Fi"]', "")
        with patch.object(self.service, "is_windows", return_value=True), patch.object(self.service, "_run_powershell", return_value=completed) as run:
            adapters = self.service.get_all_adapters()
        self.assertEqual(adapters, ["Ethernet", "Wi-Fi"])
        self.assertIn("Get-NetAdapter -ErrorAction Stop", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

class DNSRecoveryExceptionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = DNSRecoveryStore(Path(self.temp.name) / "dns-recovery.json")
        self.service = WindowsDNSService(recovery_store=self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_unexpected_rollback_exception_returns_failure_and_keeps_recovery_point(self):
        original = snapshot()
        self.store.begin_transaction("Ethernet", original)
        with patch.object(self.service, "_restore_snapshot", side_effect=RuntimeError("simulated restore fault")):
            result = self.service._rollback_transaction(
                "Ethernet", original, [], [], False, "post-change verification failed"
            )
        self.assertFalse(result.success)
        self.assertTrue(result.rollback_attempted)
        self.assertFalse(result.rollback_succeeded)
        self.assertIn("simulated restore fault", result.details)
        target = self.store.get_restore_target("Ethernet")
        self.assertIsNotNone(target)
        self.assertTrue(target[2], "failed rollback must retain a pending restore target")

    def test_restore_previous_handles_unexpected_restore_and_rollback_exceptions(self):
        original = snapshot()
        current = snapshot(ipv4_mode="manual", ipv4_servers=["1.1.1.1"])
        self.store.begin_transaction("Ethernet", original)
        self.store.commit_transaction("Ethernet", current)
        with (
            patch.object(self.service, "is_windows", return_value=True),
            patch.object(self.service, "is_admin", return_value=True),
            patch.object(self.service, "get_all_adapters", return_value=["Ethernet"]),
            patch.object(self.service, "_capture_adapter_snapshot", return_value=(current, "")),
            patch.object(self.service, "_restore_snapshot", side_effect=RuntimeError("simulated restore fault")),
        ):
            result = self.service.restore_previous_dns_settings("Ethernet")
        self.assertFalse(result.success)
        self.assertTrue(result.rollback_attempted)
        self.assertFalse(result.rollback_succeeded)
        self.assertIn("simulated restore fault", result.details)
        self.assertTrue(self.store.has_previous_settings("Ethernet"))

    def test_loopback_dependency_detects_manual_or_effective_loopback(self):
        self.service.is_windows = lambda: True
        self.service.get_all_adapters = lambda: ["Ethernet", "Wi-Fi"]
        self.service._capture_adapter_snapshot = lambda adapter, **kwargs: (
            snapshot(ipv6_mode="manual", ipv6_servers=["::1"]) if adapter == "Wi-Fi" else snapshot(), ""
        )
        in_use, detail = self.service.has_loopback_dns_dependency()
        self.assertIs(in_use, True)
        self.assertIn("Wi-Fi", detail)

    def test_loopback_dependency_returns_false_only_after_all_adapters_are_inspected(self):
        self.service.is_windows = lambda: True
        self.service.get_all_adapters = lambda: ["Ethernet", "Wi-Fi"]
        self.service._capture_adapter_snapshot = lambda adapter, **kwargs: (snapshot(), "")
        in_use, _ = self.service.has_loopback_dns_dependency()
        self.assertIs(in_use, False)

    def test_loopback_dependency_is_unknown_when_an_adapter_cannot_be_inspected(self):
        self.service.is_windows = lambda: True
        self.service.get_all_adapters = lambda: ["Ethernet", "Wi-Fi"]
        self.service._capture_adapter_snapshot = lambda adapter, **kwargs: (None, "adapter vanished") if adapter == "Wi-Fi" else (snapshot(), "")
        in_use, detail = self.service.has_loopback_dns_dependency()
        self.assertIsNone(in_use)
        self.assertIn("adapter vanished", detail)
