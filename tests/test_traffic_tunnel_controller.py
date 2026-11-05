from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from raider_dns.services import traffic_tunnel as traffic_tunnel_module
from raider_dns.services.traffic_tunnel import SingBoxTunnelController


class SingBoxBundledEngineTests(unittest.TestCase):
    def test_discovers_engine_beside_frozen_application(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "engines" / "sing-box" / "sing-box.exe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"test-placeholder-not-an-executable")
            with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(root / "Raider DNS.exe")):
                discovered = SingBoxTunnelController.discover_bundled_binary()
            self.assertEqual(discovered, binary.resolve())

    def test_ignores_unbundled_executables_and_does_not_search_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(Path(temp) / "Raider DNS.exe")):
                discovered = SingBoxTunnelController.discover_bundled_binary()
            self.assertIsNone(discovered)

    def test_frozen_build_does_not_fall_back_to_source_checkout_engine(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_root = root / "source-checkout"
            frozen_root = root / "installed-app"
            source_binary = source_root / "engines" / "sing-box" / "sing-box.exe"
            source_binary.parent.mkdir(parents=True)
            source_binary.write_bytes(b"source-tree-only-placeholder")
            frozen_root.mkdir()
            source_file = source_root / "raider_dns" / "services" / "traffic_tunnel.py"
            with (
                patch.object(sys, "frozen", True, create=True),
                patch.object(sys, "executable", str(frozen_root / "Raider DNS.exe")),
                patch.object(sys, "_MEIPASS", None, create=True),
                patch.object(traffic_tunnel_module, "__file__", str(source_file)),
            ):
                discovered = SingBoxTunnelController.discover_bundled_binary()
            self.assertIsNone(discovered)

    def test_source_checkout_discovers_engine_only_when_not_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "engines" / "sing-box" / "sing-box.exe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"test-placeholder-not-an-executable")
            source_file = root / "raider_dns" / "services" / "traffic_tunnel.py"
            with (
                patch.object(sys, "frozen", False, create=True),
                patch.object(traffic_tunnel_module, "__file__", str(source_file)),
            ):
                discovered = SingBoxTunnelController.discover_bundled_binary()
            self.assertEqual(discovered, binary.resolve())

    def test_default_profile_is_in_per_user_raider_dns_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with patch("raider_dns.services.traffic_tunnel.app_data_dir", return_value=Path(temp)):
                self.assertEqual(SingBoxTunnelController.default_config_path(), Path(temp) / "sing-box" / "config.json")

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_engine_version_query_is_timeout_bounded(self, run: Mock) -> None:
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "sing-box.exe"
            binary.write_bytes(b"placeholder")
            run.return_value = subprocess.CompletedProcess([str(binary), "version"], 0, "sing-box version 1.test\n", "")
            self.assertEqual(SingBoxTunnelController.read_version(binary), "sing-box version 1.test")
            self.assertLessEqual(run.call_args.kwargs["timeout"], 8.0)


class SingBoxStopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.controller = SingBoxTunnelController()
        self.controller.session_path = self.root / "singbox-session.json"
        self.controller.log_path = self.root / "sing-box.log"
        self.controller.binary_path = self.root / "sing-box.exe"
        self.controller.config_path = self.root / "config.json"

    def _live_process(self) -> Mock:
        process = Mock()
        process.pid = 4321
        process.poll.side_effect = [None, 0]
        process.wait.return_value = 0
        return process

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_uses_taskkill_without_force_or_process_tree(self, run: Mock) -> None:
        process = self._live_process()
        self.controller.process = process
        run.return_value = subprocess.CompletedProcess(["taskkill.exe"], 0, "SUCCESS", "")

        result = self.controller.stop(timeout=0.1)

        self.assertTrue(result.success)
        self.assertEqual(run.call_args.args[0], ["taskkill.exe", "/PID", "4321"])
        self.assertNotIn("/F", run.call_args.args[0])
        self.assertNotIn("/T", run.call_args.args[0])
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertIsNone(self.controller.process)

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_keeps_process_and_session_when_graceful_shutdown_times_out(self, run: Mock) -> None:
        process = Mock()
        process.pid = 4321
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("sing-box", 0.1)
        self.controller.process = process
        self.controller._persist_session(4321, self.controller.binary_path, self.controller.config_path)
        run.return_value = subprocess.CompletedProcess(["taskkill.exe"], 0, "SUCCESS", "")

        result = self.controller.stop(timeout=0.1)

        self.assertFalse(result.success)
        self.assertIn("graceful shutdown", result.message.casefold())
        self.assertIs(self.controller.process, process)
        self.assertTrue(self.controller.session_path.is_file())
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_already_exited_process_is_not_killed_by_a_reused_pid(self, run: Mock) -> None:
        process = Mock()
        process.pid = 4321
        process.poll.return_value = 7
        self.controller.process = process

        result = self.controller.stop()

        self.assertTrue(result.success)
        self.assertIn("already exited", result.message)
        run.assert_not_called()
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertIsNone(self.controller.process)

    def test_writes_and_reads_a_persistent_session_record(self) -> None:
        self.controller._persist_session(4321, self.controller.binary_path, self.controller.config_path)
        payload = json.loads(self.controller.session_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["pid"], 4321)
        self.assertEqual(payload["binary_path"], str(self.controller.binary_path.resolve()))
        self.assertEqual(payload["config_path"], str(self.controller.config_path.resolve()))
        self.assertEqual(self.controller._read_session()["pid"], 4321)

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_recovers_only_exact_recorded_process(self, run: Mock) -> None:
        self.controller._persist_session(4321, self.controller.binary_path, self.controller.config_path)
        self.controller._matching_process_state = Mock(side_effect=[True, True, False])
        run.return_value = subprocess.CompletedProcess(["taskkill.exe"], 0, "SUCCESS", "")

        result = self.controller.recover_previous_session(timeout=0.1)

        self.assertTrue(result.success)
        self.assertIn("stopped gracefully", result.message.casefold())
        self.assertEqual(run.call_args.args[0], ["taskkill.exe", "/PID", "4321"])
        self.assertFalse(self.controller.session_path.exists())
        self.assertIsNone(self.controller.external_pid)

    @patch("raider_dns.services.traffic_tunnel.subprocess.run")
    def test_invalid_session_record_never_stops_any_process(self, run: Mock) -> None:
        self.controller.session_path.write_text("not-json", encoding="utf-8")

        result = self.controller.recover_previous_session()

        self.assertFalse(result.success)
        self.assertIn("record is invalid", result.message.casefold())
        run.assert_not_called()
        self.assertTrue(self.controller.session_path.exists())

    def test_stale_record_is_removed_without_adapter_or_driver_cleanup(self) -> None:
        self.controller._persist_session(4321, self.controller.binary_path, self.controller.config_path)
        self.controller._matching_process_state = Mock(return_value=False)

        result = self.controller.recover_previous_session()

        self.assertTrue(result.success)
        self.assertIn("no longer running", result.message.casefold())
        self.assertIn("No adapter, route, or driver was removed", result.details)
        self.assertFalse(self.controller.session_path.exists())


    def test_unexpected_engine_exit_retains_recovery_record(self) -> None:
        process = Mock()
        process.poll.return_value = 23
        self.controller.process = process
        self.controller._persist_session(4321, self.controller.binary_path, self.controller.config_path)

        result = self.controller.check_for_unexpected_exit()

        self.assertIsNotNone(result)
        self.assertFalse(result.success)
        self.assertIn("exited unexpectedly", result.message)
        self.assertIn("exit code: 23", result.details.casefold())
        self.assertTrue(self.controller.session_path.is_file())
        self.assertIsNone(self.controller.process)
        self.assertIn("No adapter, route, or driver was removed automatically", result.details)

    def test_live_engine_is_not_reported_as_unexpected_exit(self) -> None:
        process = Mock()
        process.poll.return_value = None
        self.controller.process = process
        self.assertIsNone(self.controller.check_for_unexpected_exit())
        self.assertIs(self.controller.process, process)


    def test_start_refuses_new_tunnel_when_stale_session_requires_network_review(self) -> None:
        from raider_dns.services.traffic_tunnel import TunnelResult

        self.controller.session_path.write_text("{}", encoding="utf-8")
        self.controller.recover_previous_session = Mock(return_value=TunnelResult(
            True,
            "Previous sing-box process is no longer running",
            "No adapter, route, or driver was removed automatically; inspect network state first.",
        ))
        self.controller.validate = Mock()

        result = self.controller.start(Path("sing-box.exe"), Path("config.json"))

        self.assertFalse(result.success)
        self.assertIn("verify Windows networking", result.message)
        self.controller.validate.assert_not_called()

    def test_startup_code_uses_hidden_window_without_create_no_window_for_long_lived_tun(self) -> None:
        source = Path(__file__).resolve().parents[1] / "raider_dns" / "services" / "traffic_tunnel.py"
        text = source.read_text(encoding="utf-8")
        self.assertIn("STARTF_USESHOWWINDOW", text)
        self.assertIn("startup_info.wShowWindow = subprocess.SW_HIDE", text)
        self.assertIn("taskkill.exe", text)
        self.assertIn('["taskkill.exe", "/PID", str(pid)]', text)
        self.assertNotIn("process.terminate()", text)
        self.assertNotIn("process.kill()", text)


if __name__ == "__main__":
    unittest.main()
