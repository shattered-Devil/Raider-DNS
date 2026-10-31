from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock

from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController


class DNSCryptLifecycleTests(unittest.TestCase):
    def test_successful_termination_clears_process_reference(self) -> None:
        controller = DNSCryptProxyController()
        process = Mock()
        process.poll.side_effect = [None, 0]
        process.wait.return_value = 0
        controller.process = process

        result = controller.stop(timeout=0.1)

        self.assertTrue(result.success)
        process.terminate.assert_called_once_with()
        process.kill.assert_not_called()
        self.assertIsNone(controller.process)

    def test_failed_kill_timeout_retains_process_reference(self) -> None:
        controller = DNSCryptProxyController()
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("dnscrypt", 0.1), subprocess.TimeoutExpired("dnscrypt", 0.1)]
        controller.process = process

        result = controller.stop(timeout=0.1)

        self.assertFalse(result.success)
        self.assertIn("did not exit", result.message)
        process.kill.assert_called_once_with()
        self.assertIs(controller.process, process)

    def test_stop_does_not_claim_success_if_process_still_reports_live(self) -> None:
        controller = DNSCryptProxyController()
        process = Mock()
        process.poll.side_effect = [None, None]
        process.wait.return_value = None
        controller.process = process

        result = controller.stop(timeout=0.1)

        self.assertFalse(result.success)
        self.assertIn("could not be confirmed", result.message)
        self.assertIs(controller.process, process)


if __name__ == "__main__":
    unittest.main()
