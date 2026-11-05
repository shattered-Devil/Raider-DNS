from __future__ import annotations

import unittest
from pathlib import Path

from raider_dns.services.secure_dns import BrowserSecureDnsController, SecureDnsError


class BrowserSecureDnsTests(unittest.TestCase):
    def test_browser_support_is_explicit(self) -> None:
        self.assertEqual(BrowserSecureDnsController.browser_kind(r"C:\Program Files\Mozilla Firefox\firefox.exe"), "firefox")
        self.assertEqual(BrowserSecureDnsController.browser_kind(r"C:\Program Files\Google\Chrome\Application\chrome.exe"), "chrome")
        self.assertEqual(BrowserSecureDnsController.browser_kind(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"), "edge")
        self.assertIsNone(BrowserSecureDnsController.browser_kind(r"C:\Program Files\Spotify\Spotify.exe"))

    def test_scope_inclusive_includes_only_selected(self) -> None:
        browsers = [r"C:\Firefox\firefox.exe", r"C:\Chrome\chrome.exe", r"C:\Edge\msedge.exe"]
        selected = [browsers[0], browsers[2]]
        self.assertEqual(BrowserSecureDnsController.resolve_scope_targets(browsers, selected, "inclusive"), [browsers[0], browsers[2]])

    def test_scope_exclusive_excludes_selected(self) -> None:
        browsers = [r"C:\Firefox\firefox.exe", r"C:\Chrome\chrome.exe", r"C:\Edge\msedge.exe"]
        selected = [browsers[0]]
        self.assertEqual(BrowserSecureDnsController.resolve_scope_targets(browsers, selected, "exclusive"), [browsers[1], browsers[2]])

    def test_scope_deduplicates_case_insensitively(self) -> None:
        browsers = [r"C:\Chrome\chrome.exe", r"c:\chrome\CHROME.EXE"]
        self.assertEqual(BrowserSecureDnsController.resolve_scope_targets(browsers, [], "exclusive"), [browsers[0]])

    def test_scope_rejects_unknown_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "inclusive or exclusive"):
            BrowserSecureDnsController.resolve_scope_targets([], [], "bypass")

    def test_dns_only_rejects_non_https_endpoint(self) -> None:
        with self.assertRaisesRegex(SecureDnsError, "valid HTTPS endpoint"):
            BrowserSecureDnsController.validate_doh_url("http://resolver.example/dns-query")

    def test_dns_only_accepts_https_endpoint(self) -> None:
        self.assertEqual(
            BrowserSecureDnsController.validate_doh_url("https://resolver.example/dns-query"),
            "https://resolver.example/dns-query",
        )

    def test_non_browser_executable_is_not_supported(self) -> None:
        self.assertIsNone(BrowserSecureDnsController.browser_kind(Path(r"C:\Apps\sample.exe").as_posix()))


class LegacyIntegrationRemovalTests(unittest.TestCase):
    def test_active_source_does_not_import_old_vpn_service(self) -> None:
        root = Path(__file__).parents[1]
        sources = [root / "main.py", *list((root / "raider_dns").rglob("*.py"))]
        all_source = "\n".join(path.read_text(encoding="utf-8") for path in sources)
        self.assertNotIn("from raider_dns.services.app_connections", all_source)
        self.assertNotIn("WireSockEngine", all_source)
        self.assertNotIn("WireGuard tunnel", all_source)


if __name__ == "__main__":
    unittest.main()
