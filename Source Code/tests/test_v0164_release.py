from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController


class Release0164RegressionPackagingTests(unittest.TestCase):
    def test_finds_engine_next_to_application_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            exe = base / "engines" / "dnscrypt-proxy" / "dnscrypt-proxy.exe"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"test-placeholder-not-an-executable")
            with patch("raider_dns.services.dnscrypt_proxy.sys.executable", str(base / "Raider DNS.exe")):
                discovered = DNSCryptProxyController.discover_bundled_binary()
            self.assertEqual(discovered, exe.resolve())

    def test_returns_none_when_no_bundled_engine_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            # The executable path is deterministic; project-root fallback is still
            # checked but the normal repository has no engine binary in source ZIP.
            with patch("raider_dns.services.dnscrypt_proxy.sys.executable", str(Path(temp) / "Raider DNS.exe")):
                result = DNSCryptProxyController.discover_bundled_binary()
            self.assertIsNone(result)

    def test_release_version_is_017(self) -> None:
        from raider_dns import __version__
        self.assertEqual(__version__, "0.1.7")

    def test_installer_selects_dnscrypt_by_default_but_keeps_it_optional(self) -> None:
        script = Path(__file__).resolve().parents[1] / "installer" / "RaiderDNS.iss"
        source = script.read_text(encoding="utf-8")
        self.assertIn('Name: "dnscrypt";', source)
        self.assertIn('Types: full custom', source)
        self.assertIn("WizardSelectComponents('app,dnscrypt')", source)
        self.assertIn('Components: dnscrypt', source)
        self.assertIn("Flags: fixed", source)  # core application cannot be deselected
        self.assertIn("CloseApplications=yes", source)
        self.assertIn("function InitializeUninstall(): Boolean;", source)
        self.assertIn("The uninstaller does not change your Windows adapter DNS settings.", source)


    def test_onefile_installer_packages_exe_not_onedir_directory_and_legal_notices(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "installer" / "RaiderDNS_OneFile.iss").read_text(encoding="utf-8")
        self.assertIn('Source: "..\\release\\Raider DNS.exe"', source)
        self.assertIn("COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt", source)
        self.assertIn("THIRD_PARTY_NOTICES.md", source)
        self.assertIn("LICENSE_STATUS.md", source)
        self.assertIn('Components: dnscrypt', source)
        self.assertIn("WizardSelectComponents('app,dnscrypt')", source)

    def test_engine_download_is_pinned_to_upstream_and_hash_checked(self) -> None:
        script = Path(__file__).resolve().parents[1] / "installer" / "prepare_dnscrypt_proxy.ps1"
        source = script.read_text(encoding="utf-8")
        self.assertIn('https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/$Version/$ArchiveName', source)
        self.assertIn("9E498CB9BDBAE57756DB19CE516362AC307E9340A6996214964CFCC7C489ABC3", source)
        self.assertIn("Get-FileHash", source)
        self.assertIn("$Version = '2.1.20'", source)
        self.assertIn("-TimeoutSec 120", source)
        self.assertIn("-TimeoutSec 30", source)


if __name__ == "__main__":
    unittest.main()
