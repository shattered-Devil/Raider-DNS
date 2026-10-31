"""Static release guards for external process/network timeout handling."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseSafetyStaticTests(unittest.TestCase):
    def test_external_process_and_network_calls_are_bounded(self) -> None:
        violations: list[str] = []
        for path in (ROOT / "raider_dns").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                owner = func.value.id if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else ""
                keywords = {item.arg: item.value for item in node.keywords if item.arg}
                if owner == "subprocess" and name == "run":
                    if "timeout" not in keywords:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: subprocess.run missing timeout")
                    shell = keywords.get("shell")
                    if isinstance(shell, ast.Constant) and shell.value is True:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: shell=True")
                elif name == "urlopen" and "timeout" not in keywords:
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: urlopen missing timeout")
                elif owner == "socket" and name == "create_connection":
                    if len(node.args) < 2 and "timeout" not in keywords:
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: socket.create_connection missing timeout")
        self.assertEqual(violations, [], "Unbounded external calls found:\n" + "\n".join(violations))

    def test_release_version_is_consistent_across_packaging_metadata(self) -> None:
        from raider_dns import __version__

        self.assertEqual(__version__, "0.1.7")
        checks = {
            "installer/version_info.txt": "0.1.7",
            "installer/RaiderDNS.iss": 'MyAppVersion "0.1.7"',
            "installer/RaiderDNS_OneFile.iss": 'MyAppVersion "0.1.7"',
            "build_installer.bat": "RaiderDNS_Setup_0.1.7_x64.exe",
            "build_onefile_installer.bat": "RaiderDNS_Setup_0.1.7_x64.exe",
            "RELEASE_MANIFEST_0.1.7.txt": "Application version: 0.1.7",
        }
        for relative, expected in checks.items():
            with self.subTest(file=relative):
                self.assertIn(expected, (ROOT / relative).read_text(encoding="utf-8"))
        version_info = (ROOT / "installer/version_info.txt").read_text(encoding="utf-8")
        self.assertIn("filevers=(0, 1, 7, 0)", version_info)
        self.assertIn("prodvers=(0, 1, 7, 0)", version_info)

    def test_readme_onefile_build_output_matches_installer_input(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installer = (ROOT / "installer/RaiderDNS_OneFile.iss").read_text(encoding="utf-8")
        self.assertIn('--distpath "release"', readme)
        self.assertIn("release\\Raider DNS.exe", readme)
        self.assertIn('"..\\release\\Raider DNS.exe"', installer)

    def test_no_precompiled_engine_or_build_output_is_committed(self) -> None:
        forbidden_suffixes = {".exe", ".dll", ".pyd"}
        found = [str(path.relative_to(ROOT)) for path in ROOT.rglob("*")
                 if path.is_file() and path.suffix.lower() in forbidden_suffixes
                 and "tests" not in path.parts]
        self.assertEqual(found, [], "Source repository should not contain generated binaries: " + ", ".join(found))


if __name__ == "__main__":
    unittest.main()
