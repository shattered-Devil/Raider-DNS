"""Static release guards for external process/network timeout handling."""
from __future__ import annotations

import ast
from pathlib import Path
import shutil
import subprocess
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

        self.assertEqual(__version__, "0.2.0-beta")
        checks = {
            "installer/version_info.txt": "0.2.0-beta",
            "installer/RaiderDNS.iss": 'MyAppVersion "0.2.0-beta"',
            "installer/RaiderDNS_OneFile.iss": 'MyAppVersion "0.2.0-beta"',
            "build_installer.bat": "RaiderDNS_Setup_0.2_beta_x64.exe",
            "build_onefile_installer.bat": "RaiderDNS_Setup_0.2_beta_x64.exe",
            "RELEASE_MANIFEST_0.2_beta.txt": "Application version: 0.2.0-beta",
        }
        for relative, expected in checks.items():
            with self.subTest(file=relative):
                self.assertIn(expected, (ROOT / relative).read_text(encoding="utf-8"))
        version_info = (ROOT / "installer/version_info.txt").read_text(encoding="utf-8")
        self.assertIn("filevers=(0, 2, 0, 0)", version_info)
        self.assertIn("prodvers=(0, 2, 0, 0)", version_info)

    def test_readme_onefile_build_output_matches_installer_input(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installer = (ROOT / "installer/RaiderDNS_OneFile.iss").read_text(encoding="utf-8")
        self.assertIn('--distpath "release"', readme)
        self.assertIn("release\\Raider DNS.exe", readme)
        self.assertIn('"..\\release\\Raider DNS.exe"', installer)

    def test_generated_binary_staging_locations_are_gitignored(self) -> None:
        """Keep local installer inputs/build products out of Git history."""
        ignore_text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        required_patterns = (
            "build/",
            "dist/",
            "release/",
            "installer/downloads/",
            "installer/payload/",
            "engines/sing-box/*.exe",
            "engines/sing-box/*.dll",
            "engines/sing-box/*.sys",
            "engines/sing-box/*.pdb",
        )
        missing = [pattern for pattern in required_patterns if pattern not in ignore_text]
        self.assertEqual(missing, [], "Generated/staged binaries must be Git-ignored: " + ", ".join(missing))

        # If this checkout is inside a Git repository, verify that no compiled
        # binary is actually tracked. This catches files previously force-added
        # before the ignore rules were introduced.
        git_exe = shutil.which("git")
        if git_exe:
            result = subprocess.run(
                [git_exe, "ls-files", "-z"],
                cwd=ROOT,
                capture_output=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                tracked = [
                    item.decode("utf-8", errors="replace")
                    for item in result.stdout.split(b"\0") if item
                ]
                tracked_binaries = [
                    item for item in tracked
                    if Path(item).suffix.lower() in {".exe", ".dll", ".pyd", ".sys", ".pdb"}
                ]
                self.assertEqual(
                    tracked_binaries,
                    [],
                    "Compiled binaries must not be tracked by Git: " + ", ".join(tracked_binaries),
                )

    def test_no_precompiled_engine_or_build_output_is_committed(self) -> None:
        """Reject binaries in source while allowing Git-ignored local staging folders.

        The installer build deliberately creates binaries under installer/payload and
        the maintainer supplies the sing-box distribution under engines/sing-box.
        PyInstaller outputs live under build/dist/release. These are valid local
        staging locations but must remain ignored by Git (checked above).
        """
        forbidden_suffixes = {".exe", ".dll", ".pyd", ".sys", ".pdb"}
        generated_roots = (
            Path("build"),
            Path("dist"),
            Path("release"),
            Path("installer/downloads"),
            Path("installer/payload"),
            Path("engines/sing-box"),
        )
        found: list[str] = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in forbidden_suffixes:
                continue
            relative = path.relative_to(ROOT)
            if any(relative == root or root in relative.parents for root in generated_roots):
                continue
            if "tests" in relative.parts:
                continue
            found.append(str(relative))
        self.assertEqual(
            found,
            [],
            "Precompiled binaries must not be stored in application source: " + ", ".join(found),
        )


if __name__ == "__main__":
    unittest.main()
