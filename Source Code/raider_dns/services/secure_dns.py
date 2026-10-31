"""Browser-native secure DNS configuration (DoH).

Only Firefox, Chrome and Edge expose supported browser-level DoH configuration
paths here. This does not route non-DNS traffic and is not a general-purpose tunnel.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlparse


class SecureDnsError(RuntimeError):
    """A user-presentable error while applying or restoring browser DoH."""


class BrowserSecureDnsController:
    """Configure browser-native DoH for supported browsers only.

    This configures encrypted DNS in supported browsers only.
    """

    @classmethod
    def discover_supported_browsers(cls) -> list[str]:
        """Return existing common install paths for Firefox, Chrome and Edge."""
        if os.name != "nt":
            return []
        env = os.environ
        roots: list[Path] = []
        for key in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA"):
            value = env.get(key)
            if value:
                roots.append(Path(value))
        candidates: list[Path] = []
        for root in roots:
            candidates.extend([
                root / "Mozilla Firefox" / "firefox.exe",
                root / "Mozilla" / "Firefox" / "firefox.exe",
                root / "Google" / "Chrome" / "Application" / "chrome.exe",
                root / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            ])
        result: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            try:
                if candidate.is_file():
                    normalized = str(candidate.resolve())
                    key = normalized.casefold()
                    if key not in seen and cls.browser_kind(normalized):
                        seen.add(key)
                        result.append(normalized)
            except OSError:
                continue
        return result
    @staticmethod
    def resolve_scope_targets(browsers: list[str], selected: list[str], mode: str) -> list[str]:
        """Resolve inclusive/exclusive browser scope without touching the system.

        Inclusive: only checked browser paths are targeted. Exclusive: all known
        supported browser paths except checked paths are targeted.
        """
        if mode not in {"inclusive", "exclusive"}:
            raise ValueError("DNS scope mode must be inclusive or exclusive.")
        selected_keys = {str(path).casefold() for path in selected}
        unique: list[str] = []
        seen: set[str] = set()
        for path in browsers:
            value = str(path).strip()
            key = value.casefold()
            if not value or key in seen:
                continue
            seen.add(key)
            is_selected = key in selected_keys
            if (mode == "inclusive" and is_selected) or (mode == "exclusive" and not is_selected):
                unique.append(value)
        return unique

    FIREFOX_MARKER_BEGIN = "// Raider DNS per-app DNS BEGIN"
    FIREFOX_MARKER_END = "// Raider DNS per-app DNS END"

    @staticmethod
    def browser_kind(app_path: str) -> str | None:
        name = PureWindowsPath(str(app_path).replace("/", "\\")).name.casefold()
        if name == "firefox.exe":
            return "firefox"
        if name == "chrome.exe":
            return "chrome"
        if name == "msedge.exe":
            return "edge"
        return None

    @staticmethod
    def validate_doh_url(doh_url: str) -> str:
        parsed = urlparse((doh_url or "").strip())
        if parsed.scheme.casefold() != "https" or not parsed.netloc:
            raise SecureDnsError("Browser DoH requires a valid HTTPS endpoint on the selected provider.")
        return (doh_url or "").strip()

    @staticmethod
    def _is_windows() -> bool:
        return os.name == "nt"

    @staticmethod
    def _firefox_default_profile() -> Path:
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise SecureDnsError("Could not locate the current Windows user profile for Firefox.")
        ini_path = Path(appdata) / "Mozilla" / "Firefox" / "profiles.ini"
        if not ini_path.is_file():
            raise SecureDnsError("Firefox profiles.ini was not found. Start Firefox once, create a profile, then retry.")
        import configparser
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(ini_path, encoding="utf-8")
        except (OSError, configparser.Error) as exc:
            raise SecureDnsError(f"Could not read Firefox profiles.ini: {exc}") from exc
        profiles: list[tuple[bool, Path]] = []
        for section in parser.sections():
            if not section.casefold().startswith("profile"):
                continue
            profile_path = parser.get(section, "Path", fallback="").strip()
            if not profile_path:
                continue
            is_relative = parser.get(section, "IsRelative", fallback="1") == "1"
            path = (ini_path.parent / profile_path) if is_relative else Path(profile_path)
            if path.is_dir():
                profiles.append((parser.get(section, "Default", fallback="0") == "1", path))
        if not profiles:
            raise SecureDnsError("No existing Firefox profile directory was found.")
        defaults = [path for is_default, path in profiles if is_default]
        if defaults:
            return defaults[0]
        if len(profiles) == 1:
            return profiles[0][1]
        raise SecureDnsError("Firefox has multiple profiles but no default profile is marked. Set one as default in Firefox Profile Manager, then retry.")

    @classmethod
    def apply(
        cls,
        app_path: str,
        doh_url: str,
        bootstrap_ip: str,
        existing_state: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str]:
        kind = cls.browser_kind(app_path)
        if kind is None:
            raise SecureDnsError("Browser DoH configuration currently supports Firefox, Google Chrome, and Microsoft Edge only. This executable does not expose a supported native DoH setting.")
        endpoint = cls.validate_doh_url(doh_url)
        try:
            ipaddress.ip_address(bootstrap_ip)
        except ValueError as exc:
            raise SecureDnsError("The provider's bootstrap IP address is invalid.") from exc
        if not cls._is_windows():
            raise SecureDnsError("Browser DNS configuration is supported only on Windows.")
        state = dict(existing_state or {})
        if kind == "firefox":
            profile_dir = cls._firefox_default_profile()
            user_js = profile_dir / "user.js"
            try:
                saved_path_matches = Path(str(state.get("user_js_path", ""))).resolve() == user_js.resolve()
            except (OSError, RuntimeError):
                saved_path_matches = False
            if state.get("kind") != "firefox" or not saved_path_matches:
                state = {}
            old_text = user_js.read_text(encoding="utf-8", errors="replace") if user_js.is_file() else ""
            created_file = not user_js.exists() and not state.get("created_file", False)
            clean = cls._remove_firefox_block(old_text)
            block = "\n".join([
                cls.FIREFOX_MARKER_BEGIN,
                'user_pref("network.trr.mode", 3);',
                f'user_pref("network.trr.uri", {json.dumps(endpoint)});',
                f'user_pref("network.trr.bootstrapAddress", {json.dumps(bootstrap_ip)});',
                cls.FIREFOX_MARKER_END,
            ])
            user_js.parent.mkdir(parents=True, exist_ok=True)
            user_js.write_text((clean.rstrip() + "\n\n" if clean.strip() else "") + block + "\n", encoding="utf-8", newline="\n")
            state.update({"kind": "firefox", "user_js_path": str(user_js), "created_file": bool(state.get("created_file", created_file))})
            return state, f"Firefox DoH enabled in the default profile ({profile_dir.name}); DNS-only mode applies to Firefox, not other applications. Restart Firefox to ensure the preference is active."

        import winreg  # Windows-only, intentionally imported after the platform check.
        key_path = r"Software\Policies\Google\Chrome" if kind == "chrome" else r"Software\Policies\Microsoft\Edge"
        template = endpoint if "{?dns}" in endpoint else endpoint.rstrip("/") + "{?dns}"
        values = {"DnsOverHttpsMode": "secure", "DnsOverHttpsTemplates": template}
        if state.get("kind") != kind or state.get("registry_key") != key_path:
            state = {}
        if not state.get("kind"):
            original: dict[str, Any] = {}
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_QUERY_VALUE) as key:
                    for value_name in values:
                        try:
                            value, value_type = winreg.QueryValueEx(key, value_name)
                            original[value_name] = {"exists": True, "value": value, "type": int(value_type)}
                        except FileNotFoundError:
                            original[value_name] = {"exists": False}
            except FileNotFoundError:
                original = {name: {"exists": False} for name in values}
            state = {"kind": kind, "registry_key": key_path, "original": original}
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            for value_name, value in values.items():
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)
        state["last_applied"] = values
        label = "Google Chrome" if kind == "chrome" else "Microsoft Edge"
        return state, f"Secure DNS policy set for {label} only (HKCU policy). Restart the browser; this policy applies to that browser installation/profile scope, not a single browser tab."

    @classmethod
    def restore(cls, state: dict[str, Any]) -> str:
        if not cls._is_windows():
            raise SecureDnsError("Browser DNS restoration is supported only on Windows.")
        kind = state.get("kind")
        if kind == "firefox":
            path = Path(str(state.get("user_js_path", "")))
            if not cls._is_registered_firefox_user_js(path):
                raise SecureDnsError("The saved Firefox path does not match a profile listed in the current user's profiles.ini; no file changes were made.")
            if not path.is_file():
                return "Firefox user.js no longer exists; no file changes were made."
            current = path.read_text(encoding="utf-8", errors="replace")
            restored = cls._remove_firefox_block(current)
            if restored == current:
                return "The managed Firefox DNS block was not present; the file was left unchanged."
            if not restored.strip() and state.get("created_file"):
                path.unlink(missing_ok=True)
            else:
                path.write_text(restored.rstrip() + ("\n" if restored.strip() else ""), encoding="utf-8", newline="\n")
            return "Removed Raider DNS managed Firefox DoH preferences. Restart Firefox; preferences that existed before Raider DNS were preserved."

        if kind not in {"chrome", "edge"}:
            raise SecureDnsError("No valid browser-DNS backup was found.")
        import winreg
        key_path = str(state.get("registry_key", ""))
        expected_key = r"Software\Policies\Google\Chrome" if kind == "chrome" else r"Software\Policies\Microsoft\Edge"
        original = state.get("original", {})
        last_applied = state.get("last_applied", {})
        allowed_values = {"DnsOverHttpsMode", "DnsOverHttpsTemplates"}
        if key_path != expected_key or not isinstance(original, dict) or not isinstance(last_applied, dict):
            raise SecureDnsError("The saved browser DNS restore data is invalid or does not match the selected browser.")
        if not set(last_applied).issubset(allowed_values) or not set(original).issubset(allowed_values):
            raise SecureDnsError("The saved browser DNS restore data contains unsupported registry values.")
        restored_count = 0
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            return "The browser policy key no longer exists; there was nothing to restore."
        with key:
            for value_name, applied_value in last_applied.items():
                try:
                    current, current_type = winreg.QueryValueEx(key, value_name)
                except FileNotFoundError:
                    continue
                # If another tool/user changed the policy after Raider DNS, don't overwrite it.
                if current != applied_value:
                    continue
                previous = original.get(value_name, {"exists": False})
                if previous.get("exists"):
                    winreg.SetValueEx(key, value_name, 0, int(previous.get("type", winreg.REG_SZ)), previous.get("value", ""))
                else:
                    try:
                        winreg.DeleteValue(key, value_name)
                    except FileNotFoundError:
                        pass
                restored_count += 1
        return f"Restored {restored_count} browser DNS policy value(s). Values changed by another tool were left untouched. Restart the browser to apply the change."

    @classmethod
    def _is_registered_firefox_user_js(cls, path: Path) -> bool:
        """Only permit restoring a user.js file attached to a profile in profiles.ini."""
        appdata = os.environ.get("APPDATA")
        if not appdata or path.name.casefold() != "user.js":
            return False
        ini_path = Path(appdata) / "Mozilla" / "Firefox" / "profiles.ini"
        if not ini_path.is_file():
            return False
        import configparser
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(ini_path, encoding="utf-8")
            target = path.resolve()
            for section in parser.sections():
                if not section.casefold().startswith("profile"):
                    continue
                profile_path = parser.get(section, "Path", fallback="").strip()
                if not profile_path:
                    continue
                is_relative = parser.get(section, "IsRelative", fallback="1") == "1"
                candidate = (ini_path.parent / profile_path) if is_relative else Path(profile_path)
                if candidate.is_dir() and (candidate / "user.js").resolve() == target:
                    return True
        except (OSError, ValueError, configparser.Error):
            return False
        return False

    @classmethod
    def _remove_firefox_block(cls, text: str) -> str:
        begin = re.escape(cls.FIREFOX_MARKER_BEGIN)
        end = re.escape(cls.FIREFOX_MARKER_END)
        pattern = rf"(?ms)^\s*{begin}\s*\n.*?^\s*{end}\s*(?:\n|$)"
        return re.sub(pattern, "", text)
