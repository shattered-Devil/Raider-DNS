"""SSID/adapter-bound network profiles with explicit, opt-in application."""
from __future__ import annotations

import json
import os
import re
import subprocess
from ipaddress import ip_address
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from raider_dns.storage import app_data_dir


def read_current_ssid(timeout: float = 3.0) -> str:
    """Read only the currently connected WLAN SSID (no adapter/driver inventory).

    This intentionally avoids CIM, PnP, driver-version and full interface queries.
    It is used only for exact opt-in network-profile matching.
    """
    if os.name != "nt":
        return ""
    try:
        result = subprocess.run(
            ["netsh.exe", "wlan", "show", "interfaces"],
            shell=False, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=max(1.0, min(float(timeout), 5.0)),
            check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return ""
    if result.returncode != 0:
        return ""

    blocks = re.split(r"(?im)^\s*(?:Name|Interface Name)\s*:", result.stdout or "")
    for block in blocks:
        state_match = re.search(r"(?im)^\s*(?:State|Status)\s*:\s*(.+?)\s*$", block)
        if not state_match or state_match.group(1).strip().casefold() not in {"connected", "verbunden", "connecté", "conectado"}:
            continue
        ssid_match = re.search(r"(?im)^\s*SSID\s*:\s*(.*?)\s*$", block)
        if ssid_match:
            ssid = ssid_match.group(1).strip()
            if ssid and ssid.casefold() not in {"n/a", "not applicable"}:
                return ssid[:128]
    # Some Windows builds omit the interface header; still accept a single
    # SSID only when a connected state is explicitly present in the output.
    if re.search(r"(?im)^\s*(?:State|Status)\s*:\s*(?:connected|verbunden|connecté|conectado)\s*$", result.stdout or ""):
        match = re.search(r"(?im)^\s*SSID\s*:\s*(.*?)\s*$", result.stdout or "")
        if match and match.group(1).strip():
            return match.group(1).strip()[:128]
    return ""


def _valid_ip_address(value: str) -> bool:
    raw = str(value or "").strip()
    # Preserve a valid IPv6 zone identifier while validating the address itself.
    address, separator, zone = raw.partition("%")
    try:
        parsed = ip_address(address)
        if separator and (parsed.version != 6 or not zone or any(ch.isspace() for ch in zone)):
            return False
        return bool(raw) and not any(ch.isspace() for ch in raw)
    except ValueError:
        return False


class NetworkProfileStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else app_data_dir() / "network-profiles.json"
        self._lock = threading.RLock()

    @staticmethod
    def normalize_ssid(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip()).casefold()

    @staticmethod
    def validate_profile(raw: Any) -> dict[str, Any] | None:
        if not isinstance(raw, dict):
            return None
        name = str(raw.get("name", "")).strip()[:80]
        ssid = str(raw.get("ssid", "")).strip()[:128]
        adapter = str(raw.get("adapter_name", "")).strip()[:120]
        provider_id = str(raw.get("provider_id", "")).strip()[:100]
        servers = raw.get("servers", [])
        if not name or not (ssid or adapter) or not provider_id or not isinstance(servers, list) or not servers or len(servers) > 4:
            return None
        if not all(isinstance(item, str) and _valid_ip_address(item) for item in servers):
            return None
        mode = str(raw.get("dns_mode", "standard"))
        if mode not in {"standard", "doh", "dot", "dnscrypt"}:
            return None
        return {
            "id": str(raw.get("id") or uuid.uuid4())[:100],
            "name": name,
            "ssid": ssid,
            "adapter_name": adapter,
            "provider_id": provider_id,
            "servers": [str(item) for item in servers],
            "dns_mode": mode,
            "enabled": bool(raw.get("enabled", True)),
            "auto_apply": bool(raw.get("auto_apply", False)),
            "created_at": str(raw.get("created_at", ""))[:40],
        }

    def load(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                rows = raw.get("profiles", []) if isinstance(raw, dict) else []
                result: list[dict[str, Any]] = []
                seen: set[str] = set()
                for item in rows if isinstance(rows, list) else []:
                    profile = self.validate_profile(item)
                    if profile and profile["id"] not in seen:
                        seen.add(profile["id"])
                        result.append(profile)
                return result[:100]
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                return []

    def save(self, profiles: list[dict[str, Any]]) -> None:
        clean: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in profiles[:100]:
            profile = self.validate_profile(row)
            if profile and profile["id"] not in seen:
                seen.add(profile["id"])
                clean.append(profile)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix="network-profiles-", suffix=".tmp", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump({"schema_version": self.SCHEMA_VERSION, "profiles": clean}, stream, indent=2, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise

    @classmethod
    def find_match(cls, profiles: list[dict[str, Any]], ssid: str, adapter_name: str = "") -> dict[str, Any] | None:
        target_ssid = cls.normalize_ssid(ssid)
        target_adapter = str(adapter_name or "").strip().casefold()
        matches = []
        for profile in profiles:
            clean = cls.validate_profile(profile)
            if not clean or not clean["enabled"]:
                continue
            expected_ssid = cls.normalize_ssid(clean["ssid"])
            expected_adapter = clean["adapter_name"].casefold()
            if expected_ssid:
                if not target_ssid or expected_ssid != target_ssid:
                    continue
            elif not expected_adapter or not target_adapter or expected_adapter != target_adapter:
                continue
            if expected_adapter and (not target_adapter or expected_adapter != target_adapter):
                continue
            matches.append(clean)
        # Prefer an exact adapter binding, then the first configured SSID match.
        matches.sort(key=lambda item: 0 if item["adapter_name"] and item["adapter_name"].casefold() == target_adapter else 1)
        return matches[0] if matches else None
