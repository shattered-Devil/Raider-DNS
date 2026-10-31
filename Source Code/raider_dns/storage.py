"""Atomic JSON settings storage with defensive recovery."""
from __future__ import annotations

import json
import os
import queue
import threading
import shutil
import tempfile
import uuid
import re
from ipaddress import ip_address
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

APP_NAME = "RaiderDNS"


def _valid_web_url(value: Any, schemes: set[str]) -> bool:
    """Return False rather than raising on malformed/untrusted imported URLs."""
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme.casefold() in schemes and bool(parsed.hostname)
    except (ValueError, TypeError):
        return False


def default_settings() -> dict[str, Any]:
    return {
        "schema_version": 6,
        "theme": "dark",
        "minimize_to_tray": True,
        "close_to_tray": False,
        "activity_log_limit": 1000,
        "selected_provider": "cloudflare",
        "selected_adapter": "",
        "dns_mode": "standard",
        "favorites": ["cloudflare", "quad9", "adguard"],
        "provider_order": ["cloudflare", "google", "quad9", "adguard", "cleanbrowsing", "opendns", "comodo", "shecan"],
        "custom_providers": [],
        "provider_overrides": {},
        "disabled_builtin_providers": [],
        "profiles": [],
        "connection_dns_provider": "cloudflare",
        "connection_dns_method": "standard",
        "dnscrypt_proxy_path": "",
        "dnscrypt_config_path": "",
        "singbox_path": "",
        "singbox_config_path": "",
        "dns_scope_mode": "inclusive",
        "dns_scope_browsers": [],
        "dns_scope_targets": [],
        "browser_dns_restore": {},
        "flush_dns_after_apply": True,
        "confirm_dns_changes": True,
        "failover_enabled": False,
        "fallback_provider": "quad9",
        "window_width": 1320,
        "window_height": 860,
        "window_maximized": False,
        # App notification and DNS health monitor preferences.
        "notifications_enabled": True,
        "health_monitor_enabled": False,
        "health_interval_seconds": 30,
        "health_timeout_seconds": 2.5,
        "health_failure_threshold": 3,
        "health_recovery_threshold": 2,
        "network_poll_interval_seconds": 20,
        "tooltip_delay_ms": 750,
        "benchmark_rounds": 3,
    }


def app_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME
    return Path.home() / ".config" / "raider-dns"


class ConfigStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (app_data_dir() / "settings.json")

    def load(self) -> dict[str, Any]:
        defaults = default_settings()
        if not self.path.exists():
            return defaults
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("Settings root must be a JSON object")
            merged = defaults | loaded
            merged["schema_version"] = defaults["schema_version"]
            builtin_provider_ids = {"cloudflare", "google", "quad9", "adguard", "cleanbrowsing", "opendns", "comodo", "shecan"}
            # Custom provider objects are normalized here before their IDs can be
            # referenced by favorites, profiles, selections, or provider ordering.
            custom_providers: list[dict[str, Any]] = []
            seen_custom_ids: set[str] = set()
            raw_custom = merged.get("custom_providers", [])
            if isinstance(raw_custom, list):
                for item in raw_custom[:100]:
                    if not isinstance(item, dict):
                        continue
                    provider_id = item.get("id")
                    name = item.get("name")
                    primary = item.get("primary")
                    secondary = item.get("secondary", "")
                    description = item.get("description", "Custom DNS provider")
                    category = item.get("category", "Custom")
                    if not isinstance(provider_id, str) or not re.fullmatch(r"custom-[a-z0-9_-]{1,64}", provider_id):
                        continue
                    if provider_id in builtin_provider_ids or provider_id in seen_custom_ids:
                        continue
                    if not isinstance(name, str) or not name.strip() or len(name) > 80:
                        continue
                    if not isinstance(primary, str) or not isinstance(secondary, str):
                        continue
                    try:
                        if ip_address(primary).version != 4:
                            continue
                        if secondary and ip_address(secondary).version != 4:
                            continue
                    except ValueError:
                        continue
                    if not isinstance(description, str):
                        description = "Custom DNS provider"
                    if not isinstance(category, str):
                        category = "Custom"
                    doh_url = item.get("doh_url")
                    if not _valid_web_url(doh_url, {"https"}):
                        doh_url = None
                    elif isinstance(doh_url, str):
                        doh_url = doh_url.strip()
                    dot_hostname = item.get("dot_hostname")
                    if not isinstance(dot_hostname, str) or not dot_hostname.strip():
                        dot_hostname = None
                    website = item.get("website")
                    if not _valid_web_url(website, {"http", "https"}):
                        website = ""
                    elif isinstance(website, str):
                        website = website.strip()
                    custom_providers.append({
                        "id": provider_id,
                        "name": name.strip(),
                        "description": description.strip()[:240],
                        "primary": primary.strip(),
                        "secondary": secondary.strip(),
                        "category": category.strip()[:60] or "Custom",
                        "doh_url": doh_url,
                        "dot_hostname": dot_hostname.strip() if dot_hostname else None,
                        "website": website,
                    })
                    seen_custom_ids.add(provider_id)
            merged["custom_providers"] = custom_providers
            raw_disabled = merged.get("disabled_builtin_providers", [])
            disabled_builtin = list(dict.fromkeys(
                item for item in raw_disabled
                if isinstance(raw_disabled, list) and isinstance(item, str) and item in builtin_provider_ids
            )) if isinstance(raw_disabled, list) else []
            merged["disabled_builtin_providers"] = disabled_builtin
            raw_overrides = merged.get("provider_overrides", {})
            provider_overrides: dict[str, dict[str, Any]] = {}
            if isinstance(raw_overrides, dict):
                for provider_id, item in raw_overrides.items():
                    if provider_id not in builtin_provider_ids or not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    primary = item.get("primary")
                    secondary = item.get("secondary", "")
                    if not isinstance(name, str) or not name.strip() or len(name) > 80:
                        continue
                    if not isinstance(primary, str) or not isinstance(secondary, str):
                        continue
                    try:
                        if ip_address(primary).version != 4 or (secondary and ip_address(secondary).version != 4):
                            continue
                    except ValueError:
                        continue
                    doh_url = item.get("doh_url")
                    if not _valid_web_url(doh_url, {"https"}):
                        doh_url = None
                    else:
                        doh_url = doh_url.strip()
                    website = item.get("website")
                    if not _valid_web_url(website, {"http", "https"}):
                        website = ""
                    else:
                        website = website.strip()
                    dot = item.get("dot_hostname")
                    if not isinstance(dot, str) or not dot.strip() or len(dot) > 253 or any(ch.isspace() or ch in "/\\?#@[]" for ch in dot):
                        dot = None
                    provider_overrides[provider_id] = {
                        "id": provider_id,
                        "name": name.strip(),
                        "description": str(item.get("description", ""))[:240],
                        "primary": primary.strip(),
                        "secondary": secondary.strip(),
                        "category": str(item.get("category", "General"))[:60] or "General",
                        "doh_url": doh_url,
                        "dot_hostname": dot.strip() if dot else None,
                        "website": website,
                    }
            merged["provider_overrides"] = provider_overrides
            provider_ids = (builtin_provider_ids - set(disabled_builtin)) | seen_custom_ids
            if not provider_ids:
                # A malformed/imported settings file must not erase the entire catalogue.
                disabled_builtin = []
                merged["disabled_builtin_providers"] = []
                provider_ids = set(builtin_provider_ids)
            if merged.get("theme") not in {"dark", "light", "midnight", "ocean", "high_contrast"}:
                merged["theme"] = defaults["theme"]
            for key in ("minimize_to_tray", "close_to_tray"):
                if not isinstance(merged.get(key), bool):
                    merged[key] = defaults[key]
            try:
                merged["activity_log_limit"] = max(100, min(5000, int(merged.get("activity_log_limit", 1000))))
            except (ValueError, TypeError, OverflowError):
                merged["activity_log_limit"] = 1000
            available_builtin_order = [item for item in defaults["provider_order"] if item in provider_ids]
            fallback_default = "quad9" if "quad9" in provider_ids else (available_builtin_order[0] if available_builtin_order else next(iter(seen_custom_ids), ""))
            selected_default = "cloudflare" if "cloudflare" in provider_ids else fallback_default
            if merged.get("selected_provider") not in provider_ids:
                merged["selected_provider"] = selected_default
            if merged.get("fallback_provider") not in provider_ids:
                merged["fallback_provider"] = fallback_default
            if merged.get("dns_mode") not in {"standard", "doh", "dot", "dnscrypt"}:
                merged["dns_mode"] = defaults["dns_mode"]
            merged["favorites"] = list(dict.fromkeys(item for item in merged.get("favorites", []) if isinstance(item, str) and item in provider_ids)) if isinstance(merged.get("favorites"), list) else defaults["favorites"]
            default_order = [item for item in defaults["provider_order"] if item in provider_ids] + [item["id"] for item in custom_providers]
            supplied_order = merged.get("provider_order", [])
            if isinstance(supplied_order, list):
                saved_order = list(dict.fromkeys(item for item in supplied_order if isinstance(item, str) and item in provider_ids))
            else:
                saved_order = []
            merged["provider_order"] = saved_order + [item for item in default_order if item not in saved_order]
            merged["selected_adapter"] = merged.get("selected_adapter") if isinstance(merged.get("selected_adapter"), str) else ""
            if merged.get("connection_dns_provider") not in provider_ids:
                merged["connection_dns_provider"] = selected_default
            if merged.get("connection_dns_method") not in {"standard", "windows_doh", "browser_doh", "dot", "dnscrypt"}:
                merged["connection_dns_method"] = "standard"
            if merged.get("dns_scope_mode") not in {"inclusive", "exclusive"}:
                merged["dns_scope_mode"] = "inclusive"
            # Migrate stored browser-DNS restore snapshots from the previous settings schema.
            raw_restore = merged.get("browser_dns_restore", merged.get("app_dns_restore", {}))
            if not isinstance(raw_restore, dict):
                merged["browser_dns_restore"] = {}
            else:
                merged["browser_dns_restore"] = {str(key)[:1024]: value for key, value in raw_restore.items() if isinstance(key, str) and isinstance(value, dict)}
            # Legacy connection-scope values may contain arbitrary executable paths.
            # Keep only supported browser executable paths during one-time migration.
            def supported_browser_path(value: Any) -> bool:
                if not isinstance(value, str) or not value.strip():
                    return False
                name = value.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
                return name in {"firefox.exe", "chrome.exe", "msedge.exe"}
            old_browser_paths = merged.get("dns_scope_browsers", [])
            if not old_browser_paths:
                old_browser_paths = merged.get("connection_apps", [])
            clean_browsers = list(dict.fromkeys(value.strip()[:1024] for value in old_browser_paths if supported_browser_path(value))) if isinstance(old_browser_paths, list) else []
            merged["dns_scope_browsers"] = clean_browsers[:30]
            raw_targets = merged.get("dns_scope_targets", [])
            merged["dns_scope_targets"] = list(dict.fromkeys(value.strip()[:1024] for value in raw_targets if supported_browser_path(value)))[:30] if isinstance(raw_targets, list) else []
            # Remove obsolete connection settings after browser-DNS migration.
            for obsolete_key in ("connection_mode", "connection_apps", "connection_engine_path", "connection_profile_path", "connection_network_lock", "app_dns_restore"):
                merged.pop(obsolete_key, None)
            for key in ("flush_dns_after_apply", "confirm_dns_changes", "failover_enabled", "window_maximized", "notifications_enabled", "health_monitor_enabled"):
                if not isinstance(merged.get(key), bool):
                    merged[key] = defaults[key]
            try:
                network_interval = int(merged.get("network_poll_interval_seconds", defaults["network_poll_interval_seconds"]))
                merged["network_poll_interval_seconds"] = network_interval if network_interval in {10, 20, 30, 60} else defaults["network_poll_interval_seconds"]
            except (ValueError, TypeError, OverflowError):
                merged["network_poll_interval_seconds"] = defaults["network_poll_interval_seconds"]
            try:
                interval = int(merged.get("health_interval_seconds", defaults["health_interval_seconds"]))
                merged["health_interval_seconds"] = interval if interval in {15, 30, 60, 120, 300} else defaults["health_interval_seconds"]
            except (ValueError, TypeError, OverflowError):
                merged["health_interval_seconds"] = defaults["health_interval_seconds"]
            try:
                timeout = float(merged.get("health_timeout_seconds", defaults["health_timeout_seconds"]))
                merged["health_timeout_seconds"] = timeout if timeout in {1.0, 2.0, 2.5, 3.0, 5.0} else defaults["health_timeout_seconds"]
            except (ValueError, TypeError, OverflowError):
                merged["health_timeout_seconds"] = defaults["health_timeout_seconds"]
            for key, allowed in (("health_failure_threshold", {2, 3, 4, 5}), ("health_recovery_threshold", {1, 2, 3}), ("tooltip_delay_ms", {500, 750, 1000, 1250}), ("benchmark_rounds", {3, 5, 10})):
                try:
                    number = int(merged.get(key, defaults[key]))
                    merged[key] = number if number in allowed else defaults[key]
                except (ValueError, TypeError, OverflowError):
                    merged[key] = defaults[key]
            for key, lower, upper in (("window_width", 1050, 2800), ("window_height", 700, 1800)):
                try:
                    merged[key] = max(lower, min(int(merged.get(key, defaults[key])), upper))
                except (ValueError, TypeError, OverflowError):
                    merged[key] = defaults[key]
            raw_profiles = merged.get("profiles")
            clean_profiles: list[dict[str, Any]] = []
            seen_profile_ids: set[str] = set()
            doh_by_provider = {
                "cloudflare": "https://cloudflare-dns.com/dns-query",
                "google": "https://dns.google/dns-query",
                "quad9": "https://dns.quad9.net/dns-query",
                "adguard": "https://dns.adguard-dns.com/dns-query",
                "cleanbrowsing": "https://doh.cleanbrowsing.org/doh/family-filter/",
                **{item["id"]: item.get("doh_url") for item in custom_providers if item.get("doh_url")},
            }
            if isinstance(raw_profiles, list):
                for profile in raw_profiles:
                    if not isinstance(profile, dict) or not isinstance(profile.get("name"), str):
                        continue
                    name = profile["name"].strip()[:80]
                    servers = profile.get("servers")
                    if not name or not isinstance(servers, list) or not servers or len(servers) > 8:
                        continue
                    if not all(isinstance(server, str) for server in servers):
                        continue
                    try:
                        if any(ip_address(server).version != 4 for server in servers):
                            continue
                    except (ValueError, TypeError):
                        continue
                    provider_id = profile.get("provider_id")
                    if provider_id not in provider_ids:
                        provider_id = None
                    doh_url = profile.get("doh_url")
                    expected_doh = doh_by_provider.get(provider_id)
                    if not expected_doh or doh_url != expected_doh:
                        doh_url = None
                    profile_id = str(profile.get("id") or "")[:100]
                    if not profile_id or profile_id in seen_profile_ids:
                        profile_id = str(uuid.uuid4())
                    seen_profile_ids.add(profile_id)
                    clean_profiles.append({
                        "id": profile_id,
                        "name": name,
                        "servers": list(servers),
                        "provider_id": provider_id,
                        "doh_url": doh_url,
                        "created_at": str(profile.get("created_at") or "")[:40],
                    })
            merged["profiles"] = clean_profiles
            return merged
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            # Keep the damaged file for recovery instead of silently overwriting it.
            try:
                damaged = self.path.with_suffix(".corrupt.json")
                if not damaged.exists():
                    shutil.copy2(self.path, damaged)
            except OSError:
                pass
            return defaults

    def save(self, settings: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(settings, indent=2, ensure_ascii=False)
        fd, tmp_name = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


class ActivityLogStore:
    """Persistent bounded activity history with an in-memory read cache."""

    def __init__(self, path: Path | None = None, limit: int = 1000) -> None:
        self.path = path or (app_data_dir() / "activity.json")
        self.limit = max(100, min(5000, int(limit)))
        self._cache: list[dict[str, str]] | None = None
        self._lock = threading.RLock()

    def load(self) -> list[dict[str, str]]:
        with self._lock:
            return self._load_locked()

    def _load_locked(self) -> list[dict[str, str]]:
        if self._cache is not None:
            return list(self._cache)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._cache = []
            return []
        except (OSError, json.JSONDecodeError, TypeError):
            # Keep a malformed log for diagnosis; the next append creates a clean log.
            try:
                damaged = self.path.with_suffix(".corrupt.json")
                if self.path.exists() and not damaged.exists():
                    shutil.copy2(self.path, damaged)
            except OSError:
                pass
            self._cache = []
            return []
        if not isinstance(raw, list):
            raw = []
        clean: list[dict[str, str]] = []
        for item in raw[-self.limit:]:
            if not isinstance(item, dict):
                continue
            clean.append({
                "timestamp": str(item.get("timestamp", ""))[:40],
                "level": str(item.get("level", "INFO"))[:12],
                "action": str(item.get("action", ""))[:240],
                "details": str(item.get("details", ""))[:1200],
            })
        self._cache = clean
        return list(clean)

    def _write(self, records: list[dict[str, str]]) -> None:
        payload = json.dumps(records[-self.limit:], ensure_ascii=False, indent=2)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="activity-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _normalize_record(record: dict[str, str]) -> dict[str, str]:
        return {
            "timestamp": str(record.get("timestamp", ""))[:40],
            "level": str(record.get("level", "INFO"))[:12],
            "action": str(record.get("action", ""))[:240],
            "details": str(record.get("details", ""))[:1200],
        }

    def append(self, record: dict[str, str]) -> None:
        self.append_many([record])

    def append_many(self, new_records: list[dict[str, str]]) -> None:
        """Persist a batch with one atomic JSON rewrite rather than one per event."""
        normalized = [self._normalize_record(item) for item in new_records if isinstance(item, dict)]
        if not normalized:
            return
        with self._lock:
            records = self._load_locked()
            records.extend(normalized)
            records = records[-self.limit:]
            self._write(records)
            self._cache = records

    def clear(self) -> None:
        with self._lock:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            self._cache = []


class BackgroundActivityLogger:
    """Serialize activity-log disk writes on one dedicated daemon thread.

    Operations are processed in queue order, so a clear followed by a new log
    entry produces the expected final history. ``on_error`` runs on the worker
    thread; UI callers should marshal it through a Qt signal/dispatcher.
    """

    _STOP = object()

    def __init__(self, store: ActivityLogStore, on_error=None) -> None:
        self.store = store
        self.on_error = on_error
        self._queue: queue.Queue[tuple[str, object] | object] = queue.Queue()
        self._stopped = False
        self._state_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="RaiderDNS-ActivityLog", daemon=True)
        self._thread.start()

    def append(self, record: dict[str, str]) -> None:
        with self._state_lock:
            if self._stopped:
                return
            self._queue.put(("append", dict(record)))

    def clear(self) -> None:
        with self._state_lock:
            if self._stopped:
                return
            self._queue.put(("clear", None))

    def flush(self, timeout: float | None = 2.0) -> bool:
        """Wait for queued operations to finish, returning False on timeout."""
        finished = threading.Event()
        with self._state_lock:
            if self._stopped:
                return not self._thread.is_alive()
            self._queue.put(("barrier", finished))
        return finished.wait(timeout)

    def shutdown(self, timeout: float = 2.0) -> bool:
        with self._state_lock:
            if not self._stopped:
                self._stopped = True
                self._queue.put(self._STOP)
        self._thread.join(max(0.0, timeout))
        return not self._thread.is_alive()

    def _run(self) -> None:
        pending: tuple[str, object] | object | None = None
        while True:
            item = pending if pending is not None else self._queue.get()
            pending = None
            if item is self._STOP:
                self._queue.task_done()
                return
            completed_items = 1
            try:
                operation, payload = item  # type: ignore[misc]
                if operation == "append":
                    batch = [payload]  # type: ignore[list-item]
                    # Coalesce bursts of activity into one fsync + atomic replace.
                    # Stop at clear/barrier/stop so FIFO semantics are retained.
                    while len(batch) < 64:
                        try:
                            next_item = self._queue.get_nowait()
                        except queue.Empty:
                            break
                        if isinstance(next_item, tuple) and len(next_item) == 2 and next_item[0] == "append":
                            batch.append(next_item[1])
                            completed_items += 1
                        else:
                            pending = next_item
                            break
                    self.store.append_many(batch)  # type: ignore[arg-type]
                elif operation == "clear":
                    self.store.clear()
                elif operation == "barrier" and isinstance(payload, threading.Event):
                    payload.set()
            except Exception as exc:
                if self.on_error is not None:
                    try:
                        self.on_error(str(exc))
                    except Exception:
                        pass
            finally:
                for _ in range(completed_items):
                    self._queue.task_done()
