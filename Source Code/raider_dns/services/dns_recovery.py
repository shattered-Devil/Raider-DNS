"""Crash-safe, atomic recovery snapshots for Windows DNS transactions.

The store contains DNS configuration metadata only (adapter names, addresses,
DoH templates and encryption flags). It never stores passwords or proxy secrets.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_recovery_path() -> Path:
    if os.name == "nt":
        root = os.environ.get("APPDATA")
        if root:
            return Path(root) / "RaiderDNS" / "dns-recovery.json"
    return Path.home() / ".config" / "raider-dns" / "dns-recovery.json"


class DNSRecoveryStore:
    """Persistent per-adapter restore points with pending-transaction recovery."""

    SCHEMA_VERSION = 1

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_recovery_path()
        self._lock = threading.RLock()

    @staticmethod
    def adapter_key(adapter: str) -> str:
        return str(adapter).strip().casefold()

    @staticmethod
    def _dns_config_signature(snapshot: dict[str, Any]) -> tuple[Any, ...]:
        families = snapshot.get("families", {}) if isinstance(snapshot, dict) else {}
        result: list[Any] = []
        for family in ("IPv4", "IPv6"):
            data = families.get(family, {}) if isinstance(families, dict) else {}
            mode = str(data.get("mode", "automatic")).casefold() if isinstance(data, dict) else "automatic"
            servers = data.get("servers", []) if isinstance(data, dict) else []
            if not isinstance(servers, list):
                servers = []
            result.extend([family, mode, tuple(str(x).strip() for x in servers)])
        return tuple(result)

    @classmethod
    def signature(
        cls,
        snapshot: dict[str, Any],
        doh_servers: list[str] | tuple[str, ...] = (),
        dot_servers: list[str] | tuple[str, ...] = (),
        include_dot_global: bool = False,
    ) -> str:
        doh_map = snapshot.get("doh_by_server", {}) if isinstance(snapshot, dict) else {}
        dot_map = snapshot.get("dot_by_server", {}) if isinstance(snapshot, dict) else {}
        data = {
            "dns": cls._dns_config_signature(snapshot),
            "doh": {s: doh_map.get(s) for s in sorted(set(doh_servers), key=str.casefold)},
            "dot": {s: dot_map.get(s) for s in sorted(set(dot_servers), key=str.casefold)},
            "dot_global": snapshot.get("dot_global") if include_dot_global else None,
        }
        # JSON is deterministic and avoids depending on Python hash randomization.
        import hashlib
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": self.SCHEMA_VERSION, "adapters": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("adapters", {}), dict):
                raise ValueError("Invalid DNS recovery file structure")
            adapters = payload.get("adapters", {})
            clean: dict[str, Any] = {}
            for key, record in adapters.items():
                if isinstance(key, str) and key and isinstance(record, dict):
                    clean[key] = record
            return {"schema_version": self.SCHEMA_VERSION, "adapters": clean}
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            # Preserve a corrupt file for manual diagnosis. Do not silently replace
            # it with an empty recovery database, which could hide a restore point.
            try:
                corrupt = self.path.with_name(f"{self.path.stem}.corrupt{self.path.suffix}")
                if not corrupt.exists():
                    shutil.copy2(self.path, corrupt)
            except OSError:
                pass
            raise RuntimeError(f"DNS recovery data could not be read safely: {exc}") from exc

    def _save_unlocked(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, indent=2, ensure_ascii=False)
        fd, temp_name = tempfile.mkstemp(prefix="dns-recovery-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _mutate(self, fn) -> Any:
        with self._lock:
            payload = self._load_unlocked()
            result = fn(payload)
            self._save_unlocked(payload)
            return result

    def get_record(self, adapter: str) -> dict[str, Any] | None:
        key = self.adapter_key(adapter)
        with self._lock:
            payload = self._load_unlocked()
            value = payload["adapters"].get(key)
            return json.loads(json.dumps(value)) if isinstance(value, dict) else None

    def begin_transaction(
        self,
        adapter: str,
        snapshot: dict[str, Any],
        doh_servers: list[str] | None = None,
        dot_servers: list[str] | None = None,
        changes_dot_global: bool = False,
    ) -> None:
        key = self.adapter_key(adapter)
        if not key:
            raise ValueError("Adapter name is required for DNS recovery.")
        doh_servers = list(dict.fromkeys(str(x) for x in (doh_servers or [])))
        dot_servers = list(dict.fromkeys(str(x) for x in (dot_servers or [])))

        def change(payload: dict[str, Any]) -> None:
            adapters = payload["adapters"]
            record = adapters.get(key)
            if isinstance(record, dict) and record.get("pending"):
                raise RuntimeError(
                    "An earlier DNS transaction is still pending recovery. Use Restore Previous DNS Settings before applying another change."
                )
            current_signature = self.signature(
                snapshot, list((record or {}).get("doh_baseline", {}).keys()),
                list((record or {}).get("dot_baseline", {}).keys()),
                changes_dot_global or bool((record or {}).get("dot_global_baseline_known")),
            )
            baseline_needs_reset = not isinstance(record, dict)
            if isinstance(record, dict):
                active_signature = record.get("active_signature")
                if active_signature is not None and active_signature != current_signature:
                    # The user or another network component changed DNS outside
                    # Raider DNS. Make the new observed state the new restore point.
                    baseline_needs_reset = True
                elif not isinstance(record.get("restore_point"), dict):
                    baseline_needs_reset = True
            if baseline_needs_reset:
                record = {
                    "adapter": adapter,
                    "restore_point": snapshot,
                    "doh_baseline": {},
                    "dot_baseline": {},
                    # The global DoT switch is a machine-wide setting. Track it
                    # for rollback only when this transaction can change it; a
                    # standard DNS/DoH operation must not become dependent on a
                    # fragile netsh global-state parse merely to restore adapter IPs.
                    "dot_global_baseline": snapshot.get("dot_global") if changes_dot_global else None,
                    "dot_global_baseline_known": bool(changes_dot_global and snapshot.get("dot_global") in (True, False)),
                    "active_signature": None,
                }
            else:
                record = dict(record)
                record["adapter"] = adapter
            doh_baseline = dict(record.get("doh_baseline", {}))
            snapshot_doh = snapshot.get("doh_by_server", {})
            for server in doh_servers:
                if server not in doh_baseline:
                    doh_baseline[server] = snapshot_doh.get(server) if isinstance(snapshot_doh, dict) else None
            dot_baseline = dict(record.get("dot_baseline", {}))
            snapshot_dot = snapshot.get("dot_by_server", {})
            for server in dot_servers:
                if server not in dot_baseline:
                    dot_baseline[server] = snapshot_dot.get(server) if isinstance(snapshot_dot, dict) else None
            if changes_dot_global and not record.get("dot_global_baseline_known"):
                if snapshot.get("dot_global") not in (True, False):
                    raise RuntimeError("Windows DoT global state could not be read; refusing to change it without a reliable rollback value.")
                record["dot_global_baseline"] = snapshot.get("dot_global")
                record["dot_global_baseline_known"] = True
            record["doh_baseline"] = doh_baseline
            record["dot_baseline"] = dot_baseline
            record["pending"] = snapshot
            record["pending_doh_servers"] = doh_servers
            record["pending_dot_servers"] = dot_servers
            record["pending_changes_dot_global"] = bool(changes_dot_global)
            record["pending_started_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            adapters[key] = record
        self._mutate(change)

    def commit_transaction(
        self,
        adapter: str,
        snapshot_after: dict[str, Any],
        changes_dot_global: bool = False,
    ) -> None:
        key = self.adapter_key(adapter)

        def change(payload: dict[str, Any]) -> None:
            record = payload["adapters"].get(key)
            if not isinstance(record, dict):
                raise RuntimeError("DNS recovery transaction is missing; refusing to mark the operation as committed.")
            record["active_signature"] = self.signature(
                snapshot_after,
                list(record.get("doh_baseline", {}).keys()),
                list(record.get("dot_baseline", {}).keys()),
                bool(record.get("dot_global_baseline_known")),
            )
            record["pending"] = None
            record.pop("pending_doh_servers", None)
            record.pop("pending_dot_servers", None)
            record.pop("pending_changes_dot_global", None)
            record.pop("pending_started_at", None)
            record["last_success_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._mutate(change)

    def finish_rollback(self, adapter: str, restored_snapshot: dict[str, Any] | None, success: bool) -> None:
        key = self.adapter_key(adapter)
        if not success:
            # Keep pending snapshot on disk so a restart still exposes a recovery path.
            return

        def change(payload: dict[str, Any]) -> None:
            record = payload["adapters"].get(key)
            if not isinstance(record, dict):
                return
            if restored_snapshot is not None:
                record["active_signature"] = self.signature(
                    restored_snapshot,
                    list(record.get("doh_baseline", {}).keys()),
                    list(record.get("dot_baseline", {}).keys()),
                    bool(record.get("dot_global_baseline_known")),
                )
            record["pending"] = None
            record.pop("pending_doh_servers", None)
            record.pop("pending_dot_servers", None)
            record.pop("pending_changes_dot_global", None)
            record.pop("pending_started_at", None)
            record["last_rollback_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._mutate(change)

    def has_previous_settings(self, adapter: str) -> bool:
        record = self.get_record(adapter)
        if not record:
            return False
        if isinstance(record.get("pending"), dict):
            return True
        baseline = record.get("restore_point")
        active_signature = record.get("active_signature")
        if not isinstance(baseline, dict) or not active_signature:
            return False
        base_signature = self.signature(
            baseline,
            list(record.get("doh_baseline", {}).keys()),
            list(record.get("dot_baseline", {}).keys()),
            bool(record.get("dot_global_baseline_known")),
        )
        return active_signature != base_signature

    def get_restore_target(self, adapter: str) -> tuple[dict[str, Any], dict[str, Any], bool] | None:
        """Return (target snapshot, record, is_pending_recovery)."""
        record = self.get_record(adapter)
        if not record:
            return None
        pending = record.get("pending")
        if isinstance(pending, dict):
            return pending, record, True
        baseline = record.get("restore_point")
        if isinstance(baseline, dict):
            return baseline, record, False
        return None

    def complete_user_restore(self, adapter: str) -> None:
        key = self.adapter_key(adapter)
        def change(payload: dict[str, Any]) -> None:
            payload["adapters"].pop(key, None)
        self._mutate(change)

    def clear(self, adapter: str) -> None:
        self.complete_user_restore(adapter)
