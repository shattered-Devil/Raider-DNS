"""Local, privacy-conscious network recovery snapshots and diagnosis hints.

This module is advisory only. It never resets adapters, changes DNS, touches
routes, changes drivers, or terminates network processes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from raider_dns.storage import app_data_dir


class NetworkRecoveryIntelligence:
    SCHEMA_VERSION = 2
    MAX_SNAPSHOTS = 30

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else app_data_dir() / "network-intelligence.json"
        self._lock = threading.RLock()

    @classmethod
    def _sanitize_snapshot(cls, raw: dict[str, Any]) -> dict[str, Any]:
        """Migrate legacy records while dropping adapter/SSID/gateway identifiers."""
        checks: list[dict[str, str]] = []
        raw_checks = raw.get("checks", [])
        for item in raw_checks if isinstance(raw_checks, list) else []:
            if not isinstance(item, dict):
                continue
            # Keep only coarse diagnostic facts. Details can contain IP addresses,
            # SSIDs, interface names, or other environment-specific identifiers.
            checks.append({
                "id": str(item.get("id", ""))[:80],
                "title": str(item.get("title", ""))[:120],
                "status": str(item.get("status", "UNKNOWN"))[:16],
                "measurement": str(item.get("measurement", ""))[:100],
            })
        summary_raw = raw.get("summary", {})
        summary = {}
        if isinstance(summary_raw, dict):
            for key in ("passed", "failed", "warnings", "total"):
                value = summary_raw.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    summary[key] = max(0, min(value, 10000))
        result = {
            "captured_at": str(raw.get("captured_at", ""))[:64],
            "adapter_status": str(raw.get("adapter_status", "Unknown"))[:32],
            "dhcp_enabled": bool(raw.get("dhcp_enabled", False)),
            "checks": checks[:80],
            "summary": summary,
        }
        changes = raw.get("changes_from_previous", [])
        if isinstance(changes, list):
            allowed = []
            for item in changes[:30]:
                if not isinstance(item, dict):
                    continue
                field = str(item.get("field", ""))
                if field not in {"adapter_status", "dhcp_enabled"} and not field.startswith("check:"):
                    continue
                allowed.append({
                    "field": field[:100],
                    "label": str(item.get("label", ""))[:120],
                    "before": str(item.get("before", ""))[:32],
                    "after": str(item.get("after", ""))[:32],
                })
            result["changes_from_previous"] = allowed
        return result

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": self.SCHEMA_VERSION, "snapshots": []}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            snapshots = raw.get("snapshots", []) if isinstance(raw, dict) else []
            if not isinstance(snapshots, list):
                snapshots = []
            safe = [self._sanitize_snapshot(item) for item in snapshots if isinstance(item, dict)]
            return {"schema_version": self.SCHEMA_VERSION, "snapshots": safe[-self.MAX_SNAPSHOTS:]}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {"schema_version": self.SCHEMA_VERSION, "snapshots": []}

    def _save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="network-intel-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    @classmethod
    def _safe_snapshot(cls, report: dict[str, Any]) -> dict[str, Any]:
        """Persist only coarse connection state; no SSIDs, adapter names or IPs."""
        raw = {
            "captured_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "adapter_status": report.get("adapter_status", "Unknown"),
            "dhcp_enabled": report.get("dhcp_enabled", False),
            "checks": report.get("checks", []),
            "summary": report.get("summary", {}),
        }
        return cls._sanitize_snapshot(raw)

    @staticmethod
    def compare(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[dict[str, str]]:
        """Describe material network-state changes without treating them as faults."""
        if not isinstance(previous, dict) or not isinstance(current, dict):
            return []
        changes: list[dict[str, str]] = []
        for key, label in (
            ("adapter_status", "Link status"),
            ("dhcp_enabled", "DHCP setting"),
        ):
            before = str(previous.get(key, ""))
            after = str(current.get(key, ""))
            if before != after and (before or after):
                changes.append({"field": key, "label": label, "before": before or "Not available", "after": after or "Not available"})

        before_checks = {str(row.get("id")): row for row in previous.get("checks", []) if isinstance(row, dict)}
        after_checks = {str(row.get("id")): row for row in current.get("checks", []) if isinstance(row, dict)}
        for check_id in sorted(set(before_checks) & set(after_checks)):
            before = str(before_checks[check_id].get("status", "UNKNOWN"))
            after = str(after_checks[check_id].get("status", "UNKNOWN"))
            if before != after:
                label = str(after_checks[check_id].get("title") or before_checks[check_id].get("title") or check_id)
                changes.append({"field": f"check:{check_id}", "label": f"{label} status", "before": before, "after": after})
        return changes[:30]

    def capture(self, report: dict[str, Any]) -> dict[str, Any]:
        snapshot = self._safe_snapshot(report)
        with self._lock:
            payload = self._load()
            previous = payload["snapshots"][-1] if payload["snapshots"] else None
            snapshot["changes_from_previous"] = self.compare(previous, snapshot)
            payload["snapshots"].append(snapshot)
            payload["snapshots"] = payload["snapshots"][-self.MAX_SNAPSHOTS:]
            self._save(payload)
        return snapshot

    def latest(self) -> dict[str, Any] | None:
        with self._lock:
            snapshots = self._load()["snapshots"]
            return dict(snapshots[-1]) if snapshots else None

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._load()["snapshots"]]

    @staticmethod
    def assess(report: dict[str, Any]) -> list[dict[str, str]]:
        """Return specific, non-destructive recovery advice based on report evidence."""
        checks = report.get("checks", [])
        by_id = {str(row.get("id")): row for row in checks if isinstance(row, dict)} if isinstance(checks, list) else {}
        findings: list[dict[str, str]] = []

        adapter = by_id.get("adapter_state", {})
        address = by_id.get("address_assignment", {})
        gateway = by_id.get("default_gateway", {})
        gateway_ping = by_id.get("gateway_ping", {})
        dns = by_id.get("dns_resolution", {})
        https = by_id.get("https_connectivity", {})
        tcp = by_id.get("tcp_external_443", {})

        if adapter.get("status") == "FAIL":
            findings.append({
                "severity": "critical",
                "title": "Selected network adapter is not up",
                "reason": str(adapter.get("details", "Adapter status is not Up.")),
                "recommendation": "Check the physical connection or Wi-Fi radio/airplane-mode state before changing DNS.",
            })
        if address.get("status") == "FAIL" or gateway.get("status") == "FAIL":
            findings.append({
                "severity": "critical",
                "title": "Address or default-gateway configuration is incomplete",
                "reason": str(address.get("details") or gateway.get("details") or "No usable address or default route was detected."),
                "recommendation": "Check DHCP/router connectivity and the selected adapter. Only use DHCP renew after confirming that the adapter is configured for DHCP.",
            })
        elif gateway_ping.get("status") == "FAIL" and gateway.get("status") == "PASS":
            findings.append({
                "severity": "warning",
                "title": "Gateway does not answer ICMP",
                "reason": str(gateway_ping.get("details", "The gateway did not answer ping.")),
                "recommendation": "Some routers block ping. Verify access to the router administration page or another local service before treating this as a network outage.",
            })
        if dns.get("status") == "FAIL" and (tcp.get("status") == "PASS" or https.get("status") == "PASS"):
            findings.append({
                "severity": "warning",
                "title": "Internet transport works, but system DNS resolution fails",
                "reason": str(dns.get("details", "DNS resolution failed while TCP/HTTPS was reachable.")),
                "recommendation": "Inspect configured DNS servers and encrypted-DNS registrations. Consider flushing the DNS cache; do not reset the network stack as a first step.",
            })
        if https.get("status") == "FAIL" and tcp.get("status") == "FAIL":
            findings.append({
                "severity": "warning",
                "title": "External connectivity could not be verified",
                "reason": str(https.get("details", "HTTPS and external TCP checks failed.")),
                "recommendation": "Check captive-portal login, router connectivity, firewall policy and VPN state. DNS changes alone may not fix a transport problem.",
            })
        if not findings:
            findings.append({
                "severity": "success",
                "title": "No high-confidence network fault detected",
                "reason": "The latest read-only connectivity checks did not identify a clear connection, gateway or DNS failure.",
                "recommendation": "Keep the current configuration. A passing diagnostic is a point-in-time observation, not a guarantee against intermittent faults.",
            })
        return findings
