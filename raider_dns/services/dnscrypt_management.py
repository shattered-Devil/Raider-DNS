"""Graphical-management backend for supported dnscrypt-proxy features.

Raider DNS does not implement a second resolver. This module manages the
existing official dnscrypt-proxy configuration and its documented text files:
forwarding rules, blocked/allowed names and the optional local query log.
All writes are validated and atomic. Query logging is opt-in.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import tempfile
import threading
import tomllib
from pathlib import Path
from typing import Any

from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController
from raider_dns.storage import app_data_dir

_ALLOWED_LB_STRATEGIES = {"wp2", "p2", "ph", "p3", "first", "random"}
_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.stem + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def normalize_domain(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ch.isspace() for ch in raw) or "/" in raw or "\\" in raw:
        raise ValueError("Enter a valid DNS domain or local zone.")
    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The domain name could not be converted to IDNA.") from exc
    labels = ascii_name.split(".")
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("The domain contains an invalid DNS label.")
    return ascii_name


def normalize_forwarding_rule(domain: str, upstreams: str) -> str:
    zone = normalize_domain(domain)
    raw_targets = [item.strip() for item in str(upstreams or "").split(",") if item.strip()]
    if not raw_targets or len(raw_targets) > 8:
        raise ValueError("Provide between one and eight forwarding targets.")
    targets: list[str] = []
    for target in raw_targets:
        if target.upper() in {"$DHCP", "$BOOTSTRAP"}:
            targets.append(target.upper())
            continue
        candidate = target
        if candidate.startswith("["):
            match = re.fullmatch(r"\[([0-9a-fA-F:]+)\](?::(\d{1,5}))?", candidate)
            if not match:
                raise ValueError(f"Invalid IPv6 forwarding target: {target}")
            address_text, port_text = match.groups()
            address = ipaddress.ip_address(address_text)
            if address.version != 6:
                raise ValueError("Bracketed forwarding targets must be IPv6 addresses.")
            port = int(port_text) if port_text else 53
            if not 1 <= port <= 65535:
                raise ValueError("Forwarding target port must be between 1 and 65535.")
            targets.append(f"[{address.compressed}]:{port}" if port_text else f"[{address.compressed}]")
            continue
        if candidate.count(":") == 1:
            address_text, port_text = candidate.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValueError(f"Invalid forwarding target port: {target}")
            port = int(port_text)
        else:
            address_text, port = candidate, 53
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ValueError("Forwarding targets must be IP addresses, $DHCP or $BOOTSTRAP; hostnames are not accepted.") from exc
        if address.version != 4:
            raise ValueError("IPv6 forwarding targets must be written in brackets, for example [2001:db8::1]:53.")
        if not 1 <= port <= 65535:
            raise ValueError("Forwarding target port must be between 1 and 65535.")
        targets.append(f"{address.compressed}:{port}" if port != 53 else address.compressed)
    return f"{zone} {','.join(targets)}"


def normalize_name_pattern(value: str) -> str:
    pattern = str(value or "").strip()
    if not pattern or len(pattern) > 253 or any(ch.isspace() for ch in pattern):
        raise ValueError("Enter one domain pattern per line.")
    # Keep the GUI's rule format deliberately bounded: exact domain, exact-only
    # (=domain), or a suffix wildcard (*.example.com). Regex and interior glob
    # expressions are intentionally left to advanced upstream config editors.
    exact_only = pattern.startswith("=")
    body = pattern[1:] if exact_only else pattern
    wildcard = body.startswith("*.")
    domain = body[2:] if wildcard else body
    if "*" in domain or "?" in domain or "[" in domain or "]" in domain:
        raise ValueError("Only exact domains and leading *.domain wildcards are supported in the GUI.")
    normalized = normalize_domain(domain)
    if wildcard:
        return "*." + normalized
    return ("=" if exact_only else "") + normalized


def parse_rule_text(text: str, rule_type: str) -> list[str]:
    result: list[str] = []
    for line_number, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            if rule_type == "forwarding":
                parts = line.split(None, 1)
                if len(parts) != 2:
                    raise ValueError("Expected: domain upstream[,upstream...]")
                result.append(normalize_forwarding_rule(parts[0], parts[1]))
            else:
                result.append(normalize_name_pattern(line))
        except ValueError as exc:
            raise ValueError(f"Line {line_number}: {exc}") from exc
    # Preserve the first occurrence order and eliminate duplicates.
    return list(dict.fromkeys(result))


def parse_query_log(path: Path, limit: int = 500, max_bytes: int = 2_000_000) -> list[dict[str, str]]:
    """Read only the bounded tail of the local TSV query log."""
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size > max_bytes:
                stream.seek(size - max_bytes)
                stream.readline()  # discard partial first line
            data = stream.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return []
    records: list[dict[str, str]] = []
    for fields in csv.reader(data.splitlines(), delimiter="\t"):
        if len(fields) < 8:
            continue
        timestamp, client_ip, query_name, query_type, return_code, duration, server, relay = fields[:8]
        records.append({
            "timestamp": timestamp[:64],
            "client_ip": client_ip[:64],
            "query_name": query_name[:253],
            "query_type": query_type[:16],
            "return_code": return_code[:32],
            "duration": duration[:40],
            "server": server[:120],
            "relay": relay[:120],
        })
    return records[-max(1, min(int(limit), 2000)):]


class DNSCryptFeatureManager:
    """Manage rule files and supported feature tables for Raider's generated TOML."""
    def __init__(self, config_path: Path | None = None, data_dir: Path | None = None) -> None:
        self.config_path = Path(config_path) if config_path else DNSCryptProxyController.default_config_path()
        self.data_dir = Path(data_dir) if data_dir else self.config_path.parent
        self.forwarding_path = self.data_dir / "forwarding-rules.txt"
        self.blocked_path = self.data_dir / "blocked-names.txt"
        self.allowed_path = self.data_dir / "allowed-names.txt"
        self.query_log_path = self.data_dir / "query.log"
        self.blocked_log_path = self.data_dir / "blocked-names.log"
        self.allowed_log_path = self.data_dir / "allowed-names.log"
        self._lock = threading.RLock()

    @staticmethod
    def _toml_string(value: str) -> str:
        return json.dumps(str(value), ensure_ascii=True)

    def configure(
        self,
        *,
        query_monitor_enabled: bool,
        filtering_enabled: bool,
        split_dns_enabled: bool,
        lb_strategy: str = "wp2",
        blocked_rules: str = "",
        allowed_rules: str = "",
        forwarding_rules: str = "",
    ) -> dict[str, Any]:
        """Validate and atomically update Raider-managed DNSCrypt files/config."""
        strategy = str(lb_strategy).casefold()
        if strategy not in _ALLOWED_LB_STRATEGIES:
            raise ValueError("Unsupported DNSCrypt resolver load-balancing strategy.")
        blocked = parse_rule_text(blocked_rules, "names")
        allowed = parse_rule_text(allowed_rules, "names")
        forwarding = parse_rule_text(forwarding_rules, "forwarding")
        if len(blocked) > 5000 or len(allowed) > 5000 or len(forwarding) > 500:
            raise ValueError("Rule limit exceeded (5000 domain rules or 500 forwarding rules).")
        if split_dns_enabled and not forwarding:
            raise ValueError("Split DNS is enabled, but no forwarding rules were supplied.")
        if filtering_enabled and not blocked:
            raise ValueError("Filtering is enabled, but the blocklist is empty. An allowlist only defines exceptions; it does not block domains by itself.")
        if not self.config_path.is_file():
            raise FileNotFoundError("Generate the DNSCrypt configuration from the Connections page before configuring DNSCrypt features.")

        with self._lock:
            valid, message = DNSCryptProxyController.validate_config(self.config_path)
            if not valid:
                raise ValueError(f"The current DNSCrypt config is not a supported Raider DNS config: {message}")

            original_config = self.config_path.read_text(encoding="utf-8")
            managed_files = {
                self.forwarding_path: "# Managed by Raider DNS. One zone and its upstream IP targets per line.\n" + "\n".join(forwarding) + ("\n" if forwarding else ""),
                self.blocked_path: "# Managed by Raider DNS. Domain patterns to block.\n" + "\n".join(blocked) + ("\n" if blocked else ""),
                self.allowed_path: "# Managed by Raider DNS. Domain patterns exempt from upstream block lists.\n" + "\n".join(allowed) + ("\n" if allowed else ""),
            }
            backups: dict[Path, str | None] = {}
            for target in managed_files:
                try:
                    backups[target] = target.read_text(encoding="utf-8")
                except FileNotFoundError:
                    backups[target] = None

            root_begin = "# BEGIN RAIDER DNS MANAGED ROOT SETTINGS"
            root_end = "# END RAIDER DNS MANAGED ROOT SETTINGS"
            table_begin = "# BEGIN RAIDER DNS MANAGED TABLES"
            table_end = "# END RAIDER DNS MANAGED TABLES"
            base = original_config
            for begin, end_marker in ((root_begin, root_end), (table_begin, table_end)):
                pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end_marker) + r"\s*", re.DOTALL)
                base = pattern.sub("", base)

            root_lines = [root_begin]
            root_lines.append(f"lb_strategy = {self._toml_string(strategy)}")
            root_lines.append("lb_estimator = true")
            hot_reload = bool(filtering_enabled or split_dns_enabled)
            root_lines.append(f"enable_hot_reload = {'true' if hot_reload else 'false'}")
            if split_dns_enabled:
                root_lines.append(f"forwarding_rules = {self._toml_string(self.forwarding_path.name)}")
            root_lines.append(root_end)
            root_block = "\n".join(root_lines) + "\n\n"
            first_table = re.search(r"(?m)^\s*\[", base)
            insert_at = first_table.start() if first_table else len(base)
            # These keys belong to the TOML root table and already exist in the
            # generated secure config. Remove their original root assignments
            # before writing the managed block to avoid duplicate TOML keys.
            root_section = base[:insert_at]
            root_remainder = base[insert_at:]
            for key in ("lb_strategy", "lb_estimator", "enable_hot_reload", "forwarding_rules"):
                root_section = re.sub(rf"(?m)^\s*{re.escape(key)}\s*=.*(?:\n|$)", "", root_section)
            updated = root_section.rstrip() + "\n\n" + root_block + root_remainder

            tables = [table_begin]
            if query_monitor_enabled:
                tables += [
                    "[query_log]",
                    f"file = {self._toml_string(self.query_log_path.name)}",
                    'format = "tsv"',
                    "",
                ]
            if filtering_enabled:
                tables += [
                    "[blocked_names]",
                    f"blocked_names_file = {self._toml_string(self.blocked_path.name)}",
                    f"log_file = {self._toml_string(self.blocked_log_path.name)}",
                    'log_format = "tsv"',
                    "",
                    "[allowed_names]",
                    f"allowed_names_file = {self._toml_string(self.allowed_path.name)}",
                    f"log_file = {self._toml_string(self.allowed_log_path.name)}",
                    'log_format = "tsv"',
                    "",
                ]
            tables.append(table_end)
            if query_monitor_enabled or filtering_enabled:
                updated = updated.rstrip() + "\n\n" + "\n".join(tables) + "\n"

            # Validate generated TOML and all security invariants before touching disk.
            try:
                parsed = tomllib.loads(updated)
            except tomllib.TOMLDecodeError as exc:
                raise ValueError(f"Generated DNSCrypt TOML did not validate: {exc}") from exc
            if parsed.get("server_names") != [] or parsed.get("require_dnssec") is not True or parsed.get("require_nolog") is not True:
                raise ValueError("Managed DNSCrypt configuration would weaken the signed resolver security filters.")

            try:
                for target, content in managed_files.items():
                    _atomic_write(target, content)
                _atomic_write(self.config_path, updated)
                valid, message = DNSCryptProxyController.validate_config(self.config_path)
                if not valid:
                    raise ValueError(f"DNSCrypt validation failed: {message}")
            except Exception:
                # Roll back every managed file as one logical configuration change.
                for target, previous in backups.items():
                    try:
                        if previous is None:
                            target.unlink(missing_ok=True)
                        else:
                            _atomic_write(target, previous)
                    except OSError:
                        pass
                try:
                    _atomic_write(self.config_path, original_config)
                except OSError:
                    pass
                raise

        return {
            "query_monitor_enabled": bool(query_monitor_enabled),
            "filtering_enabled": bool(filtering_enabled),
            "split_dns_enabled": bool(split_dns_enabled),
            "lb_strategy": strategy,
            "blocked_rules": len(blocked),
            "allowed_rules": len(allowed),
            "forwarding_rules": len(forwarding),
            "hot_reload_enabled": hot_reload,
            "query_log_path": str(self.query_log_path),
        }

    def query_log(self, limit: int = 500) -> list[dict[str, str]]:
        return parse_query_log(self.query_log_path, limit=limit)

    @staticmethod
    def _count_rule_lines(path: Path) -> int:
        try:
            return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        except (OSError, UnicodeError):
            return 0

    def status(self) -> dict[str, Any]:
        try:
            config = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeError):
            config = {}
        query_log = config.get("query_log") if isinstance(config.get("query_log"), dict) else {}
        blocked_names = config.get("blocked_names") if isinstance(config.get("blocked_names"), dict) else {}
        allowed_names = config.get("allowed_names") if isinstance(config.get("allowed_names"), dict) else {}
        return {
            "configured": bool(config),
            "query_monitor_enabled": bool(query_log.get("file")),
            "filtering_enabled": bool(blocked_names.get("blocked_names_file") or allowed_names.get("allowed_names_file")),
            "split_dns_enabled": bool(config.get("forwarding_rules")),
            "lb_strategy": str(config.get("lb_strategy", "wp2")),
            "blocked_rules": self._count_rule_lines(self.blocked_path),
            "allowed_rules": self._count_rule_lines(self.allowed_path),
            "forwarding_rules": self._count_rule_lines(self.forwarding_path),
        }
