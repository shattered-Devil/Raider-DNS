"""Pure helpers for detecting changes to active adapters and DNS configuration."""
from __future__ import annotations

from typing import Any

NetworkSignature = tuple[
    tuple[str, ...], tuple[tuple[str, str, tuple[str, ...]], ...], tuple[str, ...], tuple[str, ...]
]


def build_network_signature(
    adapters: list[str], dns_rows: list[dict[str, Any]], network_info: dict[str, Any] | None = None
) -> NetworkSignature:
    """Normalize adapter, DNS and private-address data into a stable signature."""
    normalized_adapters = tuple(sorted({str(item).strip() for item in adapters if str(item).strip()}, key=str.casefold))
    normalized_dns: list[tuple[str, str, tuple[str, ...]]] = []
    for row in dns_rows:
        if not isinstance(row, dict):
            continue
        adapter = str(row.get("adapter", "Unknown")).strip() or "Unknown"
        servers_value = row.get("servers", [])
        if isinstance(servers_value, str):
            servers_value = [servers_value]
        if not isinstance(servers_value, (list, tuple)):
            servers_value = []
        family = str(row.get("family", "IPv4")).strip() or "IPv4"
        servers = tuple(sorted({str(server).strip() for server in servers_value if str(server).strip()}))
        normalized_dns.append((adapter, family, servers))
    info = network_info if isinstance(network_info, dict) else {}
    raw_v4 = info.get("private_ipv4", [])
    raw_v6 = info.get("private_ipv6", [])
    if not isinstance(raw_v4, (list, tuple)):
        raw_v4 = []
    if not isinstance(raw_v6, (list, tuple)):
        raw_v6 = []
    ipv4 = tuple(sorted({str(item).strip() for item in raw_v4 if str(item).strip()}))
    ipv6 = tuple(sorted({str(item).strip() for item in raw_v6 if str(item).strip()}))
    return (normalized_adapters, tuple(sorted(normalized_dns, key=lambda item: item[0].casefold())), ipv4, ipv6)


def describe_network_changes(previous: NetworkSignature, current: NetworkSignature) -> list[str]:
    """Describe meaningful adapter and DNS differences between two signatures."""
    changes: list[str] = []
    old_adapters, old_dns, old_ipv4, old_ipv6 = previous
    new_adapters, new_dns, new_ipv4, new_ipv6 = current
    if old_adapters != new_adapters:
        changes.append(
            "Active adapters changed: "
            f"[{', '.join(old_adapters) or 'none'}] → [{', '.join(new_adapters) or 'none'}]"
        )
    if old_ipv4 != new_ipv4:
        changes.append(f"Private IPv4 addresses changed: [{', '.join(old_ipv4) or 'none'}] → [{', '.join(new_ipv4) or 'none'}]")
    if old_ipv6 != new_ipv6:
        changes.append(f"Private IPv6 addresses changed: [{', '.join(old_ipv6) or 'none'}] → [{', '.join(new_ipv6) or 'none'}]")
    if old_dns != new_dns:
        old_map = {(name, family): servers for name, family, servers in old_dns}
        new_map = {(name, family): servers for name, family, servers in new_dns}
        for adapter, family in sorted(set(old_map) | set(new_map), key=lambda item: (item[0].casefold(), item[1].casefold())):
            before = old_map.get((adapter, family), ())
            after = new_map.get((adapter, family), ())
            if before != after:
                changes.append(
                    f"DNS servers for {adapter} ({family}): "
                    f"[{', '.join(before) or 'none'}] → [{', '.join(after) or 'none'}]"
                )
    return changes


def classify_network_transition(previous: NetworkSignature | None, current: NetworkSignature) -> str | None:
    """Classify connect/disconnect transitions separately from ordinary network changes."""
    if previous is None:
        return None
    previously_active = bool(previous[0])
    currently_active = bool(current[0])
    if previously_active and not currently_active:
        return "disconnected"
    if not previously_active and currently_active:
        return "reconnected"
    if previous != current:
        return "changed"
    return None
