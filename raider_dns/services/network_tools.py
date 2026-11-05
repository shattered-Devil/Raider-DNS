"""Windows network maintenance and network address discovery helpers.

Commands are allow-listed, shell-free, bounded by timeouts and hidden on Windows.
The module returns outcomes instead of assuming that launching a command means it worked.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from raider_dns import __version__

from raider_dns.services.timeouts import DEFAULT_COMMAND_TIMEOUT_SECONDS, DNS_CACHE_FLUSH_TIMEOUT_SECONDS, NETWORK_INFO_TIMEOUT_SECONDS, NETWORK_REPAIR_TIMEOUT_SECONDS


@dataclass(slots=True)
class CommandOutcome:
    key: str
    title: str
    success: bool
    message: str
    output: str = ""
    requires_restart: bool = False


REPAIR_OPERATIONS: dict[str, tuple[str, ...]] = {
    "flush_dns": ("Flush DNS cache", "ipconfig", "/flushdns"),
    "release_ip": ("Release DHCP lease", "ipconfig", "/release"),
    "renew_ip": ("Renew DHCP lease", "ipconfig", "/renew"),
    "register_dns": ("Register DNS records", "ipconfig", "/registerdns"),
    "clear_arp_cache": ("Clear ARP cache", "arp", "-d", "*"),
    "winsock_reset": ("Reset Winsock catalog", "netsh", "winsock", "reset"),
    "tcpip_reset": ("Reset IPv4 TCP/IP stack", "netsh", "int", "ip", "reset"),
    "ipv6_reset": ("Reset IPv6 stack", "netsh", "int", "ipv6", "reset"),
    "reset_proxy": ("Reset WinHTTP proxy to direct", "netsh", "winhttp", "reset", "proxy"),
}


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if is_windows() else 0


def run_command(command: list[str], timeout: int = DEFAULT_COMMAND_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    """Run a fixed argument vector without shell interpolation or a console window."""
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("A non-empty command argument list is required.")
    return subprocess.run(
        command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, creationflags=_creation_flags(),
    )


def flush_dns_cache() -> CommandOutcome:
    if not is_windows():
        return CommandOutcome("flush_dns", "Flush DNS cache", False, "This operation is supported on Windows only.")
    if not is_admin():
        return CommandOutcome("flush_dns", "Flush DNS cache", False, "Administrator privileges are required.")
    try:
        result = run_command(["ipconfig.exe", "/flushdns"], timeout=DNS_CACHE_FLUSH_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandOutcome("flush_dns", "Flush DNS cache", False, f"Could not run ipconfig: {exc}")
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    success = result.returncode == 0
    return CommandOutcome("flush_dns", "Flush DNS cache", success, "DNS resolver cache flushed." if success else "DNS cache flush failed.", output)


def repair_network(operations: Iterable[str], adapter: str | None = None) -> list[CommandOutcome]:
    """Execute selected repair steps in the user-provided order, stopping at invalid keys.

    DHCP release/renew and stack resets can interrupt networking. Privilege and OS
    checks happen before any command is started.
    """
    chosen = list(dict.fromkeys(operations))
    if not chosen:
        return [CommandOutcome("repair", "Network repair", False, "Select at least one repair operation.")]
    unknown = [key for key in chosen if key not in REPAIR_OPERATIONS]
    if unknown:
        return [CommandOutcome("repair", "Network repair", False, f"Unsupported repair operation: {unknown[0]}")]
    if not is_windows():
        return [CommandOutcome(key, REPAIR_OPERATIONS[key][0], False, "Network repair commands are supported on Windows only.") for key in chosen]
    if not is_admin():
        return [CommandOutcome(key, REPAIR_OPERATIONS[key][0], False, "Administrator privileges are required.") for key in chosen]

    outcomes: list[CommandOutcome] = []
    for key in chosen:
        spec = REPAIR_OPERATIONS[key]
        title, *command = spec
        requires_restart = key in {"winsock_reset", "tcpip_reset", "ipv6_reset"}
        try:
            executable = command[0] + (".exe" if command[0] in {"ipconfig", "netsh", "arp"} else "")
            args = [executable, *command[1:]]
            if key in {"release_ip", "renew_ip"} and adapter and adapter.strip():
                # Restrict DHCP lease operations to the selected adapter when possible.
                args.append(adapter.strip())
            result = run_command(args, timeout=NETWORK_REPAIR_TIMEOUT_SECONDS)
            output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
            success = result.returncode == 0
            outcomes.append(CommandOutcome(key, title, success, "Completed." if success else f"Command exited with code {result.returncode}.", output, requires_restart))
            # Do not continue a multi-step repair sequence after a failure.
            if not success:
                break
        except (OSError, subprocess.SubprocessError) as exc:
            outcomes.append(CommandOutcome(key, title, False, f"Command failed: {exc}", "", requires_restart))
            break
    return outcomes


def _normalize_private_addresses(addresses: Iterable[str]) -> tuple[set[str], set[str]]:
    private_v4: set[str] = set()
    private_v6: set[str] = set()
    for raw_address in addresses:
        if not isinstance(raw_address, str):
            continue
        address = raw_address.split("%", 1)[0].strip()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_link_local or parsed.is_multicast or not parsed.is_private:
            continue
        if parsed.version == 4:
            private_v4.add(str(parsed))
        else:
            private_v6.add(str(parsed))
    return private_v4, private_v6


def _windows_interface_addresses(timeout: float) -> list[str]:
    """Query Windows' address table without requiring elevation; use a fixed script."""
    script = (
        "Get-NetIPAddress -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.AddressState -eq 'Preferred' } | "
        "Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Compress"
    )
    try:
        result = run_command(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=max(1, int(timeout)),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        parsed = json.loads(result.stdout)
        if isinstance(parsed, str):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, str)]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError, ValueError):
        return []
    return []


def get_network_info(timeout: float = NETWORK_INFO_TIMEOUT_SECONDS, include_public: bool = True) -> dict[str, object]:
    """Return private IPv4/IPv6 addresses and an optional best-effort public lookup.

    On Windows, query Get-NetIPAddress so multiple adapters are represented. The
    hostname resolver is a dependency-light fallback if PowerShell is unavailable.
    Public IP discovery is opt-in because it contacts an external service.
    """
    addresses: list[str] = []
    if is_windows():
        addresses = _windows_interface_addresses(timeout)
    if not addresses:
        try:
            host = socket.gethostname()
            addresses = [item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)]
        except OSError:
            addresses = []
    private_v4, private_v6 = _normalize_private_addresses(addresses)

    public_ip = ""
    public_checked = bool(include_public)
    public_error = "Public IP lookup has not been run. Click Refresh IP information to contact api.ipify.org." if not include_public else ""
    if include_public:
        request = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": f"RaiderDNS/{__version__}"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                candidate = response.read(128).decode("ascii", errors="ignore").strip()
            public_ip = str(ipaddress.ip_address(candidate))
        except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            public_error = f"Public IP lookup unavailable ({exc.__class__.__name__})."

    return {
        "private_ipv4": sorted(private_v4),
        "private_ipv6": sorted(private_v6),
        "public_ip": public_ip,
        "public_error": public_error,
        "public_checked": public_checked,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

