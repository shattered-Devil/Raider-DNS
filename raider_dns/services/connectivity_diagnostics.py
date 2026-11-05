"""Bounded connectivity and adapter-health diagnostics for Raider DNS.

All probes are read-only. They run as one background job and return structured
results; this module never changes DNS, routes, drivers, proxy settings or leases.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from raider_dns import __version__


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _run_command(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=max(1, int(timeout)), check=False, creationflags=_creation_flags(),
    )


def _windows_network_facts(timeout: float = 8.0) -> dict[str, Any]:
    """Read only the link facts needed for connectivity diagnosis.

    Deliberately excludes Wi-Fi SSIDs, driver versions, CIM/PnP devices and
    hardware inventory. The returned adapter rows are used only to identify the
    selected link and its default route/address assignment.
    """
    if os.name != "nt":
        return {}
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$adapters = @(Get-NetAdapter | Select-Object @{Name='Name';Expression={$_.Name}}, @{Name='Status';Expression={$_.Status}}, @{Name='InterfaceIndex';Expression={$_.ifIndex}})
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Select-Object @{Name='NextHop';Expression={$_.NextHop}}, @{Name='InterfaceIndex';Expression={$_.ifIndex}}, @{Name='RouteMetric';Expression={$_.RouteMetric}})
$dhcp = @(Get-NetIPInterface -AddressFamily IPv4 | Select-Object @{Name='InterfaceAlias';Expression={$_.InterfaceAlias}}, @{Name='Dhcp';Expression={$_.Dhcp}})
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object @{Name='InterfaceAlias';Expression={$_.InterfaceAlias}}, @{Name='IPAddress';Expression={$_.IPAddress}})
[ordered]@{adapters=$adapters; routes=$routes; dhcp=$dhcp; addresses=$addresses} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        result = _run_command(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=max(1.0, timeout),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        parsed = json.loads(result.stdout)
        if not isinstance(parsed, dict):
            return {}
        return {
            "adapters": parsed.get("adapters", []) if isinstance(parsed.get("adapters"), list) else ([parsed["adapters"]] if isinstance(parsed.get("adapters"), dict) else []),
            "routes": parsed.get("routes", []) if isinstance(parsed.get("routes"), list) else ([parsed["routes"]] if isinstance(parsed.get("routes"), dict) else []),
            "dhcp": parsed.get("dhcp", []) if isinstance(parsed.get("dhcp"), list) else ([parsed["dhcp"]] if isinstance(parsed.get("dhcp"), dict) else []),
            "addresses": parsed.get("addresses", []) if isinstance(parsed.get("addresses"), list) else ([parsed["addresses"]] if isinstance(parsed.get("addresses"), dict) else []),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError, ValueError):
        return {}


def _ping(address: str, timeout: float = 1.5) -> tuple[bool, float | None, str]:
    if not address:
        return False, None, "No destination address is available."
    if os.name == "nt":
        args = ["ping.exe", "-n", "1", "-w", str(max(250, int(timeout * 1000))), address]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), address]
    started = time.perf_counter()
    try:
        result = _run_command(args, timeout + 1.5)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, None, f"Ping command unavailable: {exc.__class__.__name__}."
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    match = re.search(r"(?:time|zeit|temps|tiempo|tempo)\s*(?:=|<)\s*(\d+(?:[.,]\d+)?)\s*ms", text, re.I)
    measured = float(match.group(1).replace(",", ".")) if match else elapsed if result.returncode == 0 else None
    if result.returncode == 0:
        return True, measured, "ICMP echo reply received. Note: some networks block ping even when internet access works."
    return False, None, "No ICMP reply. This alone does not prove the network is offline."


def _tcp_connect(address: str, port: int, timeout: float = 2.0) -> tuple[bool, float | None, str]:
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True, round((time.perf_counter() - started) * 1000, 1), f"TCP connection to {address}:{port} succeeded."
    except (OSError, TimeoutError) as exc:
        return False, None, f"TCP connection to {address}:{port} failed ({exc.__class__.__name__})."


def _resolve_system(timeout: float = 4.0) -> tuple[bool, float | None, str]:
    """Resolve a short list of stable names with a hard process timeout on Windows.

    A direct socket.getaddrinfo call can hang in the Windows resolver and has no
    cancellation API. Using a short-lived PowerShell process means the caller can
    enforce a real deadline and continue using the bounded worker pool.
    """
    started = time.perf_counter()
    names = ("www.msftconnecttest.com", "example.com", "www.microsoft.com")
    if os.name == "nt":
        names_ps = ",".join("'" + name + "'" for name in names)
        script = (
            "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; "
            f"foreach ($name in @({names_ps})) {{ try {{ "
            "$answers = @(Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress }); "
            "if ($answers.Count -gt 0) { Write-Output ('DNS_OK=' + $name); exit 0 } "
            "} catch {} }; Write-Output 'DNS_FAIL'; exit 1"
        )
        try:
            result = _run_command(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                timeout=max(1.0, timeout),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if isinstance(exc, subprocess.TimeoutExpired):
                return False, None, f"System DNS resolution exceeded the {timeout:g}-second timeout."
            return False, None, f"System DNS check could not run ({exc.__class__.__name__})."
        match = re.search(r"(?m)^DNS_OK=([A-Za-z0-9.-]+)\s*$", result.stdout or "")
        if result.returncode == 0 and match:
            return True, round((time.perf_counter() - started) * 1000, 1), f"Windows/system resolver resolved {match.group(1)}."
        if isinstance(result.stderr, str) and "CLIXML" in result.stderr:
            detail = "Windows DNS resolution failed; PowerShell returned a structured error." 
        else:
            detail = f"Windows could not resolve the diagnostic hostnames within {timeout:g} seconds."
        return False, None, detail

    errors: list[str] = []
    for hostname in names:
        # Non-Windows use is for tests/development only; production diagnostics
        # run on Windows and use the bounded subprocess path above.
        try:
            answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            if answers:
                return True, round((time.perf_counter() - started) * 1000, 1), f"System resolver resolved {hostname}."
        except (socket.gaierror, OSError, TimeoutError) as exc:
            errors.append(f"{hostname}: {exc.__class__.__name__}")
    return False, None, "System DNS resolution failed for the diagnostic hostnames (" + "; ".join(errors[:3]) + ")."


def _https_connectivity(timeout: float = 4.0) -> tuple[bool, float | None, str]:
    """Test real HTTPS/TLS reachability; an HTTP status proves the TLS request reached a server."""
    urls = (
        "https://www.msftconnecttest.com/connecttest.txt",
        "https://www.cloudflare.com/cdn-cgi/trace",
    )
    errors: list[str] = []
    started = time.perf_counter()
    for url in urls:
        request = urllib.request.Request(url, headers={"User-Agent": f"RaiderDNS/{__version__}", "Connection": "close"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response.read(512)
                if 200 <= int(response.status) < 500:
                    return True, round((time.perf_counter() - started) * 1000, 1), f"HTTPS/TLS connection succeeded ({response.status})."
        except urllib.error.HTTPError as exc:
            # HTTP errors still prove DNS, TCP and TLS reached an HTTP server.
            return True, round((time.perf_counter() - started) * 1000, 1), f"HTTPS/TLS reached a server (HTTP {exc.code})."
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            errors.append(f"{urlparse_host(url)}: {exc.__class__.__name__}")
    return False, None, "HTTPS connectivity could not be verified: " + "; ".join(errors[:2])


def urlparse_host(url: str) -> str:
    # Avoid a separate URL-parser import for one tiny display-only helper.
    match = re.match(r"https?://([^/]+)", url, re.I)
    return match.group(1) if match else "endpoint"


def _check(check_id: str, title: str, status: str, measurement: str, details: str) -> dict[str, str]:
    return {"id": check_id, "title": title, "status": status, "measurement": measurement, "details": details}


def run_connectivity_checks(adapter: str | None = None, timeout: float = 2.0) -> dict[str, Any]:
    """Run bounded, read-only link, gateway, DNS and HTTPS probes."""
    facts = _windows_network_facts()
    adapters = facts.get("adapters", []) if isinstance(facts, dict) else []
    selected = next(
        (item for item in adapters if isinstance(item, dict) and str(item.get("Name", "")).casefold() == str(adapter or "").casefold()),
        None,
    )
    if selected is None:
        selected = next((item for item in adapters if isinstance(item, dict) and str(item.get("Status", "")).casefold() == "up"), None)
    selected_name = str(selected.get("Name", "")) if selected else str(adapter or "")
    adapter_status = str(selected.get("Status", "Unknown")) if selected else "Unknown"
    interface_index = selected.get("InterfaceIndex") if selected else None

    routes = facts.get("routes", []) if isinstance(facts, dict) else []
    route_candidates = [
        row for row in routes
        if isinstance(row, dict) and str(row.get("NextHop", "")).strip() not in {"", "0.0.0.0"}
    ]
    selected_routes = [
        row for row in route_candidates
        if interface_index is not None and str(row.get("InterfaceIndex")) == str(interface_index)
    ]
    route_pool = selected_routes or route_candidates
    route_pool.sort(key=lambda row: int(row.get("RouteMetric") or 999999))
    gateway = str(route_pool[0].get("NextHop", "")) if route_pool else ""

    dhcp_rows = facts.get("dhcp", []) if isinstance(facts, dict) else []
    dhcp_row = next(
        (row for row in dhcp_rows if isinstance(row, dict) and str(row.get("InterfaceAlias", "")).casefold() == selected_name.casefold()),
        None,
    )
    dhcp_enabled = str(dhcp_row.get("Dhcp", "")).casefold() == "enabled" if dhcp_row else False

    checks: list[dict[str, str]] = []
    if not facts:
        checks.append(_check("adapter_state", "Selected connection", "WARN", "Unavailable", "Windows link information could not be read."))
        checks.append(_check("default_gateway", "Default gateway", "WARN", "Unavailable", "Default-route discovery requires Windows network cmdlets."))
        checks.append(_check("address_assignment", "IPv4 address assignment", "WARN", "Unavailable", "Address assignment could not be read for the selected connection."))
    else:
        adapter_state_ok = adapter_status.casefold() == "up"
        checks.append(_check(
            "adapter_state", "Selected connection", "PASS" if adapter_state_ok else ("FAIL" if selected else "WARN"),
            adapter_status, "The selected network link is active." if adapter_state_ok else "The selected network link is not confirmed active.",
        ))
        checks.append(_check(
            "default_gateway", "Default gateway", "PASS" if gateway else "FAIL",
            gateway or "Not detected", "A default IPv4 route was found." if gateway else "No IPv4 default route was found.",
        ))
        address_rows = facts.get("addresses", []) if isinstance(facts, dict) else []
        selected_addresses = [
            str(row.get("IPAddress", "")) for row in address_rows
            if isinstance(row, dict) and str(row.get("InterfaceAlias", "")).casefold() == selected_name.casefold()
        ]
        usable_addresses = [
            address for address in selected_addresses
            if address and not address.startswith("169.254.") and address not in {"0.0.0.0", "127.0.0.1"}
        ]
        has_apipa = any(address.startswith("169.254.") for address in selected_addresses)
        address_detail = (
            "A preferred IPv4 address is assigned to the selected connection." if usable_addresses else
            ("Only a link-local IPv4 address was found; DHCP may not have supplied a usable lease." if has_apipa else
             "No usable preferred IPv4 address was found for the selected connection.")
        )
        checks.append(_check(
            "address_assignment", "IPv4 address assignment", "PASS" if usable_addresses else "FAIL",
            ", ".join(selected_addresses[:3]) or "Not detected", address_detail,
        ))

    gateway_ping = _ping(gateway, timeout) if gateway else (False, None, "No gateway to test.")
    checks.append(_check("gateway_ping", "Gateway reachability", "PASS" if gateway_ping[0] else ("WARN" if gateway else "SKIP"), f"{gateway_ping[1]} ms" if gateway_ping[1] is not None else "No reply", gateway_ping[2]))
    for address in ("1.1.1.1", "8.8.8.8"):
        result = _ping(address, timeout)
        checks.append(_check(f"ping_{address.replace('.', '_')}", f"External IP ping ({address})", "PASS" if result[0] else "WARN", f"{result[1]} ms" if result[1] is not None else "No reply", result[2]))
    tcp_443 = _tcp_connect("1.1.1.1", 443, timeout)
    checks.append(_check("tcp_external_443", "External TCP / 443", "PASS" if tcp_443[0] else "FAIL", f"{tcp_443[1]} ms" if tcp_443[1] is not None else "Failed", tcp_443[2]))
    tcp_53 = _tcp_connect("1.1.1.1", 53, timeout)
    checks.append(_check("tcp_dns_53", "External TCP / 53", "PASS" if tcp_53[0] else "WARN", f"{tcp_53[1]} ms" if tcp_53[1] is not None else "Failed", tcp_53[2]))
    dns = _resolve_system()
    checks.append(_check("dns_resolution", "System DNS resolution", "PASS" if dns[0] else "FAIL", f"{dns[1]} ms" if dns[1] is not None else "Failed", dns[2]))
    https = _https_connectivity()
    checks.append(_check("https_connectivity", "HTTPS / TLS connectivity", "PASS" if https[0] else "FAIL", f"{https[1]} ms" if https[1] is not None else "Failed", https[2]))

    passed = sum(1 for row in checks if row["status"] == "PASS")
    failed = sum(1 for row in checks if row["status"] == "FAIL")
    warnings = sum(1 for row in checks if row["status"] == "WARN")
    return {
        "checked_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "adapter": selected_name or adapter or "Unknown",
        "adapter_status": adapter_status,
        "gateway": gateway,
        "dhcp_enabled": dhcp_enabled,
        "checks": checks,
        "summary": {"passed": passed, "failed": failed, "warnings": warnings, "total": len(checks)},
    }


def suggest_repairs(report: dict[str, Any] | None) -> list[str]:
    """Suggest only limited, evidence-based repairs; never reset stacks automatically."""
    if not isinstance(report, dict):
        return []
    rows = report.get("checks", [])
    by_id = {str(row.get("id")): row for row in rows if isinstance(row, dict)} if isinstance(rows, list) else {}
    suggestions: list[str] = []
    dns = by_id.get("dns_resolution", {})
    https = by_id.get("https_connectivity", {})
    tcp = by_id.get("tcp_external_443", {})
    gateway = by_id.get("default_gateway", {})
    address_assignment = by_id.get("address_assignment", {})
    adapter_state = by_id.get("adapter_state", {})

    # If raw TCP/HTTPS works but system name resolution fails, flushing the cache
    # is a low-impact first action. Do not silently change the selected resolver.
    if dns.get("status") == "FAIL" and (tcp.get("status") == "PASS" or https.get("status") == "PASS"):
        suggestions.append("flush_dns")
    # Only recommend renewing DHCP when there is a gateway/addressing symptom and
    # the selected interface is actually configured for DHCP.
    if (
        report.get("dhcp_enabled") is True
        and adapter_state.get("status") == "PASS"
        # Do not renew DHCP merely because ICMP ping is blocked. Recommend it
        # only when there is concrete IP configuration evidence.
        and (gateway.get("status") == "FAIL" or address_assignment.get("status") == "FAIL")
        and "renew_ip" not in suggestions
    ):
        suggestions.append("renew_ip")
    return suggestions
