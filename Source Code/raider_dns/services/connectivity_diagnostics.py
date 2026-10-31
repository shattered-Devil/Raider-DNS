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


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _run_command(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=max(1, int(timeout)), check=False, creationflags=_creation_flags(),
    )


def _windows_network_facts(timeout: float = 8.0) -> dict[str, Any]:
    """Read adapter, default-route, DHCP and PnP network-device status once."""
    if os.name != "nt":
        return {}
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,Status,InterfaceIndex,LinkSpeed)
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object NextHop,InterfaceIndex,RouteMetric)
$drivers = @(Get-PnpDevice -Class Net -PresentOnly -ErrorAction SilentlyContinue | Select-Object FriendlyName,Status,Problem)
$dhcp = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,Dhcp)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object InterfaceAlias,IPAddress,PrefixOrigin)
@{adapters=$adapters;routes=$routes;drivers=$drivers;dhcp=$dhcp;addresses=$addresses} | ConvertTo-Json -Depth 5 -Compress
"""
    try:
        completed = _run_command(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            timeout,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return {}
        payload = json.loads(completed.stdout.strip())
        if not isinstance(payload, dict):
            return {}
        for key in ("adapters", "routes", "drivers", "dhcp", "addresses"):
            value = payload.get(key, [])
            if isinstance(value, dict):
                payload[key] = [value]
            elif not isinstance(value, list):
                payload[key] = []
        return payload
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
        request = urllib.request.Request(url, headers={"User-Agent": "RaiderDNS/0.1.7", "Connection": "close"})
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
    """Run bounded, read-only connectivity probes and return a structured report."""
    facts = _windows_network_facts()
    adapters = facts.get("adapters", []) if isinstance(facts, dict) else []
    selected = next((item for item in adapters if isinstance(item, dict) and str(item.get("Name", "")).casefold() == str(adapter or "").casefold()), None)
    if selected is None:
        selected = next((item for item in adapters if isinstance(item, dict) and str(item.get("Status", "")).casefold() == "up"), None)
    selected_name = str(selected.get("Name", "")) if selected else str(adapter or "")
    adapter_status = str(selected.get("Status", "Unknown")) if selected else "Unknown"
    interface_index = selected.get("InterfaceIndex") if selected else None

    routes = facts.get("routes", []) if isinstance(facts, dict) else []
    route_candidates = [r for r in routes if isinstance(r, dict) and str(r.get("NextHop", "")).strip() and str(r.get("NextHop", "")).strip() != "0.0.0.0"]
    selected_routes = [r for r in route_candidates if interface_index is not None and str(r.get("InterfaceIndex")) == str(interface_index)]
    route_pool = selected_routes or route_candidates
    route_pool.sort(key=lambda r: int(r.get("RouteMetric") or 999999))
    gateway = str(route_pool[0].get("NextHop", "")) if route_pool else ""

    dhcp_rows = facts.get("dhcp", []) if isinstance(facts, dict) else []
    dhcp_row = next((r for r in dhcp_rows if isinstance(r, dict) and str(r.get("InterfaceAlias", "")).casefold() == selected_name.casefold()), None)
    dhcp_enabled = str(dhcp_row.get("Dhcp", "")).casefold() == "enabled" if dhcp_row else False
    drivers = facts.get("drivers", []) if isinstance(facts, dict) else []
    driver_problem_list = []
    for item in drivers:
        if not isinstance(item, dict):
            continue
        problem = item.get("Problem")
        status_value = str(item.get("Status", "")).casefold()
        try:
            problem_code = int(problem or 0)
        except (ValueError, TypeError):
            problem_code = 0
        if problem_code > 0 or (status_value and status_value not in {"ok", "unknown"}):
            driver_problem_list.append(f"{item.get('FriendlyName', 'Network device')} (status {item.get('Status', 'unknown')}, problem {problem_code})")

    checks: list[dict[str, str]] = []
    if not facts:
        checks.append(_check("adapter_state", "Adapter status", "WARN", "Unavailable", "Could not read Windows adapter facts. This check requires Windows networking cmdlets."))
        checks.append(_check("driver_state", "Network driver status", "WARN", "Unavailable", "Driver/PnP state could not be inspected."))
        checks.append(_check("default_gateway", "Default gateway", "WARN", "Unavailable", "Default-route discovery requires Windows network cmdlets."))
    else:
        adapter_state_ok = adapter_status.casefold() == "up"
        checks.append(_check("adapter_state", f"Adapter status ({selected_name or 'selected adapter'})", "PASS" if adapter_state_ok else ("FAIL" if selected else "WARN"), adapter_status, "Adapter is reported up." if adapter_state_ok else "Adapter is not confirmed up. Check Wi-Fi/Ethernet state and driver status."))
        if driver_problem_list:
            checks.append(_check("driver_state", "Network driver / device state", "FAIL", f"{len(driver_problem_list)} issue(s)", "; ".join(driver_problem_list[:5])))
        elif drivers:
            checks.append(_check("driver_state", "Network driver / device state", "PASS", f"{len(drivers)} device(s) inspected", "Present network-class devices report OK. This is a status check, not a full driver diagnostic."))
        else:
            checks.append(_check("driver_state", "Network driver / device state", "WARN", "Unavailable", "Windows returned no present network-class devices."))
        checks.append(_check("default_gateway", "Default gateway", "PASS" if gateway else "FAIL", gateway or "Not detected", "Default IPv4 route was found." if gateway else "No IPv4 default route was found. Check the adapter's IP configuration."))
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
        address_ok = bool(usable_addresses)
        address_detail = (
            "A preferred IPv4 address is assigned to the selected adapter."
            if address_ok else
            ("Only an automatic private link-local (169.254.x.x) address was found; DHCP may not have provided a usable lease."
             if has_apipa else "No usable preferred IPv4 address was found on the selected adapter.")
        )
        checks.append(_check("address_assignment", "IPv4 address assignment", "PASS" if address_ok else "FAIL", ", ".join(selected_addresses[:3]) or "Not detected", address_detail))

    gateway_ping = _ping(gateway, timeout) if gateway else (False, None, "No gateway to test.")
    checks.append(_check("gateway_ping", "Internal gateway ping", "PASS" if gateway_ping[0] else ("WARN" if gateway else "SKIP"), f"{gateway_ping[1]} ms" if gateway_ping[1] is not None else "No reply", gateway_ping[2]))
    public_ping_results = []
    for address in ("1.1.1.1", "8.8.8.8"):
        result = _ping(address, timeout)
        public_ping_results.append(result)
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
    driver = by_id.get("driver_state", {})

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
    # Driver problems require user-visible manual/Device Manager action, not an
    # automated driver reset or reinstall that could disconnect the PC.
    if driver.get("status") == "FAIL" and not suggestions:
        return []
    return suggestions
