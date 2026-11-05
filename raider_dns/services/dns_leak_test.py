"""External recursive-resolver attribution test using dnsleak.dev's documented API.

This is opt-in and must be initiated by a user click. The service can observe
which recursive resolvers made the unique DNS queries and sees the public IP
of the test connection. The UI must disclose this before starting the test.
"""
from __future__ import annotations

import json
import re
import socket
import time
import urllib.request
from typing import Any

from raider_dns import __version__

from raider_dns.services.timeouts import EXTERNAL_DNS_LEAK_TEST_TIMEOUT_SECONDS

BASE_URL = "https://dnsleak.dev"
USER_AGENT = f"RaiderDNS/{__version__}"


def _get_json(path: str, timeout: float = EXTERNAL_DNS_LEAK_TEST_TIMEOUT_SECONDS) -> dict[str, Any]:
    request = urllib.request.Request(
        BASE_URL + path,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"DNS leak test service returned HTTP {response.status}.")
        payload = response.read(256 * 1024)
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("DNS leak test service returned an unexpected response format.")
    return data


def run_external_dns_leak_test() -> dict[str, Any]:
    """Resolve one-time test hostnames via this process's system resolver.

    The API contract asks callers to resolve every returned hostname and then
    retrieve the verdict. Resolution failures are expected for some test names;
    the DNS queries themselves are the measurement payload.
    """
    started = time.perf_counter()
    new_test = _get_json("/api/new")
    test_id = new_test.get("testId")
    hostnames = new_test.get("hostnames")
    if not isinstance(test_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", test_id) or not isinstance(hostnames, list) or not hostnames:
        raise RuntimeError("DNS leak test service did not return a valid test ID and hostname list.")
    if len(hostnames) > 32 or any(not isinstance(host, str) or not host.endswith(".t.dnsleak.dev") for host in hostnames):
        raise RuntimeError("DNS leak test service returned an invalid hostname list.")

    resolved_attempts = 0
    for host in hostnames:
        # Names ending in -q intentionally ask for AAAA; other names ask for A.
        family = socket.AF_INET6 if "-q" in host else socket.AF_INET
        try:
            socket.getaddrinfo(host, None, family, socket.SOCK_DGRAM)
        except (socket.gaierror, OSError, ValueError, UnicodeError):
            # A DNS error is expected for some one-time names; reaching the
            # authoritative nameserver is what the external service observes.
            pass
        resolved_attempts += 1

    # The authoritative side observes queries asynchronously. A brief pause is
    # part of the documented flow; avoid aggressive polling.
    time.sleep(1.0)
    report = _get_json("/api/result/" + test_id)
    verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
    client = report.get("client") if isinstance(report.get("client"), dict) else {}
    groups = report.get("groups") if isinstance(report.get("groups"), list) else []
    resolvers: list[dict[str, str]] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        resolvers.append({
            "label": str(group.get("label") or group.get("operator") or "Unknown resolver"),
            "city": str(group.get("city") or ""),
            "country": str(group.get("country") or ""),
            "status": str(group.get("status") or "unknown"),
        })
    status = str(verdict.get("status") or "inconclusive")
    if status not in {"no_leak", "split", "leak", "inconclusive"}:
        status = "inconclusive"
    return {
        "status": status,
        "headline": str(verdict.get("headline") or "DNS leak test completed"),
        "detail": str(verdict.get("detail") or "The test service did not return a detailed verdict."),
        "client_ip": str(client.get("ip") or "Not provided"),
        "client_location": ", ".join(part for part in (client.get("city"), client.get("country")) if part) or "Not provided",
        "client_network": str(client.get("org") or client.get("hostname") or "Not identified"),
        "lookups_seen": report.get("lookups", 0),
        "hostnames_attempted": resolved_attempts,
        "resolvers": resolvers,
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "test_id": test_id,
        "service": "dnsleak.dev",
    }
