"""Bounded DNS warm-cache and unique-name resolver benchmarking.

Cold samples accept valid NXDOMAIN replies as successful DNS transport: the
benchmark is measuring response timing, not whether a random name exists.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import statistics
import struct
import time
from typing import Any

from raider_dns.models import DNSProvider
from raider_dns.services.dns_probe import build_dns_query, probe_udp


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((percentile / 100.0) * len(ordered) + 0.999999) - 1))
    return round(ordered[index], 2)


def _stats(values: list[float], successes: int, total: int) -> dict[str, Any]:
    return {
        "median_ms": round(statistics.median(values), 2) if values else None,
        "p95_ms": _percentile(values, 95),
        "min_ms": round(min(values), 2) if values else None,
        "max_ms": round(max(values), 2) if values else None,
        "jitter_ms": round(statistics.median([abs(b - a) for a, b in zip(values, values[1:])]), 2) if len(values) > 1 else None,
        "success_rate": round((successes / max(1, total)) * 100.0, 1),
        "successes": successes,
        "total": total,
    }


def _probe_dns_response(provider: DNSProvider, domain: str, timeout: float) -> tuple[bool, float | None, str]:
    """Probe UDP DNS and accept NOERROR or NXDOMAIN as a valid DNS reply."""
    if not provider.servers:
        return False, None, "Provider has no resolver addresses."
    transaction_id = secrets.randbelow(65536)
    query = build_dns_query(domain=domain, qtype=1, transaction_id=transaction_id)
    errors: list[str] = []
    for server in provider.servers[:2]:
        started = time.perf_counter()
        try:
            address = ipaddress.ip_address(server)
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(max(0.25, min(8.0, float(timeout))))
                destination = (str(address), 53, 0, 0) if family == socket.AF_INET6 else (str(address), 53)
                sock.sendto(query, destination)
                response, _ = sock.recvfrom(4096)
            latency = round((time.perf_counter() - started) * 1000.0, 2)
            if len(response) < 12:
                errors.append(f"{server}: truncated DNS header")
                continue
            response_id, flags = struct.unpack("!HH", response[:4])
            if response_id != transaction_id or not (flags & 0x8000):
                errors.append(f"{server}: mismatched/non-response packet")
                continue
            if flags & 0x0200:
                errors.append(f"{server}: truncated UDP DNS response")
                continue
            rcode = flags & 0x000F
            if rcode in (0, 3):
                return True, latency, "DNS response received (NXDOMAIN is valid for an uncached unique-name probe)." if rcode == 3 else "DNS response received."
            errors.append(f"{server}: DNS RCODE {rcode}")
        except (OSError, ValueError, TimeoutError) as exc:
            errors.append(f"{server}: {exc.__class__.__name__}")
    return False, None, "; ".join(errors[:2]) or "No resolver response."


def run_advanced_benchmark(
    provider: DNSProvider,
    *,
    domain: str = "example.com",
    rounds: int = 5,
    timeout: float = 2.0,
) -> dict[str, Any]:
    """Compare repeated same-name queries with unique-name uncached queries.

    Maximum 10 rounds, at most two resolver addresses per sample. The function
    is intended to be called through Raider DNS's bounded background pool.
    """
    normalized_domain = str(domain or "example.com").strip().rstrip(".")
    # Validate name and reject unsafe query targets before opening sockets.
    build_dns_query(normalized_domain, qtype=1)
    sample_count = max(3, min(10, int(rounds)))
    timeout_value = max(0.25, min(8.0, float(timeout)))

    warm_values: list[float] = []
    cold_values: list[float] = []
    warm_success = 0
    cold_success = 0
    warm_errors: list[str] = []
    cold_errors: list[str] = []

    # Prime the resolver cache once without including this cold-up query in the
    # warm statistics. Without this step the first "warm" sample is actually cold.
    warmup = probe_udp(provider, timeout=timeout_value, domain=normalized_domain, qtype=1)
    if not warmup.success:
        warm_errors.append("Warm-up query did not succeed; the first measured sample may still be cold.")

    for _ in range(sample_count):
        result = probe_udp(provider, timeout=timeout_value, domain=normalized_domain, qtype=1)
        if result.success and result.latency_ms is not None:
            warm_success += 1
            warm_values.append(float(result.latency_ms))
        else:
            warm_errors.append(result.message[:120])

    for _ in range(sample_count):
        label = secrets.token_hex(6)
        unique_name = f"{label}.{normalized_domain}"
        okay, latency, message = _probe_dns_response(provider, unique_name, timeout_value)
        if okay and latency is not None:
            cold_success += 1
            cold_values.append(latency)
        else:
            cold_errors.append(message[:120])

    return {
        "provider_id": provider.id,
        "provider_name": provider.name,
        "domain": normalized_domain,
        "rounds": sample_count,
        "timeout_seconds": timeout_value,
        "warm": _stats(warm_values, warm_success, sample_count),
        "uncached": _stats(cold_values, cold_success, sample_count),
        "errors": {"warm": warm_errors[:3], "uncached": cold_errors[:3]},
        "note": "Warm samples repeat the selected hostname. Uncached samples use unique subdomains; valid NXDOMAIN responses count as successful transport responses.",
    }
