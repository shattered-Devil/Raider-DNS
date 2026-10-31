"""Small dependency-free DNS reachability probes for UDP/53 and DNS-over-HTTPS."""
from __future__ import annotations

import base64
import http.client
import math
import secrets
import socket
import statistics
import subprocess
import os
import re
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

from raider_dns.models import DNSProvider
from raider_dns.services.timeouts import (
    BENCHMARK_PROBE_TIMEOUT_SECONDS, BENCHMARK_ROUNDS, DOH_TIMEOUT_SECONDS,
    DOT_TIMEOUT_SECONDS, ICMP_PROCESS_GRACE_SECONDS, ICMP_TIMEOUT_SECONDS,
    TCP_DNS_TIMEOUT_SECONDS, UDP_DNS_TIMEOUT_SECONDS,
)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS client that connects to a resolver IP while validating the URL host.

    This preflight avoids changing Windows DNS before the DoH endpoint is proven
    reachable, and does not need the current system resolver to resolve the DoH
    host first. Certificate-chain and hostname validation remain enabled.
    """

    def __init__(self, hostname: str, address: str, port: int, timeout: float):
        self._target_address = address
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())

    def connect(self) -> None:
        sock = socket.create_connection((self._target_address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise



@dataclass(slots=True)
class ProbeResult:
    provider_id: str
    provider_name: str
    protocol: str
    success: bool
    latency_ms: float | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_dns_query(domain: str = "example.com", qtype: int = 1, transaction_id: int | None = None) -> bytes:
    """Build a minimal DNS query for an ASCII/IDNA domain name."""
    transaction_id = secrets.randbelow(65536) if transaction_id is None else transaction_id & 0xFFFF
    encoded_labels = []
    normalized = domain.rstrip(".")
    if not normalized:
        raise ValueError("Domain name cannot be empty")
    for label in normalized.split("."):
        label_bytes = label.encode("idna")
        if not label_bytes or len(label_bytes) > 63:
            raise ValueError("Invalid DNS label length")
        encoded_labels.append(bytes([len(label_bytes)]) + label_bytes)
    qname = b"".join(encoded_labels) + b"\x00"
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", qtype, 1)


def _valid_dns_response(payload: bytes, transaction_id: int) -> tuple[bool, str]:
    if len(payload) < 12:
        return False, "Resolver returned an incomplete DNS response."
    response_id, flags, _, _, _, _ = struct.unpack("!HHHHHH", payload[:12])
    if response_id != transaction_id:
        return False, "DNS response ID did not match the request."
    if not (flags & 0x8000):
        return False, "The response was not marked as a DNS response."
    rcode = flags & 0x000F
    if rcode == 0:
        return True, "DNS query succeeded."
    return False, {1: "DNS format error", 2: "Resolver server failure", 3: "Domain name not found", 4: "Query type not supported", 5: "Resolver refused the query"}.get(rcode, f"DNS resolver returned response code {rcode}.")


DNS_QUERY_TYPES: dict[str, int] = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2, "SOA": 6, "PTR": 12}


def probe_udp(
    provider: DNSProvider,
    timeout: float = UDP_DNS_TIMEOUT_SECONDS,
    domain: str = "example.com",
    qtype: int = 1,
) -> ProbeResult:
    transaction_id = secrets.randbelow(65536)
    query = build_dns_query(domain=domain, qtype=qtype, transaction_id=transaction_id)
    started = time.perf_counter()
    errors: list[str] = []
    for server in provider.servers:
        try:
            try:
                family = socket.AF_INET6 if __import__("ipaddress").ip_address(server).version == 6 else socket.AF_INET
            except ValueError:
                errors.append(f"{server}: Invalid resolver IP address")
                continue
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                destination = (server, 53, 0, 0) if family == socket.AF_INET6 else (server, 53)
                sock.sendto(query, destination)
                response, _ = sock.recvfrom(4096)
            okay, message = _valid_dns_response(response, transaction_id)
            latency = round((time.perf_counter() - started) * 1000, 1)
            if okay:
                return ProbeResult(provider.id, provider.name, "UDP / 53", True, latency, message)
            errors.append(f"{server}: {message}")
        except (OSError, TimeoutError) as exc:
            errors.append(f"{server}: {exc.__class__.__name__}")
    return ProbeResult(provider.id, provider.name, "UDP / 53", False, None, "; ".join(errors) or "No server responded.")


def probe_doh(
    provider: DNSProvider,
    timeout: float = DOH_TIMEOUT_SECONDS,
    domain: str = "example.com",
    qtype: int = 1,
) -> ProbeResult:
    if not provider.doh_url:
        return ProbeResult(provider.id, provider.name, "DoH", False, None, "This provider has no configured DoH endpoint in the catalogue.")
    transaction_id = secrets.randbelow(65536)
    query = build_dns_query(domain=domain, qtype=qtype, transaction_id=transaction_id)
    dns_parameter = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    separator = "&" if "?" in provider.doh_url else "?"
    url = provider.doh_url + separator + urllib.parse.urlencode({"dns": dns_parameter})
    request = urllib.request.Request(url, headers={"Accept": "application/dns-message", "User-Agent": "RaiderDNS/0.1.7"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(4096)
            if response.status != 200:
                return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS", False, None, f"HTTP status {response.status}")
        okay, message = _valid_dns_response(payload, transaction_id)
        latency = round((time.perf_counter() - started) * 1000, 1)
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS", okay, latency if okay else None, message)
    except urllib.error.HTTPError as exc:
        detail = f"HTTP {exc.code}"
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS", False, None, detail)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS", False, None, f"Connection failed: {exc.__class__.__name__}")



def probe_doh_endpoint(
    provider: DNSProvider,
    timeout: float = DOH_TIMEOUT_SECONDS,
    domain: str = "example.com",
    qtype: int = 1,
) -> ProbeResult:
    """Preflight a provider's actual DoH endpoint against its configured IP.

    This deliberately bypasses DNS resolution only for locating the endpoint
    IP. HTTPS still validates the endpoint hostname and its certificate; the
    response must contain a valid DNS message. It makes no system changes.
    """
    endpoint = (provider.doh_url or "").strip()
    if not endpoint:
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS preflight", False, None, "No DoH endpoint is configured.")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS preflight", False, None, "DoH endpoint must be a valid HTTPS URL.")
    try:
        port = parsed.port or 443
    except ValueError:
        return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS preflight", False, None, "DoH endpoint has an invalid port.")
    if port != 443:
        # Nonstandard ports are valid in some deployments, but system DoH
        # templates are provider-defined; allow their explicit TLS port.
        pass
    transaction_id = secrets.randbelow(65536)
    query = build_dns_query(domain=domain, qtype=qtype, transaction_id=transaction_id)
    dns_parameter = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [(key, value) for key, value in query_items if key.casefold() != "dns"]
    query_items.append(("dns", dns_parameter))
    target = urllib.parse.urlunsplit(("", "", parsed.path or "/dns-query", urllib.parse.urlencode(query_items), ""))
    errors: list[str] = []
    for server in provider.servers:
        started = time.perf_counter()
        conn: _PinnedHTTPSConnection | None = None
        try:
            # create_connection supports literal IPv4 and IPv6 addresses. No DNS
            # lookup is performed for the target resolver address.
            conn = _PinnedHTTPSConnection(parsed.hostname, server, port, timeout)
            conn.request("GET", target, headers={
                "Accept": "application/dns-message",
                "User-Agent": "RaiderDNS/0.1.7",
                "Connection": "close",
            })
            response = conn.getresponse()
            payload = response.read(4096)
            if response.status != 200:
                errors.append(f"{server}: HTTPS status {response.status}")
                continue
            okay, message = _valid_dns_response(payload, transaction_id)
            latency = round((time.perf_counter() - started) * 1000, 1)
            if okay:
                return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS preflight", True, latency, f"Authenticated HTTPS to {parsed.hostname} returned a valid DNS response.")
            errors.append(f"{server}: {message}")
        except (OSError, ssl.SSLError, TimeoutError, http.client.HTTPException, ValueError) as exc:
            errors.append(f"{server}: {exc.__class__.__name__}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
    return ProbeResult(provider.id, provider.name, "DNS-over-HTTPS preflight", False, None, "; ".join(errors) if errors else "No configured resolver endpoint responded.")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise OSError("Resolver closed the TLS connection before the response was complete.")
        chunks.extend(chunk)
    return bytes(chunks)


def probe_dot(provider: DNSProvider, timeout: float = DOT_TIMEOUT_SECONDS) -> ProbeResult:
    """Probe DNS-over-TLS on TCP/853 with certificate hostname validation."""
    if not provider.dot_hostname:
        return ProbeResult(provider.id, provider.name, "DNS-over-TLS", False, None, "This provider has no configured DoT hostname in the catalogue.")
    transaction_id = secrets.randbelow(65536)
    query = build_dns_query(transaction_id=transaction_id)
    framed_query = struct.pack("!H", len(query)) + query
    started = time.perf_counter()
    errors: list[str] = []
    context = ssl.create_default_context()
    for server in provider.servers:
        try:
            raw = socket.create_connection((server, 853), timeout=timeout)
            with raw:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=provider.dot_hostname) as tls_socket:
                    tls_socket.sendall(framed_query)
                    length = struct.unpack("!H", _recv_exact(tls_socket, 2))[0]
                    if length < 12 or length > 4096:
                        raise OSError("Resolver returned an invalid DNS-over-TLS message length.")
                    response = _recv_exact(tls_socket, length)
            okay, message = _valid_dns_response(response, transaction_id)
            latency = round((time.perf_counter() - started) * 1000, 1)
            if okay:
                return ProbeResult(provider.id, provider.name, "DNS-over-TLS", True, latency, message)
            errors.append(f"{server}: {message}")
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            errors.append(f"{server}: {exc.__class__.__name__}")
    return ProbeResult(provider.id, provider.name, "DNS-over-TLS", False, None, "; ".join(errors) or "No server responded.")


def probe_provider(provider: DNSProvider, protocol: str = "auto") -> ProbeResult:
    if protocol == "doh":
        return probe_doh(provider)
    if protocol == "udp":
        return probe_udp(provider)
    if protocol == "dot":
        return probe_dot(provider)
    if protocol == "tcp":
        return probe_tcp53(provider)
    if protocol == "icmp":
        return probe_icmp(provider)
    return probe_doh(provider) if provider.supports_doh else probe_udp(provider)


def probe_tcp53(provider: DNSProvider, timeout: float = TCP_DNS_TIMEOUT_SECONDS) -> ProbeResult:
    """Measure TCP connection availability to DNS port 53 (not a DNS query)."""
    errors: list[str] = []
    for server in provider.servers:
        started = time.perf_counter()
        try:
            with socket.create_connection((server, 53), timeout=timeout):
                latency = round((time.perf_counter() - started) * 1000, 1)
            return ProbeResult(provider.id, provider.name, "TCP / 53", True, latency, "TCP connection to DNS port 53 succeeded.")
        except (OSError, TimeoutError) as exc:
            errors.append(f"{server}: {exc.__class__.__name__}")
    return ProbeResult(provider.id, provider.name, "TCP / 53", False, None, "; ".join(errors) or "No server responded.")


def parse_icmp_reply_latency(output: str) -> float | None:
    """Parse common localized ping reply fields (for example ``time=12ms``)."""
    match = re.search(r"(?:time|zeit|temps|tiempo|tempo)\s*(?:=|<)\s*(\d+(?:[.,]\d+)?)\s*ms", output, re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1).replace(",", "."))
    except ValueError:
        return None


def probe_icmp(provider: DNSProvider, timeout: float = ICMP_TIMEOUT_SECONDS) -> ProbeResult:
    """Optional ICMP ping measured from native reply RTT where it can be parsed."""
    if not provider.servers:
        return ProbeResult(provider.id, provider.name, "ICMP ping", False, None, "No DNS server address is configured.")
    server = provider.servers[0]
    if os.name == "nt":
        command = ["ping.exe", "-n", "1", "-w", str(max(250, int(timeout * 1000))), server]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), server]
    started = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + ICMP_PROCESS_GRACE_SECONDS, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        if result.returncode == 0:
            reply_latency = parse_icmp_reply_latency(result.stdout or "")
            if reply_latency is not None:
                return ProbeResult(provider.id, provider.name, "ICMP ping", True, reply_latency, "Ping reply RTT parsed from the response.")
            return ProbeResult(provider.id, provider.name, "ICMP ping", True, elapsed_ms, "Ping succeeded, but reply RTT was not parseable; using ping-command elapsed time.")
        detail = (result.stderr or result.stdout).strip().splitlines()
        return ProbeResult(provider.id, provider.name, "ICMP ping", False, None, detail[-1][:160] if detail else "Ping timed out or was blocked.")
    except (OSError, subprocess.SubprocessError) as exc:
        return ProbeResult(provider.id, provider.name, "ICMP ping", False, None, f"Ping unavailable: {exc.__class__.__name__}")


def benchmark_provider(provider: DNSProvider, rounds: int = BENCHMARK_ROUNDS, timeout: float = UDP_DNS_TIMEOUT_SECONDS) -> dict[str, object]:
    """Repeated real DNS queries; report median latency and successful-query ratio."""
    rounds = max(1, min(int(rounds), 7))
    samples: list[float] = []
    errors: list[str] = []
    for _ in range(rounds):
        result = probe_udp(provider, timeout=timeout)
        if result.success and result.latency_ms is not None:
            samples.append(result.latency_ms)
        else:
            errors.append(result.message)
    return {
        "provider_id": provider.id, "provider_name": provider.name,
        "rounds": rounds, "successes": len(samples),
        "success_rate": round(len(samples) / rounds * 100, 1),
        "median_ms": round(statistics.median(samples), 1) if samples else None,
        "min_ms": round(min(samples), 1) if samples else None,
        "samples_ms": samples,
        "message": "Repeated DNS queries succeeded." if samples else (errors[0] if errors else "No successful DNS queries."),
    }


def benchmark_provider_metrics(
    provider: DNSProvider,
    rounds: int = BENCHMARK_ROUNDS,
    timeout: float = BENCHMARK_PROBE_TIMEOUT_SECONDS,
    measurements: tuple[str, ...] | list[str] = ("median", "tcp", "query"),
    domain: str = "example.com",
    query_type: int = 1,
) -> dict[str, object]:
    """Measure selected ICMP, TCP/53, and actual DNS-query latency metrics.

    ``median`` represents the ICMP ping measurement, ``tcp`` is the time to
    establish a TCP connection to port 53, and ``query`` is a real UDP DNS
    query/response. Each metric is measured independently and receives its own
    median and success rate; unavailable measurements remain ``None``.
    """
    rounds = max(1, min(int(rounds), 10))
    allowed = {"median", "tcp", "query"}
    selected = tuple(dict.fromkeys(item for item in measurements if item in allowed))
    probe_by_metric = {
        "median": probe_icmp,
        "tcp": probe_tcp53,
        "query": lambda target, timeout: probe_udp(target, timeout=timeout, domain=domain, qtype=query_type),
    }
    result: dict[str, object] = {
        "provider_id": provider.id, "provider_name": provider.name, "rounds": rounds,
        "measurements": list(selected), "message": "", "query_domain": domain, "query_type": query_type,
    }
    labels = {"median": "median_ms", "tcp": "tcp_median_ms", "query": "query_median_ms"}
    for metric in allowed:
        key = labels[metric]
        result[key] = None
        result[f"{metric}_successes"] = 0
        result[f"{metric}_success_rate"] = 0.0
        result[f"{metric}_samples_ms"] = []
        result[f"{metric}_min_ms"] = None
        result[f"{metric}_max_ms"] = None
        result[f"{metric}_p95_ms"] = None
        result[f"{metric}_jitter_ms"] = None

    if not selected:
        result["message"] = "No measurements were selected."
        return result

    messages: list[str] = []
    for metric in selected:
        samples: list[float] = []
        errors: list[str] = []
        probe = probe_by_metric[metric]
        for _ in range(rounds):
            try:
                measured = probe(provider, timeout=timeout)
            except Exception as exc:  # isolate one failed measurement from other probes
                errors.append(exc.__class__.__name__)
                continue
            if measured.success and measured.latency_ms is not None:
                samples.append(float(measured.latency_ms))
            else:
                errors.append(measured.message or "Probe failed")
        result[labels[metric]] = round(statistics.median(samples), 1) if samples else None
        result[f"{metric}_successes"] = len(samples)
        result[f"{metric}_success_rate"] = round(len(samples) / rounds * 100, 1)
        result[f"{metric}_samples_ms"] = samples
        if samples:
            sorted_samples = sorted(samples)
            p95_index = max(0, min(len(sorted_samples) - 1, int(math.ceil(0.95 * len(sorted_samples))) - 1))
            result[f"{metric}_min_ms"] = round(min(samples), 1)
            result[f"{metric}_max_ms"] = round(max(samples), 1)
            result[f"{metric}_p95_ms"] = round(sorted_samples[p95_index], 1)
            adjacent_deltas = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
            result[f"{metric}_jitter_ms"] = round(statistics.median(adjacent_deltas), 1) if adjacent_deltas else None
        if not samples:
            messages.append(f"{metric}: {errors[0] if errors else 'no response'}")

    query_rate = result.get("query_success_rate", 0.0)
    result["successes"] = result.get("query_successes", 0)
    result["success_rate"] = query_rate
    result["message"] = "All selected probes completed." if not messages else "; ".join(messages)[:500]
    return result


def rank_benchmark_results(
    results: list[dict[str, object]], metric: str = "query", ascending: bool = True
) -> list[dict[str, object]]:
    """Rank benchmark rows by one metric and leave missing measurements at the end."""
    fields = {"median": "median_ms", "tcp": "tcp_median_ms", "query": "query_median_ms"}
    rates = {"median": "median_success_rate", "tcp": "tcp_success_rate", "query": "query_success_rate"}
    metric = metric if metric in fields else "query"
    field = fields[metric]
    rate_field = rates[metric]
    measured = [row for row in results if row.get(field) is not None]
    unmeasured = [row for row in results if row.get(field) is None]
    measured.sort(
        key=lambda row: (
            float(row[field]) if ascending else -float(row[field]),
            -float(row.get(rate_field, 0.0) or 0.0),
            str(row.get("provider_name", "")).casefold(),
        )
    )
    unmeasured.sort(key=lambda row: str(row.get("provider_name", "")).casefold())
    return measured + unmeasured
