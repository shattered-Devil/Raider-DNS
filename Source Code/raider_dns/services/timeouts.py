"""Central timeout policy for Raider DNS network probes and background work.

Timeouts are expressed in seconds. Individual operations may pass an explicit
shorter/longer timeout when their UX and failure mode require it.
"""

# UI/background scheduling
MAX_CONCURRENT_NETWORK_TASKS = 4

# Resolver probes
UDP_DNS_TIMEOUT_SECONDS = 3.0
TCP_DNS_TIMEOUT_SECONDS = 2.5
ICMP_TIMEOUT_SECONDS = 2.5
ICMP_PROCESS_GRACE_SECONDS = 1.5
DOH_TIMEOUT_SECONDS = 4.0
DOT_TIMEOUT_SECONDS = 4.0
BENCHMARK_PROBE_TIMEOUT_SECONDS = 1.25
BENCHMARK_ROUNDS = 3

# Local / external address discovery
NETWORK_INFO_TIMEOUT_SECONDS = 4.0
PUBLIC_IP_TIMEOUT_SECONDS = 4.0

# Windows command safety defaults. Destructive network repair actions continue
# to use explicit longer limits at the call sites and still require confirmation.
DEFAULT_COMMAND_TIMEOUT_SECONDS = 45
DNS_CACHE_FLUSH_TIMEOUT_SECONDS = 20
NETWORK_REPAIR_TIMEOUT_SECONDS = 90

# Windows DNS PowerShell operation limits.
WINDOWS_DOH_APPLY_TIMEOUT_SECONDS = 20
WINDOWS_DNS_CACHE_TIMEOUT_SECONDS = 10
WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS = 20
EXTERNAL_DNS_LEAK_TEST_TIMEOUT_SECONDS = 8.0
