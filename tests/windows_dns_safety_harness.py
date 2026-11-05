"""Opt-in live DNS-mode integration test for a disposable Windows VM.

WARNING: this script changes the selected adapter's DNS settings and Windows
DoT global setting. It refuses to run unless explicitly enabled and restores
the captured adapter DNS plus the touched DoH/DoT registrations in a finally
block. Run only in a snapshot-backed disposable Windows VM with console access.
A sudden power loss can still interrupt any OS-level repair operation.

Required environment variables:
  RAIDERDNS_ENABLE_LIVE_DNS_TESTS=YES_I_AM_USING_A_DISPOSABLE_WINDOWS_VM
  RAIDERDNS_TEST_ADAPTER=<dedicated test adapter name>
  RAIDERDNS_TEST_DNSCRYPT_EXE=<path to trusted dnscrypt-proxy.exe>
  RAIDERDNS_TEST_DNSCRYPT_CONFIG=<path to an already validated DNSCrypt config>
Optional:
  RAIDERDNS_TEST_DNS_SERVERS=1.1.1.1,1.0.0.1
  RAIDERDNS_TEST_DOH_TEMPLATE=https://cloudflare-dns.com/dns-query
  RAIDERDNS_TEST_DOT_HOST=one.one.one.one

Run from the project root:
  python tests/windows_dns_safety_harness.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Support direct invocation as `python tests/windows_dns_safety_harness.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from raider_dns.services.dns_system import WindowsDNSService
from raider_dns.services.dnscrypt_proxy import DNSCryptProxyController

ACK_VALUE = "YES_I_AM_USING_A_DISPOSABLE_WINDOWS_VM"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def run() -> int:
    if os.name != "nt":
        print("REFUSED: live DNS-mode tests can run only on Windows.", file=sys.stderr)
        return 2
    if os.environ.get("RAIDERDNS_ENABLE_LIVE_DNS_TESTS", "") != ACK_VALUE:
        print("REFUSED: set RAIDERDNS_ENABLE_LIVE_DNS_TESTS=" + ACK_VALUE + " only inside a disposable Windows VM.", file=sys.stderr)
        return 2

    service = WindowsDNSService()
    if not service.is_admin():
        print("REFUSED: run an elevated terminal inside the disposable VM.", file=sys.stderr)
        return 2

    adapter = require_env("RAIDERDNS_TEST_ADAPTER")
    servers = [x.strip() for x in os.environ.get("RAIDERDNS_TEST_DNS_SERVERS", "1.1.1.1,1.0.0.1").split(",") if x.strip()]
    if not servers:
        raise RuntimeError("RAIDERDNS_TEST_DNS_SERVERS did not contain any addresses")
    doh_template = os.environ.get("RAIDERDNS_TEST_DOH_TEMPLATE", "https://cloudflare-dns.com/dns-query").strip()
    dot_host = os.environ.get("RAIDERDNS_TEST_DOT_HOST", "one.one.one.one").strip()
    dnscrypt_exe = Path(require_env("RAIDERDNS_TEST_DNSCRYPT_EXE")).resolve()
    dnscrypt_config = Path(require_env("RAIDERDNS_TEST_DNSCRYPT_CONFIG")).resolve()

    if adapter not in service.get_adapters():
        print(f"REFUSED: adapter {adapter!r} is not active; no settings were changed.", file=sys.stderr)
        return 2
    if not dnscrypt_exe.is_file() or not dnscrypt_config.is_file():
        print("REFUSED: DNSCrypt executable/config was not found; no settings were changed.", file=sys.stderr)
        return 2

    original, capture_error = service._capture_adapter_snapshot(adapter, include_dot=True, require_doh_inventory=True)
    if original is None:
        print("REFUSED: a complete recovery snapshot could not be captured; no settings were changed. " + capture_error, file=sys.stderr)
        return 2
    effective = [
        str(address).strip()
        for family in original.get("families", {}).values() if isinstance(family, dict)
        for address in family.get("effective", [])
    ]
    if any(address in {"127.0.0.1", "::1"} for address in effective):
        print("REFUSED: selected adapter already uses loopback DNS; choose a clean test adapter to avoid breaking an existing local resolver.", file=sys.stderr)
        return 2

    # Include provider addresses changed during the run and any prior registration
    # at those addresses. Unrelated adapter registrations are not touched.
    touched_servers = sorted(set(servers))
    doh_servers = touched_servers
    dot_servers = touched_servers
    results: list[tuple[str, bool, str]] = []
    controller = DNSCryptProxyController(dnscrypt_exe, dnscrypt_config)
    existing_matching_pid = controller._find_matching_process_id(dnscrypt_exe, dnscrypt_config)
    proxy_started_by_harness = False
    restore_ok = False
    restore_detail = "Restoration was not attempted."

    def record(name: str, result) -> bool:
        okay = bool(getattr(result, "success", False)) and getattr(result, "verified", None) is True
        message = str(getattr(result, "message", "operation returned no message"))
        detail = str(getattr(result, "details", ""))
        results.append((name, okay, f"{message}: {detail}".strip(": ")))
        print(("PASS" if okay else "FAIL") + f" [{name}] {message}: {detail}".rstrip())
        if not getattr(result, "success", False) and getattr(result, "rollback_attempted", False) and getattr(result, "rollback_succeeded", False) is not True:
            raise RuntimeError(f"{name} failed and automatic rollback was not confirmed; aborting further mutations")
        return okay

    try:
        record("Standard DNS", service.apply_dns(adapter, servers, None))
        record("Windows DoH", service.apply_dns(adapter, servers, doh_template))
        record("Windows native DoT", service.apply_dot(adapter, servers, dot_host))

        start_result = controller.start(dnscrypt_exe, dnscrypt_config)
        proxy_started_by_harness = bool(start_result.success and existing_matching_pid is None)
        if not start_result.success:
            results.append(("DNSCrypt startup", False, f"{start_result.message}: {start_result.details}".strip(": ")))
            print(f"FAIL [DNSCrypt startup] {start_result.message}: {start_result.details}")
        else:
            record("DNSCrypt local proxy", service.apply_dnscrypt_loopback(adapter))
    except Exception as exc:
        print(f"ABORTED: {exc}", file=sys.stderr)
        results.append(("Harness", False, str(exc)))
    finally:
        # The final restoration uses the same cross-process mutex as app changes.
        with service._system_dns_mutex() as locked:
            if not locked:
                restore_ok = False
                restore_detail = "DNS mutex could not be acquired for final restore. Keep the VM powered on and use the app's recovery action."
            else:
                try:
                    restore_ok, restore_detail, _ = service._restore_snapshot(
                        adapter, original, doh_servers=doh_servers, dot_servers=dot_servers,
                        restore_dot_global=True,
                    )
                    if restore_ok:
                        connectivity_ok, connectivity_detail = service.verify_dns_and_https()
                        if not connectivity_ok:
                            restore_ok = False
                            restore_detail += (
                                " Original adapter configuration was read back, but DNS/HTTPS connectivity "
                                "could not be verified after restoration; recovery metadata was retained. "
                                + connectivity_detail
                            )
                        else:
                            restore_detail += " " + connectivity_detail
                            try:
                                service.recovery_store.clear(adapter)
                            except Exception as exc:
                                restore_ok = False
                                restore_detail += f" Recovery metadata cleanup failed: {exc}"
                except Exception as exc:
                    restore_ok = False
                    restore_detail = f"Restore raised {exc.__class__.__name__}: {exc}"
        print(("PASS" if restore_ok else "CRITICAL") + f" [Restore original DNS configuration] {restore_detail}")
        if restore_ok and proxy_started_by_harness:
            stop_result = controller.stop()
            stop_ok = bool(stop_result.success)
            results.append(("Stop test DNSCrypt proxy", stop_ok, f"{stop_result.message}: {stop_result.details}".strip(": ")))
            print(("PASS" if stop_ok else "WARNING") + f" [Stop test DNSCrypt proxy] {stop_result.message}: {stop_result.details}".rstrip())
        elif not restore_ok:
            print("CRITICAL: the DNSCrypt process was deliberately left running because DNS restoration did not verify. It may still be needed if the adapter uses loopback DNS.", file=sys.stderr)

    print("\nMode test summary:")
    for name, okay, detail in results:
        print(f"  {'PASS' if okay else 'FAIL'}  {name}: {detail}")
    if not restore_ok:
        return 3
    return 1 if any(not result[1] for result in results) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except RuntimeError as exc:
        print(f"REFUSED/FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
