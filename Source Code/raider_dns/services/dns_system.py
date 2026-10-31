"""Windows DNS configuration integration.

System DNS modification is deliberately limited to Windows and requires an
administrator-elevated process. This module never silently claims a change
succeeded: PowerShell/netsh errors are returned to the UI.
"""
from __future__ import annotations

import base64
import ctypes
from contextlib import contextmanager
import ipaddress
import json
import os
import re
import subprocess
import threading
import html
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Callable
from datetime import datetime, timezone
from raider_dns.services.dns_recovery import DNSRecoveryStore
from raider_dns.services.timeouts import WINDOWS_DNS_CACHE_TIMEOUT_SECONDS, WINDOWS_DOH_APPLY_TIMEOUT_SECONDS, WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS


@dataclass(slots=True)
class DNSOperationResult:
    success: bool
    message: str
    details: str = ""
    # None means the result predates the verification-aware flow or was not verified.
    verified: bool | None = None
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    templates_registered: bool | None = None


class WindowsDNSService:
    @staticmethod
    def is_windows() -> bool:
        return os.name == "nt"

    @classmethod
    def is_admin(cls) -> bool:
        if not cls.is_windows():
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    @staticmethod
    def _quote_ps(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _friendly_command_error(raw: str, fallback: str = "Windows did not confirm the operation.") -> str:
        """Turn PowerShell's redirected CLIXML errors into concise user-facing text."""
        value = (raw or "").strip()
        if not value:
            return fallback
        if "CLIXML" in value and "<Objs" in value:
            try:
                xml_start = value.find("<Objs")
                root = ET.fromstring(value[xml_start:])
                messages: list[str] = []
                for node in root.iter():
                    if node.tag.rsplit("}", 1)[-1] == "S" and node.attrib.get("S") == "Error" and node.text:
                        message = html.unescape(node.text).strip()
                        # PS error records can embed a giant object dump after the
                        # actionable message. Keep the first useful sentence only.
                        message = re.split(r"\s+At line:\s*\d+|\s+CategoryInfo\s*:", message, maxsplit=1, flags=re.I)[0].strip()
                        if message and message not in messages:
                            messages.append(message)
                if messages:
                    return " ".join(messages)[:900]
            except (ET.ParseError, ValueError):
                pass
        # Never display serialized XML or PowerShell stack dumps in dialogs.
        value = re.sub(r"#<\s*CLIXML", "", value, flags=re.I)
        value = re.sub(r"<[^>]+>", " ", value)
        value = html.unescape(value)
        value = re.sub(r"\s+", " ", value).strip()
        return (value or fallback)[:900]

    @staticmethod
    def _run_powershell(script: str, timeout: int = WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def get_adapters(self) -> list[str]:
        if not self.is_windows():
            return []
        script = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
        try:
            result = self._run_powershell(script)
            if result.returncode != 0:
                return []
            output = result.stdout.strip()
            if not output:
                return []
            data = json.loads(output)
            if isinstance(data, str):
                return [data]
            if isinstance(data, list):
                return [str(item) for item in data if isinstance(item, str)]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []
        return []

    def get_all_adapters(self) -> list[str]:
        """Return installed adapter names, including disconnected adapters.

        Recovery must still be possible after Wi-Fi or Ethernet disconnects.
        Apply operations use get_adapters() and remain restricted to active NICs.
        """
        if not self.is_windows():
            return []
        script = "Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
        try:
            result = self._run_powershell(script)
            if result.returncode != 0 or not result.stdout.strip():
                return []
            data = json.loads(result.stdout.strip())
            values = [data] if isinstance(data, str) else data if isinstance(data, list) else []
            return list(dict.fromkeys(str(item) for item in values if isinstance(item, str) and item.strip()))
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []

    @contextmanager
    def _system_dns_mutex(self):
        """Serialize DNS mutations across Raider DNS processes on Windows.

        A named kernel mutex protects against two app instances applying DNS at
        the same time. Failure to acquire it is a hard precondition failure: no
        system mutation should start without the cross-process lock.
        """
        # Unit tests and non-Windows preview mode need no Win32 mutex.
        if os.name != "nt":
            yield True
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
            kernel32.ReleaseMutex.restype = ctypes.c_bool
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            handle = kernel32.CreateMutexW(None, False, r"Global\RaiderDNS_DNS_TRANSACTION_V016")
        except (AttributeError, OSError, TypeError):
            yield False
            return
        if not handle:
            yield False
            return
        acquired = False
        try:
            try:
                wait_result = kernel32.WaitForSingleObject(handle, 30_000)
                acquired = wait_result in (0x00000000, 0x00000080)  # OBJECT_0 or ABANDONED
            except (OSError, ValueError):
                acquired = False
            yield acquired
        finally:
            if acquired:
                try:
                    kernel32.ReleaseMutex(handle)
                except OSError:
                    pass
            try:
                kernel32.CloseHandle(handle)
            except OSError:
                pass

    def has_loopback_dns_dependency(self) -> tuple[bool | None, str]:
        """Inspect installed adapters before stopping a local DNS proxy.

        Returns (True, detail) if any adapter is configured/effectively using
        loopback DNS, (False, detail) only if every installed adapter was
        successfully inspected and none depends on loopback, or (None, detail)
        if the state could not be established. Callers must keep the proxy alive
        when the answer is True or unknown.
        """
        if not self.is_windows():
            return None, "Loopback DNS dependency detection is available only on Windows."
        adapters = self.get_all_adapters()
        if not adapters:
            return None, "Windows did not provide an installed-adapter inventory."
        for adapter in adapters:
            snapshot, error = self._capture_adapter_snapshot(adapter)
            if snapshot is None:
                return None, f"Could not inspect DNS settings for {adapter}: {error}"
            families = snapshot.get("families", {})
            for family in ("IPv4", "IPv6"):
                data = families.get(family, {}) if isinstance(families, dict) else {}
                candidates = list(data.get("servers", [])) + list(data.get("effective", [])) if isinstance(data, dict) else []
                for address in candidates:
                    if str(address).strip() in {"127.0.0.1", "::1"}:
                        return True, f"Adapter {adapter} ({family}) still references local DNS address {address}."
        return False, "All installed adapters were inspected; none references IPv4 or IPv6 loopback DNS."

    def get_dns_configuration(self) -> list[dict[str, Any]]:
        if not self.is_windows():
            return []
        script = (
            "Get-DnsClientServerAddress | "
            "Where-Object {$_.ServerAddresses -and $_.ServerAddresses.Count -gt 0} | "
            "Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress"
        )
        try:
            result = self._run_powershell(script)
            if result.returncode != 0 or not result.stdout.strip():
                return []
            parsed = json.loads(result.stdout.strip())
            rows = parsed if isinstance(parsed, list) else [parsed]
            cleaned: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                addresses = row.get("ServerAddresses", [])
                if isinstance(addresses, str):
                    addresses = [addresses]
                cleaned.append({
                    "adapter": str(row.get("InterfaceAlias", "Unknown")),
                    "family": str(row.get("AddressFamily", "IPv4")),
                    "servers": list(addresses or []),
                })
            return cleaned
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError):
            return []

    def _apply_dns_unchecked(
        self, adapter: str, servers: list[str], doh_url: str | dict[str, str] | None = None,
        flush_cache: bool = True, *, prevalidated: bool = False,
    ) -> DNSOperationResult:
        """Apply DNS addresses by address family, after validating all inputs.

        PowerShell's Set-DnsClientServerAddress has no -AddressFamily parameter.
        We obtain the per-family CimInstance from Get-DnsClientServerAddress and
        pipe it back into Set-DnsClientServerAddress, preventing a mixed-family
        call from overwriting only one family or targeting the wrong one.
        """
        if not prevalidated:
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "System DNS changes are supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Close Raider DNS and start it using Run as administrator, then retry.")
            if not adapter or adapter not in self.get_adapters():
                return DNSOperationResult(False, "Network adapter not available", "Refresh adapters and select an adapter that is currently connected.")
        if not servers:
            return DNSOperationResult(False, "No DNS servers specified")
        try:
            servers = list(dict.fromkeys(self._normalize_ip(server) for server in servers))
        except ValueError as exc:
            return DNSOperationResult(False, "Invalid DNS address", f"{exc}. No changes were made.")

        # Validate the complete DoH mapping before the first Windows mutation.
        templates: dict[str, str] = {}
        if doh_url:
            for server in servers:
                template = doh_url.get(server) if isinstance(doh_url, dict) else doh_url
                if not isinstance(template, str) or not template.strip():
                    return DNSOperationResult(False, "Missing DoH template", f"No DoH endpoint is configured for {server}. Choose a provider with DoH support or use Standard DNS.")
                if not template.strip().lower().startswith("https://"):
                    return DNSOperationResult(False, "Invalid DoH template", f"The DoH endpoint for {server} must be an HTTPS URL.")
                templates[server] = template.strip()

            # Registration is performed before adapter DNS changes. The public
            # apply_dns() method already performed a direct-IP authenticated DoH
            # preflight; retain fail-closed validation here for direct callers too.
            for server in servers:
                template = templates[server]
                ip_ps = self._quote_ps(server)
                template_ps = self._quote_ps(template)
                script_doh = (
                    "$ErrorActionPreference = 'Stop'; "
                    "if (-not (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) { "
                    "Write-Output 'DOH_ERROR=CMDLET_UNAVAILABLE'; exit 0 }; "
                    f"$ip = {ip_ps}; $template = {template_ps}; "
                    "$existing = @(Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue); "
                    "if ($existing.Count -gt 0) { "
                    "Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop "
                    "} else { "
                    "Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop "
                    "}; Write-Output 'DOH_TEMPLATE_READY'"
                )
                try:
                    doh_result = self._run_powershell(script_doh, timeout=WINDOWS_DOH_APPLY_TIMEOUT_SECONDS)
                except (OSError, subprocess.SubprocessError) as exc:
                    return DNSOperationResult(False, "Could not configure Windows DoH", self._friendly_command_error(str(exc), "DoH registration could not run."))
                if doh_result.returncode != 0 or "DOH_TEMPLATE_READY" not in doh_result.stdout:
                    details = self._friendly_command_error(doh_result.stderr or doh_result.stdout, "Windows DNS Client did not confirm DoH template registration.")
                    return DNSOperationResult(False, "Windows rejected the DoH template", details)

        groups = {
            "IPv4": [address for address in servers if ipaddress.ip_address(address).version == 4],
            "IPv6": [address for address in servers if ipaddress.ip_address(address).version == 6],
        }
        updated_families: list[str] = []
        for family, family_servers in groups.items():
            if not family_servers:
                continue
            interface_ps = self._quote_ps(adapter)
            family_ps = self._quote_ps(family)
            addresses_ps = self._powershell_array(family_servers)
            script = (
                "$ErrorActionPreference = 'Stop'; "
                f"$adapter = {interface_ps}; $family = {family_ps}; "
                "$familyObject = Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily $family -ErrorAction Stop; "
                "if (-not $familyObject) { throw 'Could not find DNS client interface/family.' }; "
                f"$familyObject | Set-DnsClientServerAddress -ServerAddresses {addresses_ps} -ErrorAction Stop; "
                f"Write-Output 'DNS_UPDATED_{family.upper()}'"
            )
            try:
                result = self._run_powershell(script)
            except (OSError, subprocess.SubprocessError) as exc:
                return DNSOperationResult(False, "Failed to apply DNS settings", self._friendly_command_error(str(exc), "Windows DNS configuration command could not run."))
            marker = f"DNS_UPDATED_{family.upper()}"
            if result.returncode != 0 or marker not in result.stdout:
                return DNSOperationResult(False, f"Failed to apply {family} DNS settings", self._friendly_command_error(result.stderr or result.stdout, f"Windows did not confirm {family} DNS changes."))
            updated_families.append(family)

        details = f"Windows DNS client is configured on {', '.join(updated_families)}."
        if templates:
            details += " Windows DNS Client DoH templates were registered with automatic upgrade enabled and plaintext UDP fallback disabled."
        if flush_cache:
            flushed, flush_detail = self._flush_cache_strict()
            if not flushed:
                return DNSOperationResult(False, "DNS settings applied but cache flush failed", details + " " + flush_detail)
            details += " " + flush_detail
        return DNSOperationResult(True, "DNS settings applied", details)

    def _apply_dnscrypt_loopback_unchecked(
        self, adapter: str, flush_cache: bool = True, *, prevalidated: bool = False,
    ) -> DNSOperationResult:
        """Point an adapter at the local DNSCrypt proxy on both loopback families."""
        if not prevalidated:
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "DNSCrypt system integration is supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Restart Raider DNS as administrator and retry.")
            if not adapter or adapter not in self.get_adapters():
                return DNSOperationResult(False, "Network adapter not available", "Refresh adapters and select an active adapter.")
        # Configure address families independently. Mixed IPv4/IPv6 input in a
        # single Set-DnsClientServerAddress call is not consistently accepted by
        # all supported Windows builds, and could leave only one family changed.
        script = (
            f"$adapter = {self._quote_ps(adapter)}; "
            "$v4 = Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv4 -ErrorAction Stop; "
            "$v6 = Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv6 -ErrorAction Stop; "
            "$v4 | Set-DnsClientServerAddress -ServerAddresses @('127.0.0.1') -ErrorAction Stop; "
            "$v6 | Set-DnsClientServerAddress -ServerAddresses @('::1') -ErrorAction Stop; "
            "$ipv4 = @(Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses }); "
            "$ipv6 = @(Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv6 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses }); "
            "if (($ipv4 -notcontains '127.0.0.1') -or ($ipv6 -notcontains '::1')) { "
            "throw 'Could not verify both IPv4 and IPv6 loopback DNS addresses on the selected adapter.' }; "
            "Write-Output 'DNSCRYPT_LOOPBACK_UPDATED'"
        )
        try:
            result = self._run_powershell(script)
        except (OSError, subprocess.SubprocessError) as exc:
            return DNSOperationResult(False, "Failed to apply local DNSCrypt addresses", str(exc))
        if result.returncode != 0 or "DNSCRYPT_LOOPBACK_UPDATED" not in result.stdout:
            return DNSOperationResult(False, "Could not verify local DNSCrypt settings", self._friendly_command_error(result.stderr or result.stdout, "Windows did not confirm both loopback DNS addresses."))
        details = "The adapter now uses 127.0.0.1 and ::1, keeping both IPv4 and IPv6 DNS requests on the local encrypted proxy. This does not prevent applications from using their own hard-coded DoH or DoT endpoints."
        if flush_cache:
            try:
                self._run_powershell("Clear-DnsClientCache -ErrorAction Stop; Write-Output 'CACHE_CLEARED'", timeout=WINDOWS_DNS_CACHE_TIMEOUT_SECONDS)
            except (OSError, subprocess.SubprocessError):
                details += " DNS cache flush could not be confirmed."
        return DNSOperationResult(True, "DNSCrypt proxy configured on IPv4 and IPv6 loopback", details)

    @staticmethod
    def _run_netsh(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["netsh.exe", *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def _apply_dot_unchecked(
        self, adapter: str, servers: list[str], dot_hostname: str, flush_cache: bool = True,
        *, prevalidated: bool = False,
    ) -> DNSOperationResult:
        """Configure native Windows DNS-over-TLS (DoT) where the OS supports it.

        TLS reachability and hostname/certificate validation must be tested by
        the caller before invoking this method. UDP/TCP fallback is disabled for
        the encrypted resolver entries.
        """
        if not prevalidated:
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "Native Windows DNS Client DoT is supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Restart Raider DNS as administrator and retry.")
            if not adapter or adapter not in self.get_adapters():
                return DNSOperationResult(False, "Network adapter not available", "Refresh adapters and select an active adapter.")
        if not servers or not isinstance(dot_hostname, str) or not dot_hostname.strip():
            return DNSOperationResult(False, "DoT configuration incomplete", "Choose a provider with a verified DNS-over-TLS hostname.")
        try:
            # Windows DNS Client accepts IPv4 and IPv6 resolver addresses.
            # Keep the configured TLS hostname separate from the IP literal: it
            # is needed for authenticated certificate-name validation.
            for server in servers:
                ipaddress.ip_address(server)
        except ValueError as exc:
            return DNSOperationResult(False, "Invalid DNS address", str(exc))
        host = dot_hostname.strip().rstrip(".")
        hostname_pattern = r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+\.?$"
        if not re.fullmatch(hostname_pattern, host):
            return DNSOperationResult(False, "Invalid DoT hostname", "Enter a valid DNS hostname without a scheme, port, path or spaces.")

        # netsh dnsclient is the client-side Windows interface for native DoT.
        # ':' requests the default DoH template field; dothost selects the TLS
        # hostname and port. Both set/add are tried because Windows distinguishes
        # existing entries from new entries. No plaintext fallback is permitted.
        for server in servers:
            command_tail = [f"server={server}", "dohtemplate=:", f"dothost={host}:853", "autoupgrade=yes", "udpfallback=no"]
            try:
                result = self._run_netsh(["dnsclient", "set", "encryption", *command_tail])
                if result.returncode != 0:
                    result = self._run_netsh(["dnsclient", "add", "encryption", *command_tail])
            except (OSError, subprocess.SubprocessError) as exc:
                return DNSOperationResult(False, "Could not configure native Windows DoT", str(exc))
            if result.returncode != 0:
                return DNSOperationResult(False, "Windows rejected the DoT configuration", self._friendly_command_error(result.stderr or result.stdout) or "netsh dnsclient failed.")

        try:
            global_result = self._run_netsh(["dnsclient", "set", "global", "dot=yes"])
        except (OSError, subprocess.SubprocessError) as exc:
            return DNSOperationResult(False, "Could not enable Windows DoT", str(exc))
        if global_result.returncode != 0:
            return DNSOperationResult(False, "Windows could not enable DoT", self._friendly_command_error(global_result.stderr or global_result.stdout, "Windows did not confirm the global DoT setting.") or "netsh dnsclient set global dot=yes failed.")

        # Apply each address family through the matching CIM object. The
        # Set-DnsClientServerAddress cmdlet does not accept -AddressFamily; using
        # that invalid parameter can report an error after DoT registration has
        # already changed, forcing a rollback.
        family_groups = {
            "IPv4": [value for value in servers if ipaddress.ip_address(value).version == 4],
            "IPv6": [value for value in servers if ipaddress.ip_address(value).version == 6],
        }
        applied_families: list[str] = []
        for family, family_servers in family_groups.items():
            if not family_servers:
                continue
            args = self._powershell_array(family_servers)
            script = (
                "$ErrorActionPreference = 'Stop'; "
                f"$adapter = {self._quote_ps(adapter)}; "
                f"$familyObject = Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily {self._quote_ps(family)} -ErrorAction Stop; "
                "if (-not $familyObject) { throw 'Could not find DNS client interface/family.' }; "
                f"$familyObject | Set-DnsClientServerAddress -ServerAddresses {args} -ErrorAction Stop; "
                f"Write-Output 'DNS_UPDATED_{family.upper()}'"
            )
            try:
                result = self._run_powershell(script)
            except (OSError, subprocess.SubprocessError) as exc:
                return DNSOperationResult(False, "Failed to apply DoT DNS servers", self._friendly_command_error(str(exc), "Windows DNS configuration command could not run."))
            if result.returncode != 0 or f"DNS_UPDATED_{family.upper()}" not in result.stdout:
                return DNSOperationResult(False, f"Failed to apply {family} DoT DNS servers", self._friendly_command_error(result.stderr or result.stdout))
            applied_families.append(family)
        if not applied_families:
            return DNSOperationResult(False, "No valid DoT DNS addresses", "No Windows DNS settings were changed.")
        details = f"Windows DoT is enabled for {host}:853 with UDP/TCP fallback disabled for configured secure resolver entries. This confirms configuration, not that every application is using DoT."
        if flush_cache:
            try:
                self._run_powershell("Clear-DnsClientCache -ErrorAction Stop; Write-Output 'CACHE_CLEARED'", timeout=WINDOWS_DNS_CACHE_TIMEOUT_SECONDS)
            except (OSError, subprocess.SubprocessError):
                details += " DNS cache flush could not be confirmed."
        return DNSOperationResult(True, "DNS-over-TLS configured", details)

    def _restore_dhcp_unchecked(
        self, adapter: str, flush_cache: bool = True, *, prevalidated: bool = False,
    ) -> DNSOperationResult:
        if not prevalidated:
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "System DNS changes are supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Start Raider DNS using Run as administrator, then retry.")
            if not adapter or adapter not in self.get_all_adapters():
                return DNSOperationResult(False, "Network adapter not available", "The adapter is no longer installed; DNS could not be reset.")
        script = (
            f"Set-DnsClientServerAddress -InterfaceAlias {self._quote_ps(adapter)} -ResetServerAddresses -ErrorAction Stop; "
            "Write-Output 'DNS_RESET'"
        )
        try:
            result = self._run_powershell(script)
        except (OSError, subprocess.SubprocessError) as exc:
            return DNSOperationResult(False, "Failed to restore automatic DNS", str(exc))
        if result.returncode != 0 or "DNS_RESET" not in result.stdout:
            return DNSOperationResult(False, "Failed to restore automatic DNS", self._friendly_command_error(result.stderr or result.stdout))
        details = "The adapter has been returned to its automatically assigned DNS servers (normally DHCP-provided)."
        if flush_cache:
            try:
                self._run_powershell("Clear-DnsClientCache -ErrorAction Stop", timeout=WINDOWS_DNS_CACHE_TIMEOUT_SECONDS)
            except (OSError, subprocess.SubprocessError):
                details += " DNS cache flush could not be confirmed."
        return DNSOperationResult(True, "Automatic DNS restored", details)

    def get_doh_template_registrations(self) -> dict[str, Any]:
        """Read registered Windows DoH templates separately from active adapter DNS."""
        if not self.is_windows():
            return {"supported": False, "entries": [], "detail": "Windows DNS Client inspection is Windows-only."}
        script = r"""
$ErrorActionPreference = 'Stop'
$cmd = Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
if ($null -eq $cmd) {
  [ordered]@{ supported=$false; entries=@() } | ConvertTo-Json -Depth 5 -Compress
  exit 0
}
$rows = @(Get-DnsClientDohServerAddress -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{ server=[string]$_.ServerAddress; template=[string]$_.DohTemplate; auto_upgrade=[bool]$_.AutoUpgrade; fallback=[bool]$_.AllowFallbackToUdp }
})
[ordered]@{ supported=$true; entries=@($rows) } | ConvertTo-Json -Depth 5 -Compress
"""
        try:
            result = self._run_powershell(script, timeout=WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"supported": False, "entries": [], "detail": f"Could not inspect registered DoH templates: {exc}"}
        if result.returncode != 0 or not result.stdout.strip():
            return {"supported": False, "entries": [], "detail": self._friendly_command_error(result.stderr or result.stdout) or "Windows returned no DoH registration inventory."}
        try:
            raw = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            return {"supported": False, "entries": [], "detail": f"Invalid DoH registration response: {exc}"}
        if not isinstance(raw, dict):
            return {"supported": False, "entries": [], "detail": "Windows returned an invalid DoH registration inventory."}
        entries = raw.get("entries", [])
        if isinstance(entries, dict):
            entries = [entries]
        normalized: list[dict[str, Any]] = []
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            try:
                server = self._normalize_ip(str(entry.get("server", "")))
            except ValueError:
                continue
            normalized.append({
                "server": server, "template": str(entry.get("template", "")),
                "auto_upgrade": bool(entry.get("auto_upgrade", False)),
                "fallback": bool(entry.get("fallback", False)),
            })
        return {"supported": bool(raw.get("supported")), "entries": normalized, "detail": ""}

    # ---- Transactional DNS safety layer (v0.1.6) -----------------------------
    def __init__(self, recovery_store: DNSRecoveryStore | None = None) -> None:
        self.recovery_store = recovery_store or DNSRecoveryStore()
        self._operation_lock = threading.RLock()

    @staticmethod
    def _normalize_ip(value: str) -> str:
        return str(ipaddress.ip_address(str(value).strip()))

    @staticmethod
    def _as_string_list(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    @staticmethod
    def _powershell_array(values: list[str]) -> str:
        return "@(" + ",".join(WindowsDNSService._quote_ps(item) for item in values) + ")"

    @staticmethod
    def _parse_bool_word(value: str) -> bool | None:
        word = str(value).strip().casefold()
        if word in {"yes", "true", "enabled", "on", "1"}:
            return True
        if word in {"no", "false", "disabled", "off", "0"}:
            return False
        return None

    @classmethod
    def _parse_global_dot(cls, text: str) -> bool | None:
        patterns = (
            r"(?im)^\s*dot\s*(?:=|:)\s*(yes|no|true|false|enabled|disabled)\b",
            r"(?im)^\s*DNS.over.TLS\s*\(DoT\)\s*:\s*(yes|no|true|false|enabled|disabled)\b",
            r"(?im)^\s*DoT\s*:\s*(yes|no|true|false|enabled|disabled)\b",
        )
        for pattern in patterns:
            match = re.search(pattern, text or "")
            if match:
                return cls._parse_bool_word(match.group(1))
        return None

    @classmethod
    def _parse_netsh_encryption_dump(cls, text: str) -> dict[str, dict[str, Any]]:
        """Parse language-independent command lines emitted by `netsh dnsclient dump`."""
        entries: dict[str, dict[str, Any]] = {}
        for line in (text or "").splitlines():
            if not re.search(r"\b(?:add|set)\s+encryption\b", line, re.IGNORECASE):
                continue
            pairs = re.findall(r"([A-Za-z][A-Za-z0-9_-]*)=(\"[^\"]*\"|'[^']*'|\S+)", line)
            fields: dict[str, str] = {}
            for key, value in pairs:
                fields[key.casefold()] = value.strip().strip("\"'")
            server = fields.get("server")
            if not server:
                continue
            try:
                server = cls._normalize_ip(server)
            except ValueError:
                continue
            entries[server] = {
                "doh_template": fields.get("dohtemplate", ":"),
                "dot_host": fields.get("dothost", ":"),
                "auto_upgrade": cls._parse_bool_word(fields.get("autoupgrade", "no")) is True,
                "udp_fallback": cls._parse_bool_word(fields.get("udpfallback", "no")) is True,
            }
        return entries

    def _capture_adapter_snapshot(
        self,
        adapter: str,
        *,
        include_dot: bool = False,
        require_doh_inventory: bool = False,
    ) -> tuple[dict[str, Any] | None, str]:
        """Capture static/manual and effective per-family DNS plus global templates.

        The PowerShell capture is read-only. Recovery is durably written before any
        write command is issued; an unreadable capture aborts a DNS change.
        """
        adapter_ps = self._quote_ps(adapter)
        script = f"""
$ErrorActionPreference = 'Stop'
$adapterName = {adapter_ps}
$netAdapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
if ($null -eq $netAdapter -or $null -eq $netAdapter.InterfaceGuid) {{ throw 'Interface identity could not be read.' }}
$guid = '{{' + ([string]$netAdapter.InterfaceGuid).Trim('{{}}') + '}}'
$ipv4Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $guid
$ipv6Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $guid
function Read-DnsFamily([string]$family, [string]$path) {{
  $manualText = ''
  try {{ $key = Get-ItemProperty -LiteralPath $path -Name NameServer -ErrorAction Stop; $manualText = [string]$key.NameServer }} catch {{ $manualText = '' }}
  $manualServers = @()
  if (-not [string]::IsNullOrWhiteSpace($manualText)) {{ $manualServers = @($manualText -split '[,; ]+' | Where-Object {{ -not [string]::IsNullOrWhiteSpace($_) }}) }}
  $effective = @(Get-DnsClientServerAddress -InterfaceAlias $adapterName -AddressFamily $family -ErrorAction Stop | ForEach-Object {{ $_.ServerAddresses }} | Where-Object {{ -not [string]::IsNullOrWhiteSpace([string]$_) }})
  $mode = if ($manualServers.Count -gt 0) {{ 'manual' }} else {{ 'automatic' }}
  return [pscustomobject]@{{ mode=$mode; servers=@($manualServers); effective=@($effective) }}
}}
$dohSupported = $null -ne (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
$dohRows = @()
if ($dohSupported) {{
  $dohRows = @(Get-DnsClientDohServerAddress -ErrorAction Stop | ForEach-Object {{
    [pscustomobject]@{{ server=[string]$_.ServerAddress; template=[string]$_.DohTemplate; auto_upgrade=[bool]$_.AutoUpgrade; fallback=[bool]$_.AllowFallbackToUdp }}
  }})
}}
[ordered]@{{
  adapter=$adapterName
  interface_guid=$guid
  families=[ordered]@{{ IPv4=(Read-DnsFamily 'IPv4' $ipv4Path); IPv6=(Read-DnsFamily 'IPv6' $ipv6Path) }}
  doh_supported=$dohSupported
  doh_rows=@($dohRows)
}} | ConvertTo-Json -Depth 8 -Compress
"""
        try:
            result = self._run_powershell(script, timeout=WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"Could not capture current adapter DNS settings before changing them: {exc}"
        if result.returncode != 0 or not result.stdout.strip():
            return None, self._friendly_command_error(result.stderr or result.stdout) or "Windows did not return a complete DNS configuration snapshot."
        try:
            raw = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            return None, f"Windows returned an invalid DNS snapshot: {exc}"
        if not isinstance(raw, dict) or not isinstance(raw.get("families"), dict):
            return None, "Windows returned an incomplete DNS snapshot; no changes were made."

        families: dict[str, dict[str, Any]] = {}
        for family in ("IPv4", "IPv6"):
            value = raw["families"].get(family, {})
            if not isinstance(value, dict):
                return None, f"Could not capture {family} DNS configuration; no changes were made."
            mode = str(value.get("mode", "")).casefold()
            if mode not in {"automatic", "manual"}:
                return None, f"Windows returned an unknown {family} DNS mode; no changes were made."
            addresses: list[str] = []
            for address in self._as_string_list(value.get("servers", [])):
                try:
                    parsed = self._normalize_ip(address)
                except ValueError:
                    return None, f"Windows returned an invalid {family} DNS server address: {address!r}."
                if ipaddress.ip_address(parsed).version != (4 if family == "IPv4" else 6):
                    return None, f"Windows returned an address-family mismatch for {family}: {address!r}."
                addresses.append(parsed)
            effective: list[str] = []
            for address in self._as_string_list(value.get("effective", [])):
                try:
                    effective.append(self._normalize_ip(address))
                except ValueError:
                    continue
            if mode == "manual" and not addresses:
                return None, f"Windows reports manual {family} DNS but did not provide the static server list."
            families[family] = {"mode": mode, "servers": addresses, "effective": effective}

        doh_supported = bool(raw.get("doh_supported"))
        if require_doh_inventory and not doh_supported:
            return None, "Windows DoH template inventory is unavailable; refusing a change that cannot be rolled back safely."
        doh_by_server: dict[str, dict[str, Any]] = {}
        doh_rows = raw.get("doh_rows", [])
        if isinstance(doh_rows, dict):
            doh_rows = [doh_rows]
        if isinstance(doh_rows, list):
            for entry in doh_rows:
                if not isinstance(entry, dict):
                    continue
                try:
                    server = self._normalize_ip(str(entry.get("server", "")))
                except ValueError:
                    continue
                doh_by_server[server] = {
                    "template": str(entry.get("template", "")),
                    "auto_upgrade": bool(entry.get("auto_upgrade", False)),
                    "fallback": bool(entry.get("fallback", False)),
                }

        snapshot: dict[str, Any] = {
            "adapter": str(raw.get("adapter", adapter)),
            "interface_guid": str(raw.get("interface_guid", "")),
            "families": families,
            "doh_supported": doh_supported,
            "doh_by_server": doh_by_server,
            "dot_by_server": {},
            "dot_global": None,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        # Standard DNS and DoH transactions never modify native DoT state.
        # Avoid two extra netsh process launches for every ordinary DNS change;
        # capture the global/per-resolver DoT inventory only when the transaction
        # will actually modify or restore it.
        if not include_dot:
            snapshot["netsh_dump_available"] = None
            return snapshot, ""

        # `netsh dnsclient dump` uses command syntax, so it is more reliable to
        # parse than localized display tables. Failure is fatal for DoT.
        try:
            dump = self._run_netsh(["dnsclient", "dump"], timeout=10)
            snapshot["netsh_dump_available"] = dump.returncode == 0
            snapshot["dot_by_server"] = self._parse_netsh_encryption_dump(dump.stdout) if dump.returncode == 0 else {}
            dot_dump_text = dump.stdout if dump.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError) as exc:
            snapshot["netsh_dump_available"] = False
            dot_dump_text = ""
            snapshot["netsh_capture_error"] = str(exc)[:300]
        try:
            global_result = self._run_netsh(["dnsclient", "show", "global"], timeout=8)
            dot_global = self._parse_global_dot(global_result.stdout) if global_result.returncode == 0 else None
            if dot_global is None:
                # The dump may record explicit global settings in command syntax.
                match = re.search(r"(?im)\b(?:add|set)\s+global\b[^\r\n]*\bdot=(yes|no)\b", dot_dump_text)
                if match:
                    dot_global = self._parse_bool_word(match.group(1))
            snapshot["dot_global"] = dot_global
        except (OSError, subprocess.SubprocessError) as exc:
            snapshot["dot_global"] = None
            snapshot["netsh_global_error"] = str(exc)[:300]
        if include_dot and (snapshot.get("dot_global") not in (True, False) or not snapshot.get("netsh_dump_available")):
            detail = snapshot.get("netsh_capture_error") or snapshot.get("netsh_global_error") or "Windows DoT state could not be identified unambiguously."
            return None, f"Refusing to modify native DoT without a recoverable snapshot of the global and per-resolver settings. {detail}"
        return snapshot, ""

    def _flush_cache_strict(self) -> tuple[bool, str]:
        try:
            result = self._run_powershell(
                "Clear-DnsClientCache -ErrorAction Stop; Write-Output 'DNS_CACHE_CLEARED'",
                timeout=WINDOWS_DNS_CACHE_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Could not clear the DNS cache before verification: {exc}"
        if result.returncode != 0 or "DNS_CACHE_CLEARED" not in result.stdout:
            return False, self._friendly_command_error(result.stderr or result.stdout) or "Windows did not confirm that the DNS cache was cleared."
        return True, "DNS cache cleared before verification."

    def verify_dns_and_https(self) -> tuple[bool, str]:
        """Run a short, informational DNS + HTTPS reachability probe on Windows.

        This result must never be treated as proof that the adapter settings
        themselves were or were not applied. The transaction verifies those by
        reading back the adapter and encryption registrations.
        """
        if not self.is_windows():
            return False, "DNS and HTTPS verification requires the Windows system resolver."
        script = r"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dnsOk = $false
$dnsHost = ''
$dnsErrors = @()
foreach ($name in @('example.com','www.msftconnecttest.com')) {
  try {
    $answers = @(Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress })
    if ($answers.Count -gt 0) { $dnsOk = $true; $dnsHost = $name; break }
    $dnsErrors += ($name + ': no IPv4 answer returned')
  } catch {
    $dnsErrors += ($name + ': ' + $_.Exception.GetType().Name)
  }
}
if (-not $dnsOk) {
  Write-Output 'DNS_VERIFY=FAIL'
  Write-Output 'HTTPS_VERIFY=NOT_RUN'
  $dnsSummary = ($dnsErrors -join '; ') -replace '[<>
]', ' '
  if ($dnsSummary.Length -gt 180) { $dnsSummary = $dnsSummary.Substring(0,180) }
  Write-Output ('DNS_DETAIL=Windows could not resolve a diagnostic hostname. ' + $dnsSummary)
  Write-Output 'VERIFY_DETAIL=Resolver reachability was not verified; adapter settings were not judged by this test.'
  exit 0
}
$httpsOk = $false
$httpsDetail = ''
try {
  $response = Invoke-WebRequest -Uri 'https://www.msftconnecttest.com/connecttest.txt' -Method Get -TimeoutSec 3 -MaximumRedirection 2 -UseBasicParsing -ErrorAction Stop
  if ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 500) { $httpsOk = $true; $httpsDetail = ('HTTPS/TLS reached an endpoint (HTTP ' + [int]$response.StatusCode + ').') }
} catch {
  if ($null -ne $_.Exception.Response) { $httpsOk = $true; $httpsDetail = 'HTTPS/TLS reached an HTTP endpoint.' }
  else { $httpsDetail = 'DNS worked, but the short HTTPS/TLS connectivity probe did not reach an HTTP endpoint.' }
}
Write-Output 'DNS_VERIFY=PASS'
Write-Output ('DNS_DETAIL=Windows resolved ' + $dnsHost + '.')
if ($httpsOk) {
  Write-Output 'HTTPS_VERIFY=PASS'
  Write-Output ('VERIFY_DETAIL=' + $httpsDetail)
} else {
  Write-Output 'HTTPS_VERIFY=FAIL'
  Write-Output ('VERIFY_DETAIL=' + $httpsDetail)
}
"""
        try:
            result = self._run_powershell(script, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"DNS/HTTPS verification could not complete ({exc.__class__.__name__})."
        output = result.stdout or ""
        if result.returncode != 0 and "DNS_VERIFY=" not in output:
            detail = self._friendly_command_error(result.stderr or output, "Windows did not return a usable DNS/HTTPS verification result.")
            return False, f"DNS/HTTPS verification could not complete: {detail}"
        dns_pass = "DNS_VERIFY=PASS" in output
        https_pass = "HTTPS_VERIFY=PASS" in output
        detail_line = next((line.split("=", 1)[1].strip() for line in output.splitlines() if line.startswith("VERIFY_DETAIL=")), "")
        dns_detail = next((line.split("=", 1)[1].strip() for line in output.splitlines() if line.startswith("DNS_DETAIL=")), "")
        if not dns_pass:
            return False, dns_detail or "Windows could not resolve a diagnostic hostname through the active DNS client."
        if not https_pass:
            return False, detail_line or "HTTPS/TLS connectivity could not be independently verified."
        return True, "Fresh DNS resolution and HTTPS/TLS connectivity both succeeded. " + (dns_detail + " " if dns_detail else "") + detail_line

    def _expected_dns_matches(
        self,
        snapshot: dict[str, Any],
        expected_servers: list[str] | None = None,
        expect_automatic: bool = False,
        expect_dnscrypt_loopback: bool = False,
    ) -> tuple[bool, str]:
        families = snapshot.get("families", {})
        if expect_automatic:
            failures = [family for family in ("IPv4", "IPv6") if families.get(family, {}).get("mode") != "automatic"]
            return (not failures, "" if not failures else f"These address families were not restored to automatic DNS: {', '.join(failures)}.")
        expected_groups: dict[str, list[str]] = {"IPv4": [], "IPv6": []}
        if expect_dnscrypt_loopback:
            expected_groups = {"IPv4": ["127.0.0.1"], "IPv6": ["::1"]}
        else:
            for server in expected_servers or []:
                parsed = self._normalize_ip(server)
                expected_groups["IPv4" if ipaddress.ip_address(parsed).version == 4 else "IPv6"].append(parsed)
        failures: list[str] = []
        for family, expected in expected_groups.items():
            if not expected:
                continue
            actual = families.get(family, {})
            if str(actual.get("mode", "")).casefold() != "manual":
                failures.append(f"{family} DNS is not configured statically as requested")
                continue
            actual_servers = [self._normalize_ip(x) for x in actual.get("servers", [])]
            if actual_servers != expected:
                failures.append(f"{family} DNS servers do not match the requested list")
        return (not failures, "; ".join(failures))

    def _restore_adapter_addresses(self, adapter: str, snapshot: dict[str, Any]) -> tuple[bool, str]:
        families = snapshot.get("families", {})
        ipv4 = families.get("IPv4", {}) if isinstance(families, dict) else {}
        ipv6 = families.get("IPv6", {}) if isinstance(families, dict) else {}
        if not isinstance(ipv4, dict) or not isinstance(ipv6, dict):
            return False, "Recovery snapshot is missing IPv4/IPv6 family state."
        parts = [
            "$ErrorActionPreference = 'Stop'",
            f"$adapter = {self._quote_ps(adapter)}",
            "Get-NetAdapter -Name $adapter -ErrorAction Stop | Out-Null",
            "Set-DnsClientServerAddress -InterfaceAlias $adapter -ResetServerAddresses -ErrorAction Stop",
        ]
        for family, value in (("IPv4", ipv4), ("IPv6", ipv6)):
            mode = str(value.get("mode", "automatic")).casefold()
            servers = self._as_string_list(value.get("servers", []))
            if mode == "manual":
                if not servers:
                    return False, f"Recovery snapshot says {family} DNS is manual but contains no server addresses."
                # Set-DnsClientServerAddress has no -AddressFamily parameter.
                # Pipe the specific family object to preserve the other family.
                normalized: list[str] = []
                for raw in servers:
                    try:
                        address = self._normalize_ip(raw)
                    except ValueError:
                        return False, f"Recovery snapshot contains an invalid {family} DNS address."
                    expected_version = 4 if family == "IPv4" else 6
                    if ipaddress.ip_address(address).version != expected_version:
                        return False, f"Recovery snapshot contains an address-family mismatch for {family}."
                    normalized.append(address)
                args = self._powershell_array(normalized)
                family_ps = self._quote_ps(family)
                parts.append(f"$familyObject = Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily {family_ps} -ErrorAction Stop")
                parts.append("if (-not $familyObject) { throw 'Could not find DNS client interface/family during recovery.' }")
                parts.append(f"$familyObject | Set-DnsClientServerAddress -ServerAddresses {args} -ErrorAction Stop")
            elif mode != "automatic":
                return False, f"Recovery snapshot contains an unknown {family} DNS mode."
        parts.append("Write-Output 'DNS_RECOVERY_ADDRESSES_RESTORED'")
        try:
            result = self._run_powershell("; ".join(parts), timeout=WINDOWS_POWERSHELL_DEFAULT_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Could not restore adapter DNS addresses: {exc}"
        if result.returncode != 0 or "DNS_RECOVERY_ADDRESSES_RESTORED" not in result.stdout:
            return False, self._friendly_command_error(result.stderr or result.stdout) or "Windows did not confirm restoration of DNS addresses."
        return True, "The previous manual/automatic IPv4 and IPv6 DNS configuration was restored."

    def _restore_doh_entries(self, snapshot: dict[str, Any], servers: list[str]) -> tuple[bool, str]:
        if not servers:
            return True, "No DoH template registrations needed rollback."
        if not snapshot.get("doh_supported"):
            # No DoH mutation could have succeeded without the same cmdlets, and
            # a non-DoH operation doesn't need to touch this inventory.
            return True, "DoH template inventory was not used by this operation."
        before = snapshot.get("doh_by_server", {})
        for server in dict.fromkeys(self._normalize_ip(value) for value in servers):
            original = before.get(server) if isinstance(before, dict) else None
            server_ps = self._quote_ps(server)
            if not isinstance(original, dict):
                script = (
                    f"$server = {server_ps}; "
                    "if (Get-Command Remove-DnsClientDohServerAddress -ErrorAction SilentlyContinue) { "
                    "$entries = @(Get-DnsClientDohServerAddress -ServerAddress $server -ErrorAction SilentlyContinue); "
                    "if ($entries.Count -gt 0) { Remove-DnsClientDohServerAddress -ServerAddress $server -ErrorAction Stop }; "
                    "Write-Output 'DOH_ENTRY_REMOVED_OR_ABSENT' } else { throw 'Remove-DnsClientDohServerAddress is unavailable.' }"
                )
            else:
                template = str(original.get("template", "")).strip()
                if not template:
                    return False, f"The recovery snapshot for DoH server {server} has no URI template."
                template_ps = self._quote_ps(template)
                auto = "$true" if bool(original.get("auto_upgrade", False)) else "$false"
                fallback = "$true" if bool(original.get("fallback", False)) else "$false"
                script = (
                    f"$server = {server_ps}; $template = {template_ps}; "
                    "$entries = @(Get-DnsClientDohServerAddress -ServerAddress $server -ErrorAction SilentlyContinue); "
                    "if ($entries.Count -gt 0) { "
                    f"Set-DnsClientDohServerAddress -ServerAddress $server -DohTemplate $template -AutoUpgrade {auto} -AllowFallbackToUdp {fallback} -ErrorAction Stop "
                    "} else { "
                    f"Add-DnsClientDohServerAddress -ServerAddress $server -DohTemplate $template -AutoUpgrade {auto} -AllowFallbackToUdp {fallback} -ErrorAction Stop "
                    "}; Write-Output 'DOH_ENTRY_RESTORED'"
                )
            try:
                result = self._run_powershell(script, timeout=WINDOWS_DOH_APPLY_TIMEOUT_SECONDS)
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"Could not restore DoH template for {server}: {exc}"
            marker = "DOH_ENTRY_REMOVED_OR_ABSENT" if not isinstance(original, dict) else "DOH_ENTRY_RESTORED"
            if result.returncode != 0 or marker not in result.stdout:
                return False, f"Could not restore DoH template for {server}: " + (self._friendly_command_error(result.stderr or result.stdout) or "Windows returned no confirmation.")
        return True, "DoH template registrations were restored separately from adapter DNS addresses."

    def _restore_dot_entries(self, snapshot: dict[str, Any], servers: list[str]) -> tuple[bool, str]:
        if not servers:
            return True, "No per-resolver DoT entries needed rollback."
        before = snapshot.get("dot_by_server", {})
        for server in dict.fromkeys(self._normalize_ip(value) for value in servers):
            original = before.get(server) if isinstance(before, dict) else None
            try:
                deleted = self._run_netsh(["dnsclient", "delete", "encryption", f"server={server}", "protocol=dot"], timeout=8)
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"Could not remove the attempted DoT entry for {server}: {exc}"
            # A delete can correctly report that no entry exists; only fail if
            # there is an original entry we must reconstruct and that fails below.
            if isinstance(original, dict):
                args = [
                    "dnsclient", "add", "encryption", f"server={server}",
                    f"dohtemplate={original.get('doh_template') or ':'}",
                    f"dothost={original.get('dot_host') or ':'}",
                    f"autoupgrade={'yes' if original.get('auto_upgrade') else 'no'}",
                    f"udpfallback={'yes' if original.get('udp_fallback') else 'no'}",
                ]
                try:
                    restored = self._run_netsh(args, timeout=8)
                    if restored.returncode != 0:
                        # `add encryption` and `set encryption` differ at index 1.
                        # Keep the `encryption` subcommand in place.
                        args[1] = "set"
                        restored = self._run_netsh(args, timeout=8)
                except (OSError, subprocess.SubprocessError) as exc:
                    return False, f"Could not restore original encryption entry for {server}: {exc}"
                if restored.returncode != 0:
                    return False, f"Could not restore original encryption entry for {server}: {self._friendly_command_error(restored.stderr or restored.stdout, 'Windows did not confirm restoration of the DoT entry.') }"
            elif deleted.returncode != 0:
                # If there was no prior entry, a failed delete is acceptable only
                # when a follow-up query clearly establishes absence. Unknown or
                # localized output is treated as ambiguous and keeps recovery armed.
                try:
                    check = self._run_netsh(["dnsclient", "show", "encryption", f"server={server}"], timeout=8)
                except (OSError, subprocess.SubprocessError) as exc:
                    return False, f"Could not verify removal of the attempted DoT entry for {server}: {exc}"
                visible = " ".join((check.stdout or "").casefold().split())
                if check.returncode != 0:
                    return False, f"Could not verify whether the DoT entry for {server} remains after deletion failed."
                if any(token in visible for token in ("dothost", "dot host", "dns-over-tls", "dohtemplate")):
                    return False, f"Could not remove the newly registered DoT entry for {server}."
                if not any(token in visible for token in ("not found", "no entry", "does not exist", "no encryption", "not configured", "no matching", "none")):
                    return False, f"Windows returned ambiguous output while checking whether the DoT entry for {server} was removed."
        return True, "Per-resolver DoT registration state was restored."

    def _restore_dot_global(self, enabled: bool | None) -> tuple[bool, str]:
        if enabled not in (True, False):
            return False, "Original global DoT state is unknown; refusing to guess during rollback."
        try:
            result = self._run_netsh(["dnsclient", "set", "global", f"dot={'yes' if enabled else 'no'}"], timeout=8)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Could not restore Windows global DoT state: {exc}"
        if result.returncode != 0:
            return False, f"Could not restore Windows global DoT state: {self._friendly_command_error(result.stderr or result.stdout)}"
        return True, f"Original global DoT setting restored ({'enabled' if enabled else 'disabled'})."

    def _restore_snapshot(
        self,
        adapter: str,
        snapshot: dict[str, Any],
        *,
        doh_servers: list[str] | None = None,
        dot_servers: list[str] | None = None,
        restore_dot_global: bool = False,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        details: list[str] = []
        # Adapter names can be reused if a NIC is removed/reinstalled. Never
        # write a snapshot captured from a different interface GUID.
        current_before, preflight_error = self._capture_adapter_snapshot(
            adapter, include_dot=restore_dot_global, require_doh_inventory=bool(doh_servers)
        )
        if current_before is None:
            return False, "Could not safely identify the adapter before restoration. " + preflight_error, None
        expected_guid = str(snapshot.get("interface_guid", "")).strip().strip("{}")
        current_guid = str(current_before.get("interface_guid", "")).strip().strip("{}")
        if expected_guid and current_guid and expected_guid.casefold() != current_guid.casefold():
            return False, "The selected adapter no longer matches the saved restore point's interface identity. No settings were changed.", current_before
        okay, detail = self._restore_doh_entries(snapshot, doh_servers or [])
        details.append(detail)
        if not okay:
            return False, " ".join(details), None
        okay, detail = self._restore_dot_entries(snapshot, dot_servers or [])
        details.append(detail)
        if not okay:
            return False, " ".join(details), None
        if restore_dot_global:
            okay, detail = self._restore_dot_global(snapshot.get("dot_global"))
            details.append(detail)
            if not okay:
                return False, " ".join(details), None
        okay, detail = self._restore_adapter_addresses(adapter, snapshot)
        details.append(detail)
        if not okay:
            return False, " ".join(details), None
        cache_ok, cache_detail = self._flush_cache_strict()
        details.append(cache_detail)
        if not cache_ok:
            return False, " ".join(details), None
        current, capture_error = self._capture_adapter_snapshot(adapter, include_dot=restore_dot_global, require_doh_inventory=bool(doh_servers))
        if current is None:
            details.append(capture_error)
            return False, " ".join(details), None
        matches, mismatch = self._same_dns_configuration(
            snapshot, current, doh_servers=doh_servers or [], dot_servers=dot_servers or [],
            compare_dot_global=restore_dot_global,
        )
        if not matches:
            details.append("Post-restore verification failed: " + mismatch)
            return False, " ".join(details), current
        details.append("Adapter DNS configuration verified after restoration.")
        return True, " ".join(details), current

    @staticmethod
    def _same_dns_configuration(
        expected: dict[str, Any],
        actual: dict[str, Any],
        *,
        doh_servers: list[str] | None = None,
        dot_servers: list[str] | None = None,
        compare_dot_global: bool = False,
    ) -> tuple[bool, str]:
        """Compare the adapter state and only the registrations touched by a transaction."""
        expected_families = expected.get("families", {})
        actual_families = actual.get("families", {})
        failures: list[str] = []
        for family in ("IPv4", "IPv6"):
            before = expected_families.get(family, {})
            after = actual_families.get(family, {})
            before_mode = str(before.get("mode", "")).casefold()
            after_mode = str(after.get("mode", "")).casefold()
            if before_mode != after_mode:
                failures.append(f"{family} mode expected {before_mode}, got {after_mode}")
            if before_mode == "manual":
                before_servers = [str(x) for x in before.get("servers", [])]
                after_servers = [str(x) for x in after.get("servers", [])]
                if before_servers != after_servers:
                    failures.append(f"{family} manual server list differs")

        def normalized_entry(value: Any, *, doh: bool) -> dict[str, Any] | None:
            if not isinstance(value, dict):
                return None
            if doh:
                return {
                    "template": str(value.get("template", "")).rstrip("/"),
                    "auto_upgrade": bool(value.get("auto_upgrade", False)),
                    "fallback": bool(value.get("fallback", False)),
                }
            return {
                "doh_template": str(value.get("doh_template", ":")),
                "dot_host": str(value.get("dot_host", ":")).casefold(),
                "auto_upgrade": bool(value.get("auto_upgrade", False)),
                "udp_fallback": bool(value.get("udp_fallback", False)),
            }

        expected_doh = expected.get("doh_by_server", {})
        actual_doh = actual.get("doh_by_server", {})
        for server in doh_servers or []:
            normalized = str(server)
            if normalized_entry(expected_doh.get(normalized), doh=True) != normalized_entry(actual_doh.get(normalized), doh=True):
                failures.append(f"DoH template registration differs for {normalized}")

        expected_dot = expected.get("dot_by_server", {})
        actual_dot = actual.get("dot_by_server", {})
        for server in dot_servers or []:
            normalized = str(server)
            if normalized_entry(expected_dot.get(normalized), doh=False) != normalized_entry(actual_dot.get(normalized), doh=False):
                failures.append(f"DoT registration differs for {normalized}")

        if compare_dot_global and expected.get("dot_global") != actual.get("dot_global"):
            failures.append(
                f"Global DoT state expected {expected.get('dot_global')}, got {actual.get('dot_global')}"
            )
        return not failures, "; ".join(failures)

    def _rollback_transaction(
        self,
        adapter: str,
        snapshot_before: dict[str, Any],
        doh_servers: list[str],
        dot_servers: list[str],
        changes_dot_global: bool,
        reason: str,
    ) -> DNSOperationResult:
        try:
            restored, restore_detail, restored_snapshot = self._restore_snapshot(
                adapter, snapshot_before, doh_servers=doh_servers, dot_servers=dot_servers,
                restore_dot_global=changes_dot_global,
            )
        except Exception as exc:
            # Never let an unexpected rollback exception escape as an ordinary
            # worker error. The durable pending snapshot remains available for
            # the prominent manual recovery action on the next UI interaction.
            restored = False
            restored_snapshot = None
            restore_detail = (
                f"Automatic restoration raised {exc.__class__.__name__}: {exc}. "
                "The durable recovery record was retained; do not assume DNS is restored."
            )
        try:
            self.recovery_store.finish_rollback(adapter, restored_snapshot or snapshot_before, restored)
        except (OSError, RuntimeError, ValueError) as exc:
            restored = False
            restore_detail += f" Recovery state could not be finalized: {exc}"
        if restored:
            suffix = (
                "The previous DNS configuration was automatically restored and its Windows settings "
                "were verified by read-back. Network reachability was not used to judge rollback success."
            )
        else:
            connectivity_ok = False
            suffix = "AUTOMATIC RESTORATION COULD NOT BE CONFIRMED. Do not apply another DNS change; use Restore Previous DNS Settings and inspect the recovery report."
        return DNSOperationResult(
            False,
            reason,
            f"{restore_detail} {suffix}".strip(),
            verified=False,
            rollback_attempted=True,
            rollback_succeeded=restored,
            templates_registered=False if doh_servers else None,
        )

    @staticmethod
    def _probe_configured_dns_servers(servers: list[str], timeout: float = 0.9) -> tuple[bool, str]:
        """Probe the configured resolvers directly, without depending on Windows' cached resolver state."""
        from raider_dns.models import DNSProvider
        from raider_dns.services.dns_probe import probe_udp

        failures: list[str] = []
        for index, server in enumerate(servers, start=1):
            provider = DNSProvider(
                f"_raider_dns_verify_{index}", "Configured DNS resolver",
                "Post-apply direct DNS reachability check", server, "", "Verification",
            )
            try:
                result = probe_udp(provider, timeout=timeout)
            except Exception as exc:
                failures.append(f"{server}: {exc.__class__.__name__}")
                continue
            if result.success:
                return True, f"A direct DNS query to {server} succeeded in {result.latency_ms} ms."
            failures.append(f"{server}: {result.message}")
        detail = "; ".join(failures[:3]) or "No configured resolver returned a DNS response."
        return False, "Configured resolver reachability could not be confirmed: " + detail

    def _run_transaction(
        self,
        adapter: str,
        operation: Callable[[], DNSOperationResult],
        *,
        expected_servers: list[str] | None = None,
        expect_automatic: bool = False,
        expect_dnscrypt_loopback: bool = False,
        doh_servers: list[str] | None = None,
        expected_doh_templates: dict[str, str] | None = None,
        dot_servers: list[str] | None = None,
        changes_dot_global: bool = False,
        clear_restore_after_commit: bool = False,
        require_active_adapter: bool = True,
        connectivity_check: Callable[[], tuple[bool, str]] | None = None,
        flush_cache: bool = True,
        require_connectivity: bool = False,
    ) -> DNSOperationResult:
        doh_servers = list(dict.fromkeys(self._normalize_ip(value) for value in (doh_servers or [])))
        dot_servers = list(dict.fromkeys(self._normalize_ip(value) for value in (dot_servers or [])))
        with self._operation_lock, self._system_dns_mutex() as mutex_acquired:
            if not mutex_acquired:
                return DNSOperationResult(False, "Could not lock system DNS operations", "Another Raider DNS instance may be changing DNS, or Windows could not create/acquire the system DNS mutex. No changes were made.")
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "System DNS changes are supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Restart Raider DNS as administrator and retry.")
            available_adapters = self.get_adapters() if require_active_adapter else self.get_all_adapters()
            if not adapter or adapter not in available_adapters:
                qualifier = "active " if require_active_adapter else "installed "
                return DNSOperationResult(False, "Network adapter not available", f"Select an {qualifier}adapter. No changes were made.")
            if expected_servers is not None:
                if not expected_servers:
                    return DNSOperationResult(False, "No DNS servers specified", "No changes were made.")
                try:
                    for address in expected_servers:
                        self._normalize_ip(address)
                except ValueError as exc:
                    return DNSOperationResult(False, "Invalid DNS address", str(exc))
            before, capture_error = self._capture_adapter_snapshot(
                adapter, include_dot=changes_dot_global, require_doh_inventory=bool(doh_servers),
            )
            if before is None:
                return DNSOperationResult(False, "Could not save original DNS configuration", capture_error + " No changes were made.")
            if changes_dot_global and before.get("dot_global") not in (True, False):
                return DNSOperationResult(False, "Could not read original global DoT state", "Windows' original DoT setting could not be established. No changes were made.")
            try:
                # Persist all recovery material before the first system write.
                self.recovery_store.begin_transaction(
                    adapter, before, doh_servers=doh_servers, dot_servers=dot_servers,
                    changes_dot_global=changes_dot_global,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                return DNSOperationResult(False, "Could not create a safe DNS transaction", f"No DNS changes were made. {exc}")

            try:
                result = operation()
            except Exception as exc:
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    f"DNS operation raised {exc.__class__.__name__}: {exc}",
                )
            if not isinstance(result, DNSOperationResult):
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    "DNS operation returned an invalid result; the previous configuration is being restored.",
                )
            if not result.success:
                # The operation might have registered one resolver before a later
                # resolver failed, so even a reported failure must roll back.
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    f"{result.message}: {result.details}".strip(": "),
                )

            if flush_cache:
                flushed, flush_detail = self._flush_cache_strict()
                if not flushed:
                    # A cache-flush failure does not invalidate the Windows DNS
                    # settings themselves. Continue with authoritative read-back and
                    # retain the previous configuration as an explicit restore point.
                    flush_detail = "DNS cache flush was not confirmed: " + flush_detail
            else:
                flushed, flush_detail = True, "DNS cache flush skipped (disabled in settings)."
            after, after_error = self._capture_adapter_snapshot(
                adapter, include_dot=changes_dot_global, require_doh_inventory=bool(doh_servers),
            )
            if after is None:
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    "DNS settings were changed but the resulting configuration could not be read back. " + after_error,
                )
            matches, mismatch = self._expected_dns_matches(
                after, expected_servers=expected_servers, expect_automatic=expect_automatic,
                expect_dnscrypt_loopback=expect_dnscrypt_loopback,
            )
            if not matches:
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    "DNS configuration verification failed: " + mismatch,
                )

            if expected_doh_templates:
                for server, template in expected_doh_templates.items():
                    normalized = self._normalize_ip(server)
                    registered = after.get("doh_by_server", {}).get(normalized)
                    if not isinstance(registered, dict) or str(registered.get("template", "")).rstrip("/") != str(template).strip().rstrip("/"):
                        return self._rollback_transaction(
                            adapter, before, doh_servers, dot_servers, changes_dot_global,
                            f"DoH template registration was not verified for {normalized}; refusing to report the mode as active.",
                        )
                    if not bool(registered.get("auto_upgrade")) or bool(registered.get("fallback")):
                        return self._rollback_transaction(
                            adapter, before, doh_servers, dot_servers, changes_dot_global,
                            f"DoH template for {normalized} is not configured with required automatic upgrade and plaintext fallback disabled.",
                        )
                # A manually configured IPv6 DNS server can silently bypass a
                # provider's IPv4-only DoH setup. Do not report a secured mode if
                # any active static resolver is not independently registered for
                # encrypted DNS with plaintext fallback disabled.
                for family in ("IPv4", "IPv6"):
                    family_data = after.get("families", {}).get(family, {})
                    if str(family_data.get("mode", "")).casefold() != "manual":
                        continue
                    for active_server in family_data.get("servers", []):
                        normalized_active = self._normalize_ip(active_server)
                        registration = after.get("doh_by_server", {}).get(normalized_active)
                        if (
                            not isinstance(registration, dict)
                            or not str(registration.get("template", "")).strip().lower().startswith("https://")
                            or not bool(registration.get("auto_upgrade"))
                            or bool(registration.get("fallback"))
                        ):
                            return self._rollback_transaction(
                                adapter, before, doh_servers, dot_servers, changes_dot_global,
                                f"Encrypted DNS verification found manually configured {family} resolver {normalized_active} without a verified DoH template and plaintext-fallback-disabled policy. The previous configuration will be restored instead of leaving a mixed DNS setup.",
                            )

            if dot_servers:
                for server in dot_servers:
                    entry = after.get("dot_by_server", {}).get(server)
                    if (
                        not isinstance(entry, dict)
                        or str(entry.get("dot_host", "")).casefold() in {"", ":"}
                        or bool(entry.get("udp_fallback"))
                    ):
                        return self._rollback_transaction(
                            adapter, before, doh_servers, dot_servers, changes_dot_global,
                            f"DoT registration for {server} could not be verified with plaintext UDP fallback disabled.",
                        )
                # A leftover static IPv6 resolver could remain a plaintext path
                # while the IPv4 resolver uses DoT. Reject that mixed state.
                for family in ("IPv4", "IPv6"):
                    family_data = after.get("families", {}).get(family, {})
                    if str(family_data.get("mode", "")).casefold() != "manual":
                        continue
                    for active_server in family_data.get("servers", []):
                        normalized_active = self._normalize_ip(active_server)
                        entry = after.get("dot_by_server", {}).get(normalized_active)
                        if (
                            normalized_active not in dot_servers
                            or not isinstance(entry, dict)
                            or str(entry.get("dot_host", "")).casefold() in {"", ":"}
                            or bool(entry.get("udp_fallback"))
                        ):
                            return self._rollback_transaction(
                                adapter, before, doh_servers, dot_servers, changes_dot_global,
                                f"Encrypted DNS verification found active {family} resolver {normalized_active} without a verified DoT registration and disabled plaintext fallback. The previous configuration will be restored.",
                            )
                if after.get("dot_global") is not True:
                    return self._rollback_transaction(
                        adapter, before, doh_servers, dot_servers, changes_dot_global,
                        "Windows global DoT state was not verified enabled after applying the configuration.",
                    )

            # Adapter configuration and encrypted-transport registration are the
            # transaction's correctness criteria. Internet reachability is a
            # separate network condition: captive portals, filtered public DNS,
            # local firewalls and ISP policies must not silently undo a verified
            # Windows configuration. Keep the recovery point and report an
            # explicit warning when the optional reachability probe fails.
            check = connectivity_check or self.verify_dns_and_https
            try:
                resolver_reachable, connectivity_detail = check()
                resolver_reachable = bool(resolver_reachable)
                verified: bool | None = resolver_reachable and bool(flushed)
            except Exception as exc:
                resolver_reachable = False
                verified = False
                connectivity_detail = f"Reachability probe could not complete ({exc.__class__.__name__})."
            if not resolver_reachable and require_connectivity:
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    "The local DNS service did not answer a verification query; the previous adapter configuration is being restored. "
                    + str(connectivity_detail),
                )
            if verified is not True:
                warning_parts = []
                if not flushed:
                    warning_parts.append("DNS cache clearing could not be confirmed.")
                warning_parts.append(str(connectivity_detail))
                connectivity_detail = (
                    "Windows DNS settings were applied and read back successfully, "
                    "but resolver/internet reachability is unverified. The applied settings "
                    "were kept; use Restore Previous DNS Settings if they do not work. "
                    + " ".join(warning_parts)
                )
            try:
                self.recovery_store.commit_transaction(adapter, after, changes_dot_global=changes_dot_global)
                if clear_restore_after_commit:
                    self.recovery_store.complete_user_restore(adapter)
            except (OSError, RuntimeError, ValueError) as exc:
                return self._rollback_transaction(
                    adapter, before, doh_servers, dot_servers, changes_dot_global,
                    f"DNS settings passed read-back verification but the recovery record could not be committed: {exc}",
                )
            details = " ".join(part for part in [result.details, flush_detail, "Adapter DNS settings verified.", connectivity_detail] if part)
            if expected_doh_templates:
                details += " Registered DoH templates are tracked separately from active adapter DNS addresses."
            return DNSOperationResult(
                True, result.message, details, verified=verified,
                rollback_attempted=False, rollback_succeeded=None,
                templates_registered=bool(expected_doh_templates) if expected_doh_templates is not None else None,
            )

    def apply_dns(
        self,
        adapter: str,
        servers: list[str],
        doh_url: str | dict[str, str] | None = None,
        flush_cache: bool = True,
        *,
        allow_unverified_doh_preflight: bool = False,
    ) -> DNSOperationResult:
        if not servers:
            return DNSOperationResult(False, "No DNS servers specified", "No changes were made.")
        normalized_servers: list[str] = []
        try:
            normalized_servers = [self._normalize_ip(server) for server in servers]
        except ValueError as exc:
            return DNSOperationResult(False, "Invalid DNS address", f"{exc}. No changes were made.")
        templates: dict[str, str] | None = None
        doh_preflight_ok: bool | None = None
        doh_preflight_detail = ""
        if doh_url:
            templates = {}
            for server, normalized_server in zip(servers, normalized_servers):
                template = (doh_url.get(server) or doh_url.get(normalized_server)) if isinstance(doh_url, dict) else doh_url
                if not isinstance(template, str) or not template.strip():
                    return DNSOperationResult(False, "Missing DoH template", f"No DoH endpoint is configured for {server}. No changes were made.")
                if not template.strip().lower().startswith("https://"):
                    return DNSOperationResult(False, "Invalid DoH template", f"The DoH endpoint for {server} must be an HTTPS URL. No changes were made.")
                templates[normalized_server] = template.strip()
        if templates:
            if allow_unverified_doh_preflight:
                # This flag is set only after the user accepts the preflight
                # warning in the UI. Do not repeat the same slow network probe;
                # explicitly continue with an unverified status instead.
                doh_preflight_ok = False
                doh_preflight_detail = "Authenticated DoH preflight was bypassed after explicit user confirmation."
            else:
                # Test the real HTTPS endpoint over TLS using the configured
                # resolver IP before changing Windows DNS. This avoids relying
                # on the current resolver to resolve the endpoint hostname.
                from raider_dns.models import DNSProvider
                from raider_dns.services.dns_probe import probe_doh_endpoint
                checked_templates: set[str] = set()
                for server in normalized_servers:
                    template = templates[server]
                    if template in checked_templates:
                        continue
                    checked_templates.add(template)
                    matching = [address for address in normalized_servers if templates[address] == template]
                    preflight_provider = DNSProvider(
                        "_raider_dns_doh_preflight", "DoH endpoint preflight", "Preflight", matching[0],
                        matching[1] if len(matching) > 1 else "", "Preflight", doh_url=template,
                    )
                    try:
                        preflight = probe_doh_endpoint(preflight_provider)
                        preflight_success = bool(preflight.success)
                        preflight_message = preflight.message
                        preflight_latency = preflight.latency_ms
                    except Exception as exc:
                        preflight_success = False
                        preflight_message = f"Preflight could not complete ({exc.__class__.__name__})."
                        preflight_latency = None
                    if not preflight_success:
                        doh_preflight_ok = False
                        doh_preflight_detail = (
                            "The configured DoH endpoint could not be reached during authenticated HTTPS/DNS preflight: "
                            + preflight_message
                        )
                        return DNSOperationResult(
                            False, "DoH endpoint preflight failed",
                            "No Windows DNS settings were changed. " + doh_preflight_detail
                            + " You can explicitly choose to apply the Windows DoH registration anyway, but DNS may remain unavailable on this network.",
                        )
                    doh_preflight_ok = True
                    doh_preflight_detail = f"Authenticated DoH endpoint preflight succeeded in {preflight_latency} ms."

        if templates is not None:
            connectivity_check = lambda: (
                bool(doh_preflight_ok),
                doh_preflight_detail or "DoH endpoint reachability was not independently checked.",
            )
        else:
            connectivity_check = lambda: self._probe_configured_dns_servers(normalized_servers)

        return self._run_transaction(
            adapter,
            lambda: self._apply_dns_unchecked(adapter, normalized_servers, templates, False, prevalidated=True),
            expected_servers=normalized_servers,
            doh_servers=normalized_servers if templates is not None else [],
            expected_doh_templates=templates,
            connectivity_check=connectivity_check,
            flush_cache=flush_cache,
        )

    def apply_dnscrypt_loopback(self, adapter: str, flush_cache: bool = True) -> DNSOperationResult:
        return self._run_transaction(
            adapter,
            lambda: self._apply_dnscrypt_loopback_unchecked(adapter, False, prevalidated=True),
            expect_dnscrypt_loopback=True,
            connectivity_check=lambda: self._probe_configured_dns_servers(["127.0.0.1", "::1"], timeout=1.0),
            flush_cache=flush_cache,
            require_connectivity=True,
        )

    def apply_dot(
        self, adapter: str, servers: list[str], dot_hostname: str, flush_cache: bool = True,
        *, allow_unverified_preflight: bool = False,
    ) -> DNSOperationResult:
        # Validate all user input before capturing/persisting a transaction. This
        # avoids needless recovery state and any partial mutation for bad input.
        if not servers:
            return DNSOperationResult(False, "No DNS servers specified", "No changes were made.")
        try:
            normalized = [self._normalize_ip(server) for server in servers]
        except ValueError as exc:
            return DNSOperationResult(False, "Invalid DNS address", f"{exc}. No changes were made.")
        host = str(dot_hostname or "").strip().rstrip(".")
        hostname_pattern = r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+\.?$"
        if not re.fullmatch(hostname_pattern, host):
            return DNSOperationResult(False, "Invalid DoT hostname", "Enter a valid DNS hostname without a scheme, port, path or spaces. No changes were made.")
        if not self.is_windows():
            return DNSOperationResult(False, "Windows-only operation", "Native Windows DNS Client DoT is supported only on Windows.")
        if not self.is_admin():
            return DNSOperationResult(False, "Administrator permission required", "Restart Raider DNS as administrator and retry. No system changes were made.")
        # The transaction validates the adapter before any system write. The
        # authenticated preflight below is read-only and is independent of it.
        # Enforce authenticated DoT reachability at the service boundary, not
        # only in the UI. Other callers/tests must not be able to change system
        # DNS before the TLS certificate hostname and DNS response are checked.
        from raider_dns.models import DNSProvider
        from raider_dns.services.dns_probe import probe_dot
        test_provider = DNSProvider(
            "_raider_dns_dot_preflight", "DoT preflight", "Authenticated DNS-over-TLS preflight",
            normalized[0], normalized[1] if len(normalized) > 1 else "", "Preflight",
            dot_hostname=host,
        )
        preflight_ok = False
        preflight_detail = ""
        if allow_unverified_preflight:
            # The user has already accepted the initial failure prompt. Avoid
            # repeating the same preflight request on the second apply attempt.
            preflight_detail = "Authenticated DoT preflight was bypassed after explicit user confirmation."
        else:
            try:
                preflight = probe_dot(test_provider)
                preflight_ok = bool(preflight.success)
                preflight_detail = (
                    f"Authenticated DoT preflight succeeded in {preflight.latency_ms} ms."
                    if preflight_ok else f"DoT endpoint preflight could not be verified for {host}:853. {preflight.message}"
                )
            except Exception as exc:
                preflight_detail = f"DoT endpoint preflight could not complete ({exc.__class__.__name__})."
        if not preflight_ok and not allow_unverified_preflight:
            return DNSOperationResult(
                False, "DNS-over-TLS preflight failed",
                "No system changes were made. " + preflight_detail
                + " You can explicitly choose to apply the Windows DoT registration anyway, but DNS may remain unavailable on this network.",
            )
        result = self._run_transaction(
            adapter,
            lambda: self._apply_dot_unchecked(adapter, normalized, host, False, prevalidated=True),
            expected_servers=normalized, dot_servers=normalized, changes_dot_global=True,
            connectivity_check=lambda: (preflight_ok, preflight_detail),
            flush_cache=flush_cache,
        )
        if result.success:
            result.details = f"{preflight_detail} {result.details}".strip()
        return result

    def restore_dhcp(self, adapter: str, flush_cache: bool = True) -> DNSOperationResult:
        return self._run_transaction(
            adapter,
            lambda: self._restore_dhcp_unchecked(adapter, False, prevalidated=True),
            expect_automatic=True,
            # Keep the pre-change restore point so users can return to the exact
            # manual/automatic IPv4/IPv6 state they had before Raider DNS changed it.
            clear_restore_after_commit=False,
            require_active_adapter=False,
            connectivity_check=self.verify_dns_and_https,
            flush_cache=flush_cache,
        )

    def has_previous_settings(self, adapter: str) -> bool:
        try:
            return self.recovery_store.has_previous_settings(adapter)
        except (OSError, RuntimeError, ValueError):
            # Treat a damaged/unreadable recovery database as actionable rather
            # than silently hiding the recovery affordance.
            return True

    def restore_previous_dns_settings(self, adapter: str) -> DNSOperationResult:
        """Restore this adapter's persisted baseline or pending pre-crash snapshot."""
        with self._operation_lock, self._system_dns_mutex() as mutex_acquired:
            if not mutex_acquired:
                return DNSOperationResult(False, "Could not lock system DNS operations", "Another Raider DNS instance may be changing DNS, or Windows could not create/acquire the system DNS mutex. No changes were made.")
            if not self.is_windows():
                return DNSOperationResult(False, "Windows-only operation", "DNS recovery is supported only on Windows.")
            if not self.is_admin():
                return DNSOperationResult(False, "Administrator permission required", "Restart Raider DNS as administrator before restoring DNS settings.")
            if not adapter or adapter not in self.get_all_adapters():
                return DNSOperationResult(False, "Network adapter not available", "The adapter is no longer installed, so this saved DNS configuration cannot be restored to it.")
            try:
                target_tuple = self.recovery_store.get_restore_target(adapter)
            except (OSError, RuntimeError, ValueError) as exc:
                return DNSOperationResult(False, "DNS recovery data unavailable", f"No settings were changed. {exc}")
            if target_tuple is None:
                return DNSOperationResult(False, "No previous DNS settings found", "Apply DNS through Raider DNS first, or inspect the recovery file.")
            target, record, is_pending = target_tuple
            current, capture_error = self._capture_adapter_snapshot(
                adapter,
                include_dot=bool(record.get("dot_global_baseline_known")) or bool(record.get("pending_changes_dot_global")),
                require_doh_inventory=bool(record.get("doh_baseline")) or bool(record.get("pending_doh_servers")),
            )
            if current is None:
                return DNSOperationResult(False, "Could not capture current DNS before recovery", capture_error + " No changes were made.")

            if is_pending:
                target_doh = list(record.get("pending_doh_servers", []))
                target_dot = list(record.get("pending_dot_servers", []))
                restore_global = bool(record.get("pending_changes_dot_global"))
            else:
                target = json.loads(json.dumps(target))
                # Merge the original per-server registration values captured before
                # Raider first touched each endpoint, independently of adapter state.
                target_doh = list(record.get("doh_baseline", {}).keys())
                target_dot = list(record.get("dot_baseline", {}).keys())
                target_doh_map = dict(target.get("doh_by_server", {}))
                target_doh_map.update(record.get("doh_baseline", {}))
                target["doh_by_server"] = target_doh_map
                target_dot_map = dict(target.get("dot_by_server", {}))
                target_dot_map.update(record.get("dot_baseline", {}))
                target["dot_by_server"] = target_dot_map
                if record.get("dot_global_baseline_known"):
                    target["dot_global"] = record.get("dot_global_baseline")
                restore_global = bool(record.get("dot_global_baseline_known"))

            if not is_pending:
                try:
                    self.recovery_store.begin_transaction(
                        adapter, current, doh_servers=target_doh, dot_servers=target_dot,
                        changes_dot_global=restore_global,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    return DNSOperationResult(False, "Could not prepare safe DNS restoration", str(exc))

            try:
                restored, detail, restored_snapshot = self._restore_snapshot(
                    adapter, target, doh_servers=target_doh, dot_servers=target_dot,
                    restore_dot_global=restore_global,
                )
            except Exception as exc:
                restored, restored_snapshot = False, None
                detail = (
                    f"Restoration raised {exc.__class__.__name__}: {exc}. "
                    "The saved pending recovery record was retained."
                )
            if not restored:
                try:
                    # If restoring the previous state failed, attempt to return to
                    # the pre-recovery state. Keep a pending snapshot if this fails.
                    try:
                        rolled_back, rollback_detail, now = self._restore_snapshot(
                            adapter, current,
                            doh_servers=target_doh,
                            dot_servers=target_dot,
                            restore_dot_global=restore_global,
                        )
                    except Exception as rollback_exc:
                        rolled_back, now = False, None
                        rollback_detail = f"Rollback raised {rollback_exc.__class__.__name__}: {rollback_exc}; recovery data remains pending."
                    self.recovery_store.finish_rollback(adapter, now or current, rolled_back)
                    detail += f" Recovery attempt failed; rollback to the pre-recovery configuration: {rollback_detail}"
                except Exception as exc:
                    detail += f" Recovery rollback also failed: {exc}"
                return DNSOperationResult(False, "Could not completely restore the previous DNS settings", detail, verified=False, rollback_attempted=True, rollback_succeeded=False)

            connectivity_ok, connectivity_detail = self.verify_dns_and_https()
            if is_pending:
                self.recovery_store.finish_rollback(adapter, restored_snapshot or target, True)
            else:
                # The explicit Restore Previous action prioritizes restoring the
                # user's baseline. If public HTTPS is still blocked afterward, do
                # not put the possibly broken Raider config back on the interface.
                self.recovery_store.complete_user_restore(adapter)
            note = "Previous DNS configuration restored. " + detail + " " + connectivity_detail
            if not connectivity_ok:
                note += " The saved configuration was restored, but internet connectivity could not be verified. Check the adapter and any captive-portal/proxy requirements; Raider DNS did not reapply the newer DNS settings."
            return DNSOperationResult(
                True,
                "Previous DNS settings restored" if connectivity_ok else "Previous DNS settings restored; connectivity needs attention",
                note,
                verified=connectivity_ok,
                rollback_attempted=False,
                rollback_succeeded=None,
            )
