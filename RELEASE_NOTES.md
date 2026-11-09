# Raider DNS 0.2 Beta — Release Notes

**Release:** 0.2.0-beta  
**Platform:** Windows 10 / Windows 11 (x64)  
**Technology:** Python · PySide6 · Windows DNS Client  
**Author:** Nima Zahedi — Shattered-Devil

Raider DNS 0.2 Beta expands the application from a straightforward DNS switcher into a Windows DNS management and network diagnostics suite. This release brings together encrypted DNS integrations, managed DNS engines, resolver benchmarking, domain filtering, network-aware diagnostics, and safer DNS configuration workflows.

## Highlights

### Simplified and safer Standard DNS

- Applies exactly the selected provider's DNS addresses to the selected Windows adapter and requested address family.
- Does not append unrelated providers to the ordinary DNS server list.
- Does not modify global Windows DoH policy, routes, proxies, Winsock settings, drivers, or unrelated adapters as part of Standard DNS switching.
- Captures a durable restore point and reads the resulting Windows DNS configuration back.
- In the normal verification workflow, compares Windows DNS and HTTPS/TLS health before and after the change. A persistent regression of a previously healthy dimension triggers restoration of the previous configuration.
- Separates direct resolver reachability from Windows' effective DNS and HTTPS health.

### Regional Rules

Settings includes manually selected Global and Iran network profiles. Global is selected by default.

The Iran profile uses longer bounded DNS/resolver timeouts, additional rechecks, and treats external HTTPS diagnostic failures as advisory. A persistent loss of previously working Windows DNS still triggers exact rollback in the normal verification workflow. Region selection is a user preference; the application does not geolocate the user or assume that every network in a country behaves identically.

### Restricted Network Mode

An independent On/Off switch is available under Settings → Regional Rules. It is Off by default and applies to Standard DNS only.

When enabled:

- DNS resolver queries, Windows DNS Client resolution checks, HTTPS/TLS checks, pre-change connectivity baselines, and post-change health retries are skipped.
- After applying DNS, Raider DNS performs adapter-bound ICMP ping measurements to the configured DNS IP addresses.
- If neither address replies, the new DNS settings remain installed and an embedded Dashboard panel asks whether to restore the previous DNS settings or keep the new settings.
- A ping failure is not presented as proof that DNS is unavailable. Some networks block ICMP while allowing DNS.
- Windows command success, exact DNS configuration read-back, and durable recovery-snapshot persistence remain required.
- Automatic background resolver monitoring and automatic resolver failover are paused for Standard DNS while this mode is active. User-initiated diagnostics and benchmarks remain available.

### Route-aware adapter diagnostics

- Uses Windows route information to identify the preferred interface for actual destinations.
- Shows the selected adapter, interface index, route/source address, gateway, and resolver route context where available.
- Warns when the selected adapter differs from the preferred default-route adapter without silently changing the user's selection.
- Separates adapter-bound resolver probes from Windows system-wide DNS lookup results.

### Expanded DNS Tools

- DNS record lookup for A, AAAA, CNAME, MX, TXT, NS, SOA, and PTR.
- Optional explicit resolver selection.
- HTTP/HTTPS URL hostname normalization.
- Bounded, read-only Windows DNS cache inspection.
- Existing DNS cache flush and connectivity diagnostics.
- Domain block/allow controls accepting domains, full URLs, and leading wildcard patterns such as `*.example.com`.
- Block/allow rules are applied through DNSCrypt Proxy local filtering; they do not filter Standard DNS by themselves.

## Other major capabilities

### DNS providers and profiles

- Built-in and custom DNS providers.
- Search, favorites, provider ordering, and reusable DNS profiles.
- Profile creation, application, deletion, import, and export.
- Opt-in exact-match network profile matching based on saved SSID and/or adapter identity.
- Local profile storage.

### Encrypted DNS and engines

- Windows-native DoH and DoT configuration and diagnostics.
- Supported browser-specific DoH controls.
- Official DNSCrypt Proxy management for encrypted DNS, local filtering, forwarding, Split DNS, resolver pools, and optional query logging.
- Optional sing-box TUN engine integration for user-provided traffic-routing profiles.
- Engine Supervisor monitoring for managed DNSCrypt Proxy and sing-box processes.

DNS encryption protects DNS lookups; it does not automatically encrypt all application traffic. sing-box TUN is a separate feature that routes traffic according to the user's profile. Raider DNS does not provide VPN servers, proxy subscriptions, credentials, or remote endpoints.

### Benchmark Lab

- DNS query and resolver response-time measurements.
- Repeated query samples, including warm-cache and unique-name workflows.
- Median, P95, jitter, min/max, and success-rate summaries where supported.
- Separate ICMP and TCP connection measurements.
- Resolver comparison, ranking, and supported result export.

### Diagnostics and recovery

- Selected-adapter route, IP, gateway, and neighbor-state diagnostics.
- Direct UDP DNS probes and Windows DNS Client A/AAAA checks.
- DoH/DoT configuration and endpoint diagnostics where supported.
- TCP and HTTPS/TLS connectivity checks.
- Windows DNS Client service status.
- Manual, selected-adapter recovery actions and evidence-based repair recommendations.
- Transactional DNS restoration using the captured previous configuration.

### Interface and application management

- Nine themes: Dark, Light, Light Mild, Paper, Warm Sand, Mist Blue, Midnight, Ocean, and High Contrast.
- English and Persian interface selection with Persian RTL layout.
- Nine-page navigation and refreshed Dashboard.
- Plasma Stream visual with four ribbons and eleven filaments.
- Local Activity Log with configurable retention.
- Settings backup and restore.
- Single-instance behavior, improved administrator relaunch handling, tray lifecycle, and safer shutdown.

## Installation and optional components

Download the release assets from the official GitHub Releases page:

https://github.com/Shattered-Devil/Raider-DNS/releases

The core Raider DNS application is required. DNSCrypt Proxy and sing-box TUN are separate advanced components and are optional in the installer when their verified payloads are included. They are not required for Standard DNS switching. Installing an engine does not automatically activate it.

Before uninstalling, restore the previous DNS configuration if an adapter depends on DNSCrypt loopback, and stop any active sing-box TUN tunnel from Raider DNS. Do not manually delete unknown VPN routes or adapters.

## Important limitations and safety notes

- Standard DNS changes Windows DNS addresses; it does not encrypt DNS traffic.
- DoH, DoT, and DNSCrypt encrypt DNS queries, not all application traffic.
- DNSCrypt filtering only affects queries that pass through the local DNSCrypt Proxy.
- sing-box TUN behavior depends on the user-provided profile and reachable remote endpoint.
- ICMP ping is not a DNS functionality test. A failed ping does not prove that DNS is unreachable.
- Windows-wide DNS policies, VPNs, firewalls, browser-native DoH, and multiple active adapters can affect effective DNS behavior.
- Review diagnostic exports and DNS query logs before sharing them; they can reveal domains and local network details.
- Test DNS changes, adapter operations, encrypted transports, TUN routing, engine shutdown, and installer behavior on a disposable Windows 10/11 system before relying on the application on a primary machine.

## Validation

The current source release records:

- **366 pytest tests passed**, with 1 optional test skipped and 49 subtests passed.
- **367 unittest tests run**, with 1 skipped.
- Python compilation passed.
- Source ZIP integrity and clean extraction checks passed.

The available test environment did not provide live Windows adapter operations or PySide6 GUI rendering. These automated results do not prove that DNS/PowerShell operations, ICMP binding, DoH/DoT, DNSCrypt loopback, sing-box TUN routing, GUI rendering, or Inno Setup compilation work on every Windows system. Those require live Windows validation.

## Project links

- Repository: https://github.com/Shattered-Devil/Raider-DNS
- Releases: https://github.com/Shattered-Devil/Raider-DNS/releases
- Issues: https://github.com/Shattered-Devil/Raider-DNS/issues

**Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil**
