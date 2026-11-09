# Raider DNS

<p align="center">
  <strong>Windows DNS Management · Encrypted DNS · Network Diagnostics · Traffic Tunneling</strong>
</p>

<p align="center">
  <a href="https://github.com/Shattered-Devil/Raider-DNS/releases"><img src="https://img.shields.io/badge/Release-0.2%20Beta-168aad?style=for-the-badge" alt="Release 0.2 Beta"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D4?style=for-the-badge" alt="Windows 10 and 11">
  <img src="https://img.shields.io/badge/Interface-Python%20%7C%20PySide6-41A5D8?style=for-the-badge" alt="Python and PySide6">
  <a href="https://github.com/Shattered-Devil/Raider-DNS"><img src="https://img.shields.io/badge/Repository-Shattered--Devil-181717?style=for-the-badge&logo=github" alt="GitHub repository"></a>
</p>

<p align="center"><em>Secure · Optimize · Stay Connected</em></p>

---

## Overview

**Raider DNS** is a Windows desktop application for managing system DNS, configuring supported encrypted DNS transports, measuring resolver performance, diagnosing network connectivity, and managing optional local DNS and traffic-routing engines.

Built with **Python and PySide6**, Raider DNS brings together:

- Windows Standard DNS configuration for selected network adapters.
- Windows-native DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) management where supported.
- Supported browser-specific DoH controls.
- DNSCrypt Proxy management for local encrypted DNS, filtering, forwarding, and Split DNS.
- Optional sing-box TUN integration for profile-driven device traffic routing.
- DNS provider catalogue and reusable DNS profiles.
- Resolver benchmarking, DNS tools, diagnostics, and local activity history.
- Regional verification rules and a separate Restricted Network Mode.

> **Release status: 0.2 Beta.** Raider DNS can change machine-level network configuration and can manage optional DNS/TUN engines. Test DNS changes, adapter operations, encrypted transports, engine shutdown, and installer behavior in a disposable Windows 10/11 environment before relying on the application on a primary system. Automated source tests do not replace live Windows network validation.

## What's new since 0.1.7

Raider DNS 0.2 Beta introduces a substantial expansion of the application:

- **Redesigned application navigation:** nine main pages with a consolidated Dashboard and reusable DNS profiles integrated into DNS Providers.
- **Simplified Standard DNS:** applies the exact selected provider address list to the selected adapter, without appending unrelated fallback providers or changing global Windows DoH policy.
- **Safer DNS transactions:** durable recovery snapshots, Windows configuration read-back, before/after health comparisons in the normal verification workflow, and exact rollback after a confirmed persistent regression.
- **Regional Rules:** manually selectable Global and Iran verification profiles, with Global as the default.
- **Restricted Network Mode:** an independent ping-only Standard DNS workflow with an embedded Restore previous DNS / Keep new DNS decision when neither configured DNS IP replies to ICMP.
- **Route-aware adapter diagnostics:** Windows route/source-interface inspection, selected-adapter context, resolver route information, and warnings when the selected adapter differs from the preferred internet route.
- **Expanded DNS Tools:** A, AAAA, CNAME, MX, TXT, NS, SOA, and PTR lookup; optional resolver selection; URL normalization; and a bounded Windows DNS cache inspector.
- **Domain filtering controls:** editable DNSCrypt block/allow rules supporting domains, URLs, and leading wildcard patterns.
- **DNSCrypt Proxy management:** resolver configuration, local filtering, forwarding, Split DNS, optional query logging, and engine lifecycle management.
- **Optional sing-box TUN integration:** user-provided profile validation and managed start/stop controls for separate traffic routing.
- **Engine Supervisor:** bounded process monitoring and deduplicated unexpected-exit notifications without automatic restarts or force-killing unrelated processes.
- **Advanced Benchmark Lab:** repeated DNS measurements and latency/reliability statistics.
- **Expanded Diagnostics and recovery guidance:** Windows DNS, DoH/DoT, adapter route, gateway, neighbor, TCP, HTTPS, and DNS Client service checks, plus selected manual repair actions.
- **Interface improvements:** nine themes, Persian RTL layout, theme-aware switches, refreshed navigation, and the Plasma Stream visual.
- **Local data and release improvements:** activity history, retention controls, settings backup/restore, optional engine installer components, and expanded release/security documentation.

See [`CHANGELOG.md`](CHANGELOG.md) for the complete consolidated feature history and [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for the current beta release summary.

## Main capabilities

### 1. Dashboard and network context

The Dashboard is the primary status overview. It brings key connection context together rather than using a separate Network Intelligence page.

- Shows selected DNS mode and provider context.
- Presents connection status and available DNS health/measurement summaries.
- Displays saved automatic-profile match context where applicable without exposing SSIDs or adapter identifiers in the profile summary.
- Shows managed DNSCrypt and sing-box engine state.
- Provides access to common DNS apply, restore, and cache actions.
- Includes **Plasma Stream**, with four animated ribbons and eleven fine filaments.
- Displays the Restricted Network Mode Restore/Keep decision panel when a ping-only Standard DNS attempt finds no ICMP response from the configured DNS addresses.

The Dashboard intentionally does not display a detailed Wi-Fi/adapter hardware inventory. Detailed route and connectivity information belongs in Diagnostics.

### 2. DNS Connections and transport modes

The Connections page brings DNS transport selection and optional local engines together.

| Mode | Scope | What it does | Separate engine |
|---|---|---|---|
| Standard DNS | Windows system DNS | Applies ordinary resolver addresses to the selected Windows adapter and selected address family. | No |
| Windows DoH | Windows system DNS | Uses supported Windows DNS Client encrypted-DNS registration and adapter configuration. | No separate Raider-managed engine |
| Windows DoT | Windows system DNS | Configures supported Windows DNS-over-TLS behavior using resolver identity/hostname information. | No separate Raider-managed engine |
| Browser DoH | Supported browser | Configures the browser's own secure-DNS behavior and supported scope settings. | Browser dependent |
| DNSCrypt Proxy | Local DNS path | Points Windows DNS to the local DNSCrypt Proxy after the local listener/query checks succeed. | `dnscrypt-proxy.exe` |
| sing-box TUN | Device IP traffic | Runs a user-provided sing-box TUN profile to route traffic according to its inbound, outbound, and routing rules. | `sing-box.exe` |

**Important distinction:** DoH, DoT, and DNSCrypt encrypt DNS lookups; they do not automatically tunnel all application traffic. sing-box TUN is a separate traffic-routing feature. Its behavior depends on the user's profile and a working remote endpoint.

### 3. DNS Providers and reusable profiles

The DNS Providers page combines the resolver catalogue with reusable DNS profiles.

- Browse built-in DNS providers.
- Add and manage custom providers.
- Search and organize the provider catalogue.
- Mark providers as favorites and reorder them.
- Create, apply, and delete reusable DNS profiles.
- Import and export supported provider/profile data.
- Keep saved configuration data locally in the application's user data area.
- Use opt-in exact-match network-profile matching based on saved SSID and/or adapter identity.

Automatic profile application is limited to supported Standard DNS and Windows-native DoH workflows and requires the necessary elevation. Other saved transport profiles can remain available for manual use. Automatic profile matching is not fuzzy matching and does not silently change the user's selected adapter.

### 4. Regional Rules and Restricted Network Mode

Settings → **Regional Rules** contains two independent controls.

#### Region profile

- **Global** is the default profile and uses the normal verification timeouts and policy.
- **Iran** uses longer bounded DNS/resolver timeouts, additional rechecks, and treats external HTTPS diagnostic failures as advisory. A persistent loss of previously working Windows DNS still triggers exact rollback in the normal verification workflow.

The region is selected manually. Raider DNS does not geolocate the user or assume every ISP, access network, or connection in a country behaves identically.

#### Restricted Network Mode

Restricted Network Mode is a separate On/Off switch, disabled by default. It applies to **Standard DNS only**; it does not alter DoH, DoT, or DNSCrypt transactions.

When enabled, Standard DNS uses a minimal post-apply reachability workflow:

1. Save the previous DNS configuration and apply the selected DNS addresses.
2. Confirm that Windows accepted the configuration and read the exact addresses back.
3. Ping the configured DNS IP addresses from the selected adapter and measure ICMP latency.
4. If neither DNS IP replies, keep the new settings installed and show an embedded Dashboard choice: **Restore previous DNS** or **Keep new DNS**.

The following connectivity checks are skipped in this mode: the pre-change DNS/HTTPS health baseline, direct DNS resolver queries, Windows DNS Client resolution checks, HTTPS/TLS checks, and post-change health retries. Automatic background DNS resolver monitoring and automatic resolver failover are paused for Standard DNS while the mode is active. User-initiated diagnostics and benchmarks remain available.

Windows command success, exact selected-adapter DNS read-back, and durable recovery-snapshot persistence remain required configuration-integrity safeguards. A failure in those operations is not ignored.

**ICMP limitation:** A failed ping means that no ICMP echo response was received. It does not prove that DNS queries cannot work; some networks block ping while allowing DNS. If ping cannot be attempted on the selected adapter, the app reports that limitation instead of calling the DNS server unreachable.

### 5. DNSCrypt Proxy management and filtering

Raider DNS manages the official DNSCrypt Proxy executable as an external local process; it does not implement a replacement DNSCrypt protocol engine.

Supported management areas include:

- Managed engine start/stop and status reporting.
- Local configuration generation and validation.
- Resolver selection and supported resolver-pool/load-balancing configuration.
- DNS filtering using supported block and allow rules.
- Forwarding rules for supported Split DNS scenarios.
- Optional DNS query logging and a local query monitor.
- Safe handling of configuration changes and service shutdown.

DNSCrypt uses a local loopback listener. Raider DNS checks the local proxy path before leaving Windows adapter DNS pointed at loopback. If an adapter may still depend on the local proxy, the application should not simply remove or stop the engine without resolving that dependency.

#### Domain rule input

DNS Tools accepts domain names, full HTTP/HTTPS URLs, and leading wildcard patterns such as `*.example.com` for supported DNSCrypt filtering rules.

**Filtering scope:** these rules are applied by DNSCrypt Proxy local filtering. They do not block domains in Standard DNS mode, and they do not control browser/application traffic that bypasses the system DNS path.

**Logging privacy:** DNS query logging is off by default. Query logs can contain domain names, resolver details, timestamps, and local client addresses. Enable it only when needed and review the log before sharing it.

### 6. sing-box TUN traffic routing

Raider DNS integrates the official sing-box command-line engine as a separately managed process.

- The executable is discovered from the Raider DNS installation's managed engine directory; the UI does not ask users to browse for an arbitrary EXE.
- Users select a compatible sing-box JSON profile.
- The profile is checked with the bundled CLI before the application attempts to start the tunnel.
- The Connections page provides distinct validation, start, and stop actions.
- Engine state is exposed to the Dashboard and Engine Supervisor.
- The tunnel uses the profile's TUN inbound, outbound, DNS, and routing rules.

**What is not included:** Raider DNS does not provide a VPN server, proxy subscription, account, endpoint, or credentials. Users must supply a valid profile and have access to a working remote proxy/server. TUN routing generally requires administrator privileges. A running process alone does not prove that every application's traffic or DNS is routed as intended; test routes and DNS behavior on the target Windows system.

### 7. Engine Supervisor

The Engine Supervisor monitors Raider DNS-managed DNSCrypt Proxy and sing-box process state.

- Detects whether managed processes are running.
- Distinguishes expected user-requested stops from unexpected exits where controller state permits.
- Reports unexpected process termination to the user.
- Uses bounded polling and local process state.
- Does not automatically restart a failed engine.
- Does not force-kill processes or terminate unrelated processes with the same executable name.
- Does not treat process existence as proof of resolver reachability, proxy health, route integrity, or leak-free traffic.

### 8. DNS Security Center

The DNS Security Center provides a place to inspect DNS security-related configuration and run supported checks.

- Review relevant Windows DNS and encrypted-DNS configuration.
- Inspect supported DoH template registration/configuration state.
- Review DNS health information.
- Run the available DNS audit.
- Run an external DNS leak test when the user chooses to do so.

An external leak test contacts a third-party service. That service may observe the public IP address and recursive resolvers used during the test. The test does not automatically inspect every browser's independent DoH traffic.

### 9. DNS Tools

DNS Tools combines record lookups, cache inspection, filtering-rule entry, and related diagnostics.

Supported DNS record types:

- `A` — IPv4 address.
- `AAAA` — IPv6 address.
- `CNAME` — canonical name.
- `MX` — mail exchanger.
- `TXT` — text records.
- `NS` — name servers.
- `SOA` — start of authority.
- `PTR` — reverse lookup.

The lookup workflow supports an optional explicit resolver IP and normalizes pasted HTTP/HTTPS website URLs to their hostname. The Windows DNS cache inspector is read-only and bounded; cache flush remains a separate user action.

### 10. Benchmark Lab

Raider DNS includes resolver measurement tools so provider selection is based on measured behavior rather than assumptions.

Available measurements include:

- Actual DNS query/response latency.
- TCP connection time to port 53.
- ICMP round-trip time where Windows and the network permit it.
- Repeated same-name queries and unique-name query samples in the advanced benchmark workflow.
- Summary statistics such as median, P95, jitter, minimum/maximum latency, and success rate where available.
- Resolver comparison and ranking from completed measurements.
- Export of supported benchmark results.

ICMP latency, TCP connection time, and DNS query latency measure different things. A low ping does not necessarily mean a resolver returns DNS answers faster. Results are network-, resolver-, and time-dependent; rerun tests when conditions change.

### 11. Diagnostics and recovery guidance

Diagnostics helps investigate connectivity and DNS issues through user-initiated checks and selective repairs.

- Connectivity and DNS checks.
- DNS and HTTPS reachability checks where applicable.
- Selected-link, gateway, IP, IPv4/IPv6 route, and relevant connection tests.
- ARP/NDP neighbor-state inspection.
- Configured resolver UDP checks and Windows DNS A/AAAA resolution checks.
- Supported DoH/DoT configuration and endpoint checks.
- Windows DNS Client service status.
- Actionable, non-destructive recovery guidance.
- Supported manual repair operations with explicit user action.

Manual repair options include starting a stopped Windows DNS Client service, clearing the selected adapter's neighbor cache, and restarting the selected adapter. Automatic recovery recommendations are limited to conditions with supporting diagnostic evidence. Broad Winsock/TCP/IP/IPv6 resets, proxy resets, driver operations, and arbitrary process/route cleanup are not performed automatically.

### 12. Activity Log

The Activity Log provides a local history of supported application actions and outcomes.

- Records supported DNS operations, diagnostics, repairs, imports, and application actions.
- Supports reviewing and exporting history where available.
- Uses configurable retention limits to prevent unbounded growth.
- Remains local to the user's machine unless the user exports and shares it.

Review exported logs before sharing them; diagnostic details may reveal domain names, addresses, or local network information.

### 13. Settings, themes, and language

- Nine themes: Dark, Light, Light Mild, Paper, Warm Sand, Mist Blue, Midnight, Ocean, and High Contrast.
- Theme-aware switches with checked, unchecked, knob, and focus colors derived from the active Raider DNS theme.
- English and Persian language selection.
- Persian right-to-left layout support for the application interface.
- Fixed tooltip delay of 750 ms.
- DNS health check interval, timeout, failure, and recovery thresholds.
- Engine Supervisor enablement and polling interval.
- Network-change polling preferences.
- Settings backup/export and restore/import workflows.
- Configurable local activity-history retention.

Some operating-system, provider-supplied, and third-party engine messages may remain in their original language even when the application interface is set to Persian.

---

## DNS change safety

Changing system DNS affects the machine's network configuration. Raider DNS uses a transactional approach for supported Windows DNS operations:

1. Identify the selected adapter and validate the requested settings.
2. Capture and persist a recovery snapshot before changing the adapter.
3. Serialize conflicting DNS mutations so overlapping operations do not race.
4. Apply the requested DNS configuration.
5. Read the resulting Windows configuration back and perform checks appropriate to the selected mode.
6. Keep recovery information available so the previous configuration can be restored if required.
7. In the normal verification workflow, retry and roll back when a previously healthy DNS or HTTPS/TLS dimension has a confirmed persistent regression.

Restricted Network Mode intentionally uses a different Standard DNS post-apply policy: it performs ICMP ping measurements only and asks the user whether to restore or keep DNS if neither configured address replies. It does not claim that ping proves DNS functionality.

Use **Restore Previous DNS Settings** to restore the saved previous configuration. This is not the same as selecting automatic/DHCP DNS: the previous configuration may have been a manually configured resolver.

## Feature boundaries and limitations

| Feature | Does | Does not guarantee |
|---|---|---|
| Standard DNS | Changes configured resolver addresses. | Encryption or resolver availability. |
| Restricted Network Mode | Measures ICMP reachability and lets the user decide whether to restore. | Successful DNS resolution. |
| DoH / DoT | Configures supported encrypted DNS behavior. | Encryption for all application traffic. |
| Browser DoH | Changes DNS behavior for supported browsers. | System-wide DNS behavior or control over unsupported browsers. |
| DNSCrypt | Uses a local DNSCrypt Proxy for DNS queries sent to it. | Filtering of browser/app traffic that bypasses system DNS. |
| Split DNS | Forwards matching DNS names according to DNSCrypt rules. | General IP traffic splitting. |
| sing-box TUN | Routes traffic according to the user profile. | A working remote server, universal app coverage, or leak-free operation without validation. |
| Engine Supervisor | Observes managed process state and reports unexpected exits. | Remote endpoint health or automatic repair/restart. |
| Recovery guidance | Presents local, evidence-based advice. | Automatic driver, route, or unrelated VPN repair. |

## Privacy and data handling

- Automatic network matching uses exact local identifiers when needed; identifiers are not displayed in the Dashboard profile summary.
- Internal recovery snapshots are bounded and sanitized to avoid retaining raw adapter names, SSIDs, gateway addresses, and detailed diagnostic payloads.
- DNSCrypt query logging is opt-in and may reveal browsing-related domain history.
- External DNS leak tests contact a third-party endpoint and may expose public network metadata.
- Settings backups and diagnostic exports may contain provider names, DNS addresses, or operational details. Protect them and redact before public sharing.
- Do not publish sing-box profiles, subscription URLs, proxy credentials, private keys, or recovery files in GitHub issues.

## Installation

1. Open the [GitHub Releases](https://github.com/Shattered-Devil/Raider-DNS/releases) page.
2. Download the Windows installer for the release you intend to test.
3. Run the installer and review the component selection page.
4. The Raider DNS application is required. DNSCrypt Proxy and sing-box TUN are optional advanced components when their verified payloads are included in the installer.
5. Launch Raider DNS and configure the desired DNS mode or provide a compatible sing-box profile.
6. Installing an engine does **not** automatically activate DNSCrypt or start a TUN tunnel. Activation remains a user action inside Raider DNS.

### Before uninstalling

- Restore the saved previous Windows DNS settings if DNSCrypt was active.
- Stop DNSCrypt only after confirming no adapter still depends on its loopback listener.
- Gracefully stop any active sing-box TUN tunnel from Raider DNS.
- If tunnel shutdown cannot be confirmed, do not force-kill the engine or manually delete unknown routes/adapters. Keep the application open and inspect Diagnostics/network state.

The uninstaller does not silently rewrite adapter DNS or remove unknown VPN/TUN routes.

## Requirements

### Running the application

- Windows 10/11, x64 target.
- Administrator privileges for operations that modify system DNS or configure TUN routing.
- DNSCrypt Proxy and/or sing-box engine component installed for the corresponding optional features.
- A valid user-provided sing-box profile and working remote endpoint to use traffic tunneling.

### Running from source

- Python 3.11 or newer (the maintainer's current build environment uses Python 3.14).
- Dependencies listed in `requirements.txt` (including PySide6).
- Windows is required for real adapter operations, UAC, and TUN integration.

## Run from source

Open a terminal in the directory containing `main.py`:

```powershell
python -m pip install -r requirements.txt
python .\main.py
```

## Run the test suite

```powershell
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

The optional Qt render smoke test requires an environment with PySide6 installed. Source/unit tests do not prove that Windows DNS mutations, UAC, DoH/DoT, DNSCrypt loopback, sing-box TUN routing, installer operation, or shutdown/recovery are correct on every Windows machine.

## Build

The repository provides build scripts for the executable and the two installer layouts. Run them from the project root on a Windows build machine with the required tools installed:

- `build_onefile_exe.bat` — build the single-file Windows executable.
- `build_onefile_installer.bat` — build the one-file installer.
- `build_installer.bat` — build the onedir installer.

Build prerequisites include PyInstaller 6.x, Inno Setup 6 or newer, PowerShell, and the source dependencies. The maintainer stages complete official DNSCrypt Proxy and sing-box payloads separately when those optional installer components are required. Keep their original licenses and companion files; do not include private proxy profiles, subscriptions, credentials, or keys in public packages.

## Copyright and third-party licensing

**Application copyright:**

`Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil`

Raider DNS contains original application code and assets as well as third-party components. Third-party components remain subject to their own licenses and notices; the Raider DNS application terms do not override those licenses. Review and include the applicable upstream license texts and redistribution materials before publishing a packaged build.

See:

- [`LICENSE_STATUS.md`](LICENSE_STATUS.md)
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- [`COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt`](COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt)
- [sing-box upstream repository](https://github.com/SagerNet/sing-box)
- [DNSCrypt Proxy upstream repository](https://github.com/DNSCrypt/dnscrypt-proxy)
- [Qt for Python licensing](https://doc.qt.io/qtforpython-6/commercial/index.html)
- [PyInstaller licensing](https://pyinstaller.org/en/stable/license.html)

Do not describe Raider DNS as open source unless an explicit application license grants the relevant rights. Confirm the application-level license file is present in the repository before publishing the release.

## Security reporting

Please do not publish exploit details, private DNS profiles, subscription URLs, credentials, private keys, adapter dumps, or unredacted recovery files in public issues.

Use the repository's [Security Advisories](https://github.com/Shattered-Devil/Raider-DNS/security/advisories) feature when enabled. Otherwise, contact the maintainer privately through the GitHub profile and request a secure channel.

For ordinary bugs and feature requests, use [GitHub Issues](https://github.com/Shattered-Devil/Raider-DNS/issues). Include the application version, Windows edition/build, reproduction steps, and relevant logs after removing private network information.

## Project documentation

- [`CHANGELOG.md`](CHANGELOG.md) — consolidated change history since the 0.1.7 beta baseline.
- [`RELEASE_NOTES.md`](RELEASE_NOTES.md) — current release summary.
- [`TEST_REPORT.md`](TEST_REPORT.md) — automated test coverage and known validation gaps.
- [`SECURITY.md`](SECURITY.md) — security reporting and safe testing.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution guidance.
- [`docs/NETWORK_REGION_PROFILES.md`](docs/NETWORK_REGION_PROFILES.md) — Global, Iran, and Restricted Network Mode behavior.

## Maintainer

**Nima Zahedi**  
GitHub: [Shattered-Devil](https://github.com/Shattered-Devil)  
Repository: [Raider-DNS](https://github.com/Shattered-Devil/Raider-DNS)

---

<p align="center">
  <strong>Raider DNS</strong><br />
  Secure · Optimize · Stay Connected<br />
  <sub>Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil</sub>
</p>
