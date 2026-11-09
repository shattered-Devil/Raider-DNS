# Raider DNS — Changelog

## 0.2 Beta

This release consolidates the development work introduced after the 0.1.7 beta baseline. The changes below are grouped by capability rather than by intermediate development build.

### What's New Since 0.1.7

#### Application navigation and user interface

- Reworked the application navigation into nine main areas: Dashboard, Connections, DNS Tools, DNS Providers, DNS Security Center, Benchmark Lab, Diagnostics, Activity Log, and Settings.
- Consolidated connection status, saved-profile context, and managed-engine status into the Dashboard.
- Integrated reusable DNS profiles into DNS Providers rather than maintaining a separate Profiles page.
- Added unique SVG navigation icons and increased navigation icon sizing.
- Preserved the Plasma Stream visual with four animated ribbons and eleven fine filaments.
- Improved animation resource management with visibility-aware updates and bounded visual history.
- Expanded the theme collection to nine themes: Dark, Light, Light Mild, Paper, Warm Sand, Mist Blue, Midnight, Ocean, and High Contrast.
- Reworked preference controls into theme-aware switches, including checked/unchecked tracks, knobs, and focus outlines.
- Added Persian interface selection and right-to-left layout support.
- Standardized tooltip delay at 750 ms and removed the obsolete tooltip-delay preference.

#### Standard DNS management and reliability

- Simplified Standard DNS to apply the exact selected provider address list to the selected Windows adapter and address family.
- Removed legacy fallback-address concatenation from the ordinary Standard DNS operation. Provider failover remains a separate, opt-in operation.
- Kept Standard DNS independent from DNSCrypt, sing-box, virtual adapters, packet tunnels, proxy settings, Winsock settings, and unrelated Windows network configuration.
- Removed the global Windows DoH compatibility prompt and stopped Standard DNS from changing Windows DoH `AutoUpgrade` settings.
- Standard DNS transactions no longer require a Windows DoH inventory query merely to capture the adapter DNS baseline.
- Added durable DNS recovery snapshots, Windows configuration read-back, serialized DNS mutations, and exact restoration of the captured previous configuration.
- Added before/after Windows DNS and HTTPS/TLS health comparison for the normal reliability-protected DNS modes. A persistent loss of a dimension that was healthy before a change triggers restoration of the previous snapshot after a recheck.
- Separated direct resolver reachability from system-wide Windows DNS health. A direct UDP/53 timeout alone does not force rollback if effective Windows DNS and HTTPS remain healthy.
- Distinguished pre-existing connectivity failures from regressions introduced during a DNS change.
- Kept DNSCrypt loopback handling strict: the local proxy must respond before Windows is left configured to use it.
- Improved transaction results so “configuration applied” and “resolver health verified” are not treated as interchangeable states.

#### Regional Rules and Restricted Network Mode

- Added a **Regional Rules** area in Settings with manually selected Global and Iran profiles. Global is the default.
- Added longer bounded DNS/resolver timeouts and additional rechecks for the Iran profile.
- Made external HTTPS diagnostic failures advisory in the Iran profile; a persistent loss of previously working Windows DNS still triggers rollback in the normal verification workflow.
- Added an independent **Restricted Network Mode** On/Off switch, disabled by default. It applies to Standard DNS only; it does not change DoH, DoT, or DNSCrypt behavior.
- When Restricted Network Mode is enabled, Standard DNS skips the pre-change DNS/HTTPS baseline, direct DNS resolver queries, Windows DNS Client resolution checks, HTTPS/TLS checks, and post-change health retries.
- Restricted Network Mode performs adapter-bound ICMP ping measurements against the configured DNS IP addresses after applying the DNS configuration.
- If neither configured DNS IP replies to ping, the new DNS settings remain installed and an embedded Dashboard panel asks the user to restore the previous DNS settings or keep the new settings.
- If ping cannot be attempted on the selected adapter, the application reports that limitation instead of describing it as a DNS-server failure.
- Preserved Windows command success, exact adapter DNS read-back, and durable recovery-snapshot persistence as configuration-integrity safeguards even in Restricted Network Mode.
- Paused automatic background resolver monitoring and automatic resolver failover for Standard DNS while Restricted Network Mode is active. User-initiated diagnostics and benchmarks remain available.
- Clarified that a failed ICMP ping does not prove DNS is unavailable; a network may block ping while allowing DNS queries.

#### Network adapter and route intelligence

- Improved default-route detection using Windows route information for actual destinations, including `Find-NetRoute` where supported by the operation.
- Incorporated route and interface metrics while preserving valid zero-valued metrics.
- Identified and displayed the preferred route adapter without silently replacing the user's selected adapter.
- Added warnings when the selected DNS adapter differs from the adapter Windows prefers for general internet traffic.
- Added selected adapter/interface index, source address, gateway, and per-resolver route context to diagnostics.
- Kept adapter-bound resolver probes separate from system-wide Windows DNS lookup results.
- Avoided claiming that `Resolve-DnsName` identifies the exact recursive server that answered; Windows does not expose that information through this command.
- Improved handling of Wi-Fi, Ethernet, VPN, and virtual interfaces without changing unrelated adapters.

#### DNS Providers and reusable profiles

- Combined the resolver catalogue and reusable DNS profile workflows in DNS Providers.
- Added provider search, favorites, ordering, custom providers, and supported provider/profile import and export.
- Preserved local profile storage.
- Added opt-in exact-match network profile matching using saved SSID and/or adapter identity.
- Limited automatic profile application to supported Standard DNS and Windows-native DoH workflows; other saved transport profiles remain available for manual use.
- Kept provider selection separate from transport selection.

#### DNS Tools and domain rules

- Expanded DNS record lookup to support A, AAAA, CNAME, MX, TXT, NS, SOA, and PTR records.
- Added an optional explicit resolver address for DNS lookups.
- Added normalization for pasted HTTP/HTTPS website URLs so the hostname can be queried.
- Added a bounded, read-only Windows DNS cache inspector alongside the existing cache-flush action.
- Added single-entry domain block and allow rule controls.
- Added support for domain names, full HTTP/HTTPS URLs, and leading wildcard patterns such as `*.example.com` in supported local filtering rules.
- Clarified that domain block/allow rules are enforced through DNSCrypt Proxy local filtering and do not filter Standard DNS traffic by themselves.
- Preserved DNSCrypt forwarding and Split DNS rule management.

#### DNSCrypt Proxy and DNS filtering

- Added graphical lifecycle and configuration management for the official DNSCrypt Proxy executable.
- Added local configuration generation, validation, resolver selection, resolver-pool/load-balancing configuration, and safe configuration updates.
- Added supported local blocklists, allowlists, forwarding rules, and Split DNS configuration.
- Added optional DNS query logging and a local query monitor with bounded log reading and refresh behavior.
- Kept query logging disabled by default because logs can contain browsing-domain and network information.
- Added local listener checks before leaving a Windows adapter configured to use DNSCrypt loopback.
- Preserved configuration rollback when generated DNSCrypt configuration is invalid or its required local listener is unavailable.

#### DNS query monitoring and resolver failover

- Added optional local DNS query log visibility for DNSCrypt Proxy.
- Added primary/fallback resolver health monitoring and opt-in failover policies.
- Added consecutive-failure detection, recovery checks, and hysteresis to reduce unnecessary resolver switching.
- Kept automatic failover separate from the ordinary exact-address Standard DNS apply operation.
- Paused automatic monitoring/failover for Standard DNS while Restricted Network Mode is active.

#### Encrypted DNS and traffic-engine integrations

- Added/expanded Windows-native DNS-over-HTTPS (DoH) configuration and diagnostics.
- Added/expanded Windows-native DNS-over-TLS (DoT) configuration and diagnostics, including per-resolver policy inspection and authenticated endpoint checks where supported.
- Added supported browser-specific DoH controls for supported browsers.
- Integrated the official sing-box CLI as an optional, separately managed TUN traffic-routing engine.
- Added sing-box profile selection, JSON validation, start/stop controls, engine discovery, and Dashboard/Supervisor status integration.
- Kept sing-box TUN routing separate from ordinary DNS changes. It requires a compatible user-provided profile and working remote endpoint; Raider DNS does not provide VPN servers, subscriptions, or credentials.
- Made DNSCrypt Proxy and sing-box optional installer components rather than requirements for core Standard DNS functionality.
- Added packaged-engine discovery safeguards so frozen builds do not accidentally use executables from a developer's source checkout.

#### Engine Supervisor and application lifecycle

- Expanded Engine Supervisor monitoring for Raider DNS-managed DNSCrypt Proxy and sing-box processes.
- Distinguished expected user-requested stops from unexpected process exits where controller state permits.
- Added deduplicated alerts for unexpected engine termination.
- Used bounded polling and local process state.
- Avoided automatic engine restarts, force-killing processes, and terminating unrelated processes with matching executable names.
- Improved single-instance behavior, administrator relaunch handling, window activation, tray-icon lifecycle, and safe application shutdown.
- Avoided treating a running process as proof of DNS resolver health, tunnel routing, or leak-free traffic.

#### Benchmark Lab

- Improved DNS query timing and independent DoT timing.
- Added bounded concurrent resolver probes.
- Added advanced repeated-query benchmarking with warm-cache and unique-name samples.
- Added median, P95, jitter, minimum/maximum latency, and success-rate statistics where supported by the benchmark workflow.
- Distinguished DNS query latency from ICMP round-trip time and TCP connection time.
- Added supported benchmark result summaries, resolver comparisons, ranking, and export.

#### DNS Security Center, diagnostics, and recovery

- Expanded DNS security configuration inspection and DNS audit workflows.
- Added optional external DNS leak testing with a clear third-party disclosure.
- Expanded diagnostics for selected-adapter IPv4/IPv6 routes, address assignment, gateway reachability, ARP/NDP neighbor state, configured UDP DNS, Windows A/AAAA resolution, DoH endpoints, DoT state, TCP connectivity, HTTPS/TLS, and Windows DNS Client service state.
- Added per-resolver and global encrypted-DNS policy inspection where supported.
- Added manual repair actions to start a stopped DNS Client service, clear the selected adapter's neighbor cache, and restart the selected adapter with explicit user action and re-enable handling.
- Narrowed automatic recovery recommendations to cases supported by positive diagnostic evidence.
- Kept Winsock, TCP/IP, IPv6 stack, proxy, driver, and broad adapter-reset operations out of automatic repair.
- Removed the separate hardware-inventory/recovery presentation and kept recovery guidance inside Diagnostics.

#### Activity history, privacy, and data management

- Added a local Activity Log for supported DNS operations, diagnostics, repairs, imports, and application actions.
- Added configurable activity-history retention and bounded local recovery history.
- Migrated legacy recovery data to a coarse, sanitized format that avoids retaining raw adapter names, SSIDs, gateway addresses, and detailed diagnostic payloads.
- Added settings backup/export and restore/import workflows.
- Kept diagnostics and application history local unless the user exports and shares them.
- Added privacy warnings for DNS query logs, diagnostic exports, and external leak tests.

#### Packaging, build, and release maintenance

- Maintained PyInstaller one-file executable support and Inno Setup one-file/onedir installer paths.
- Made DNSCrypt Proxy and sing-box optional installer components when their verified payloads are staged.
- Kept third-party engine binaries out of the source archive and added maintainer staging/verification scripts.
- Added/updated executable version metadata, installer version resources, release manifests, and third-party notices.
- Added packaging safety checks for ignored build/staging payloads and frozen-engine discovery.
- Consolidated release documentation, security guidance, contribution guidance, and test reporting.

### Validation recorded for the current 0.2 beta source package

- Pytest: **366 passed, 1 skipped, 49 subtests passed**.
- Unittest: **367 tests run, 1 skipped**.
- Python compilation: passed.
- ZIP integrity and clean source extraction: passed.
- Live Windows 10/11 adapter operations, ICMP binding, PowerShell behavior, DoH/DoT, DNSCrypt loopback, sing-box TUN routing, GUI rendering, and Inno Setup compilation still require validation on Windows. Automated source tests do not replace those tests.

---

**Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil**
