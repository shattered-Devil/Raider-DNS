<div align="center">
  <img src="Assets/raider-dns-banner.svg" alt="Raider DNS" width="100%" />

  # Raider DNS

  **Windows DNS Management & Network Diagnostics**

  [![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?logo=windows)](https://www.microsoft.com/windows)
  [![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
  [![PySide6](https://img.shields.io/badge/UI-PySide6-41CD52?logo=qt&logoColor=white)](https://doc.qt.io/qtforpython-6/)
  [![Release](https://img.shields.io/badge/release-v0.1.7%20RC-orange)](https://github.com/shattered-Devil/Raider-DNS/releases)

  [Download](https://github.com/shattered-Devil/Raider-DNS/releases) ·
  [Features](#features) ·
  [Security](#security--network-safety) ·
  [Documentation](docs/) ·
  [Issues](https://github.com/shattered-Devil/Raider-DNS/issues)
</div>

---
## Application Screenshots

### Dashboard
![Raider DNS Dashboard](Assets/Screenshots/dashboard.png)

### Connections
![Raider DNS Connections](Assets/Screenshots/connections.png)
## About

**Raider DNS** is a Windows desktop application for managing DNS configuration, encrypted DNS transports, resolver performance, network diagnostics, and DNS recovery. It is built with Python and PySide6 / Qt Widgets.

> **Current version:** `0.1.7` — Release Candidate  
> **Maintainer / copyright:** Nima Zahedi · Copyright (C) 2026 Nima Zahedi  
> **Target:** Windows 10/11 x64. Windows 11 is the recommended target.

This repository follows the same public-release approach as the maintainer's Noble Password Manager project: the root README is the project landing page, `Source Code/` contains the application source, and `docs/` contains release and technical documentation.

**Release status matters:** v0.1.7 includes source-level and automated-test improvements for network shutdown and engine stability. Live Windows validation of WinTun cleanup, real DNS operations, the GUI, and installer behavior is still required. Do not treat the release candidate as production-certified.

## Download

### Raider DNS v0.1.7 — Release Candidate

Download the latest release from **[GitHub Releases](https://github.com/shattered-Devil/Raider-DNS/releases/latest)**.

| Package | Purpose |
|---|---|
| `RaiderDNS_Setup_0.1.7_x64.exe` | Recommended installer for Windows x64. |
| `Raider DNS.exe` | Optional standalone application build, only if separately tested by the maintainer. |
| `SHA256SUMS.txt` | SHA-256 hashes for the published binary assets. |
| Source code | Available in this repository and the GitHub source archive. |

The installer includes Raider DNS and offers **DNSCrypt Proxy as an optional component selected by default**. Standard DNS and Windows-native DoH/DoT do not require DNSCrypt Proxy. sing-box is not bundled; its TUN integration requires a separately obtained executable and configuration.

> **Beta / Release Candidate notice:** Test network-changing features in a disposable Windows VM with a snapshot first. Keep a working recovery path for your DNS settings.

## Screenshots

Screenshots will be added to [`Assets/Screenshots/`](Assets/Screenshots/README.md) after capturing the final tested v0.1.7 interface. Do not use screenshots containing public IP addresses, private hostnames, adapter identifiers, recovery data, or other personal network details.

## Features

- **DNS configuration:** Standard IPv4/IPv6 DNS settings for Windows network adapters.
- **Encrypted DNS:** Windows-native DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) registration and verification.
- **DNSCrypt:** Optional local DNSCrypt Proxy integration.
- **Browser DNS controls:** Browser-native DoH settings for supported browsers. This is not a system-wide VPN or traffic tunnel.
- **sing-box TUN integration:** Can launch a user-supplied sing-box executable/configuration. sing-box is not distributed with this release.
- **Provider management:** Built-in and custom providers, favourites, ordering, profiles, import/export, and backups.
- **Resolver benchmarking:** Median ICMP, TCP/53, and DNS-query latency measurements.
- **Diagnostics and recovery:** Connectivity checks, selectable repairs, DNS audit, durable recovery snapshots, verified adapter read-back, rollback on configuration mismatch, and restore controls.
- **Productivity:** Activity log, CSV export, system tray, administrator relaunch, and appearance themes.
- **Plasma Stream UI:** Four broad ribbons and eleven fine filaments, preserving the intended visual density.

## Security & network safety

DNS configuration changes are system-level operations. Raider DNS uses a serialized transaction, persists a recovery snapshot before mutation, reads settings back from Windows, and rolls back when the actual adapter configuration or required encrypted-DNS registration does not match the requested state.

External resolver reachability is reported separately from whether Windows accepted the configuration. A matching adapter read-back can still show **connectivity unverified** if an upstream resolver, firewall, VPN, or network blocks requests. DNSCrypt is handled more strictly because Windows must not be left pointing at a loopback proxy that does not answer queries.

### sing-box / TUN shutdown

The TUN engine can create a virtual adapter and alter Windows routes. v0.1.7 uses a hidden-console process lifecycle and a PID-specific, non-forced shutdown request. If process exit cannot be confirmed, Raider DNS is designed to remain open and preserve its session record. Unexpected exits and stale sessions are reported for inspection.

Raider DNS intentionally does not delete arbitrary VPN adapters, driver devices, or routes because they may belong to other VPN or networking tools. Normal shutdown improvements do not guarantee recovery after power loss, a kernel/driver crash, or force-closing the process externally. Follow [`NETWORK_SHUTDOWN_RECOVERY_0.1.7.md`](docs/NETWORK_SHUTDOWN_RECOVERY_0.1.7.md) and test in a disposable VM.

### Security reporting

Please do not publish exploit details, adapter dumps, public IP addresses, private hostnames, or recovery snapshots in public issues. Follow [`SECURITY.md`](SECURITY.md) for private vulnerability reporting and safe reproduction guidance.

## Installation

1. Open [GitHub Releases](https://github.com/shattered-Devil/Raider-DNS/releases/latest).
2. Download `RaiderDNS_Setup_0.1.7_x64.exe`.
3. Verify its SHA-256 against `SHA256SUMS.txt` attached to the same release.
4. Run the installer. Windows may request administrator permission because DNS management affects system network settings.
5. Choose whether to install the optional DNSCrypt Proxy component. It is selected by default; it can be deselected using Custom installation.
6. Launch Raider DNS and review the initial network state before applying DNS changes.

Before uninstalling, restore the previous DNS configuration and gracefully stop DNSCrypt / sing-box where applicable. Do not remove an engine while a network adapter still depends on it.

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for detailed instructions and troubleshooting.

## Run from source

Requirements: Windows 10/11 x64 for Windows DNS operations, Python 3.11+, and PySide6 as specified in `Source Code/requirements.txt`.

```powershell
cd "Source Code"
python -m pip install -r requirements.txt
python .\main.py
```

Run the automated tests from the same directory:

```powershell
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

See [`docs/BUILD_FROM_SOURCE.md`](docs/BUILD_FROM_SOURCE.md) for PyInstaller and Inno Setup instructions. The Windows CI workflow runs the source test suite on Windows with Python 3.11 and 3.14.

## Repository layout

```text
Assets/                 App icon, repository banner, screenshot guidance
Source Code/            Python/PySide6 application, tests, installer scripts
.github/                Windows CI and GitHub issue templates
docs/                   Release audit, test report, recovery and build guides
README.md               Repository landing page
CHANGELOG.md            Current and historical changes
RELEASE_NOTES_v0.1.7.md v0.1.7 release notes
SECURITY.md             Vulnerability reporting and safe testing
CONTRIBUTING.md         Development and contribution guidance
THIRD_PARTY_NOTICES.md  Third-party license/notice information
LICENSE_STATUS.md       Application license status
requirements.md         Runtime and build requirements
```

## Testing and known limitations

The v0.1.7 source report records **193 tests collected: 192 passed and 1 skipped**. The skipped test was the optional Qt render smoke test because PySide6 was unavailable in the original headless build environment. The tests include mocked process and network behavior and static source checks; they do not prove live Windows behavior.

Not yet certified by the source build environment:

- WinTun driver cleanup and route restoration on real Windows hardware.
- DNS, DoH, DoT, DNSCrypt, UAC, PowerShell/CIM and adapter operations on each supported Windows configuration.
- Real-world GUI rendering, FPS, CPU and memory profiling.
- PyInstaller and Inno Setup builds, clean installation, upgrade, and uninstall.
- Crash / power-loss recovery for active tunnels.

See [`docs/RELEASE_AUDIT_0.1.7.md`](docs/RELEASE_AUDIT_0.1.7.md) and [`docs/TEST_REPORT_0.1.7.md`](docs/TEST_REPORT_0.1.7.md). The GitHub Actions results should be checked after the first push.

## License and copyright

Copyright (C) 2026 Nima Zahedi. **No application-level license has been selected yet.** This repository is public for inspection, but public visibility alone does not grant permission to reuse, modify, redistribute, or publish derivative works. See [`LICENSE_STATUS.md`](LICENSE_STATUS.md) and do not describe the application as open-source until a license is deliberately selected and added.

Raider DNS also uses or integrates with third-party components. Their licenses remain separate from the application copyright. Review [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and the relevant license texts before distributing binaries. The current notice file is not, by itself, proof of full Qt/PySide6 redistribution compliance.

---

**Raider DNS** · Copyright (C) 2026 Nima Zahedi · v0.1.7 Release Candidate
