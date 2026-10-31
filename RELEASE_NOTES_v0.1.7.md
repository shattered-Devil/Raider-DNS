# Raider DNS v0.1.7 — Release Candidate

**Copyright (C) 2026 Nima Zahedi**

## Highlights

- Improved sing-box TUN shutdown lifecycle using a hidden console process and PID-specific, non-forced shutdown requests.
- Added a persistent session journal, unexpected-process-exit monitoring, and stale-session inspection.
- Raider DNS stays open if graceful TUN shutdown cannot be confirmed; it does not silently force-kill the engine.
- Added safer application-close sequencing and an application-owned bounded Qt worker pool.
- Hardened DNSCrypt Proxy process/log lifecycle and timeout handling.
- Preserved the Plasma Stream design at four broad ribbons and eleven fine filaments.
- Updated packaging and Windows version metadata to 0.1.7.

## Existing capabilities

Standard DNS, Windows-native DoH/DoT, optional DNSCrypt Proxy, browser-native DoH controls, user-supplied sing-box TUN integration, provider management, resolver benchmarking, diagnostics, DNS recovery, activity logs, CSV export, themes, and system-tray support.

## Important limitations

This is a **release candidate**. The source-level test report records 193 tests collected, 192 passed, and one optional Qt render test skipped because PySide6 was unavailable in the original headless environment. Live Windows validation is still required for WinTun cleanup, routes, DNS transports, UAC, GUI performance, and installation/uninstallation. Do not treat the test count as proof of driver or network safety.

The app does not bundle sing-box. DNSCrypt Proxy is an optional installer component. Review the release audit, test report, network shutdown recovery guide, and third-party notices before using or redistributing the build.

## Downloads

- `RaiderDNS_Setup_0.1.7_x64.exe` — recommended Windows installer.
- `Raider DNS.exe` — optional standalone executable, only where the maintainer has separately tested it.
- `SHA256SUMS.txt` — checksums for the binary downloads.

## Copyright and licensing

Copyright (C) 2026 Nima Zahedi. No application-level license has been selected. Third-party components remain under their respective licenses; see `THIRD_PARTY_NOTICES.md` and `LICENSE_STATUS.md`.
