# Raider DNS v0.1.7

**Windows DNS management, encrypted DNS, resolver diagnostics, and network recovery.**

Raider DNS is a Windows desktop application built with Python and PySide6. It manages Windows adapter DNS settings, supports Windows-native DoH/DoT and optional DNSCrypt Proxy, provides resolver benchmarks and network diagnostics, and includes an external sing-box TUN integration for users who configure it themselves.

> **Release status:** v0.1.7 is a stability-focused release candidate. It improves sing-box TUN shutdown/recovery, unexpected-engine-exit reporting, worker isolation, and DNSCrypt process lifecycle handling. Automated tests are not a substitute for live validation on Windows. See `RELEASE_AUDIT_0.1.7.md` and `TEST_REPORT_0.1.7.md` before installing or publishing.

## What's new in 0.1.7

- **TUN shutdown safety:** sing-box is launched with a hidden console window rather than `CREATE_NO_WINDOW`, so Windows can deliver its normal console-close lifecycle and sing-box can release WinTun resources. Raider DNS uses a non-forced, PID-specific stop request and refuses to close if shutdown cannot be confirmed.
- **Unexpected sing-box exit monitoring:** a lightweight timer checks the child process while the tunnel is running. Unexpected exits are reported, the recovery record is retained, and the app does not automatically delete unknown adapters or routes.
- **Stale TUN session protection:** the app checks the exact recorded executable/config/PID and blocks a new TUN start when a stale session requires network inspection.
- **Safer close workflow:** tunnel shutdown runs off the GUI thread; periodic jobs pause during the close sequence; failed shutdown restores the UI and timers; the final worker bookkeeping signal cannot block an already-confirmed clean close.
- **Dedicated Qt worker pool:** Raider DNS now owns its bounded `QThreadPool` rather than changing the process-wide global pool limit.
- **DNSCrypt lifecycle hardening:** process log handles are scoped correctly, failed termination retains the process reference, and a second timeout is reported instead of escaping as an uncaught exception.
- **Visual design preserved:** Plasma Stream remains at **4 broad ribbons and 11 fine filaments**. The visibility-aware 25 FPS animation and 24-segment path cap remain; no ribbons or filaments were removed.
- Packaging and version metadata updated to `0.1.7`.

## Main capabilities

- Standard DNS configuration for Windows network adapters.
- Windows-native DoH and DoT registration and verification.
- Optional local DNSCrypt Proxy engine; the installer selects it by default, but it can be deselected.
- Browser-native DoH controls for supported browsers. This is browser-specific DNS behavior; it is not a full-device VPN or traffic tunnel.
- External sing-box TUN integration through a user-supplied executable and configuration. sing-box is not bundled by this release.
- DNS provider catalogue, custom providers, favourites, ordering, saved profiles, import/export, and backups.
- Resolver benchmarking with median ICMP, TCP/53, and DNS-query latency measurements.
- Diagnostics, selectable repair actions, activity log, CSV export, system tray, themes, and administrator relaunch support.
- Transactional DNS updates with durable recovery state, Windows adapter read-back, rollback on configuration mismatch, and explicit restore controls.

## TUN shutdown and network safety

The sing-box TUN engine can modify Windows routes and create a virtual network adapter. Do not terminate it with a force-kill as a normal shutdown path. Raider DNS now starts the long-lived process with a hidden console lifecycle and requests a PID-specific graceful stop. If shutdown cannot be confirmed, the application stays open and retains the session record.

If sing-box exits unexpectedly or Raider DNS starts with a stale session record, the app reports that network state must be checked. It deliberately does **not** remove arbitrary VPN adapters, default routes, or driver devices automatically: those could belong to another VPN or networking tool. Use Diagnostics to inspect the physical adapter and default route before starting another TUN session.

This improves the normal shutdown path but cannot guarantee recovery after power loss, a kernel/driver crash, or forced termination outside Raider DNS. Test the TUN integration in a disposable Windows VM before relying on it.

## DNS safety model

Raider DNS serializes system DNS changes, writes a durable recovery snapshot before mutating the adapter, reads the settings back from Windows, and rolls back when the adapter configuration or required encrypted-DNS registrations do not match the requested state.

External resolver reachability is treated separately from adapter configuration correctness. When Windows read-back matches but a public resolver or connectivity probe is unreachable, the configuration is retained and displayed as **connectivity unverified** rather than being silently rolled back. DNSCrypt is stricter: a local DNS query must succeed through the loopback proxy before the adapter is left pointing to it. DoH/DoT endpoint preflight failures require explicit user confirmation before proceeding unverified.

A successful configuration read-back does not guarantee that an upstream network, firewall, VPN, or resolver will answer queries. The app keeps the previous DNS recovery point available; use **Restore Previous DNS Settings** if the selected DNS service is not working.

## Requirements

- Windows 10/11 x64 for system DNS configuration. Windows 11 is the recommended target. Windows 10 support status should be checked against Microsoft's current lifecycle.
- Python 3.11 or newer for running/building from source.
- PySide6 (`requirements.txt`).
- Inno Setup 6 or newer for the installer build.
- Internet access during installer creation to download the hash-pinned DNSCrypt Proxy archive (unless the verified archive is already cached).

The source ZIP intentionally does not include `dnscrypt-proxy.exe` or `sing-box.exe`. The Windows installer build downloads and verifies DNSCrypt Proxy, then stages it as an optional installer component. sing-box remains an externally supplied dependency for users who enable the TUN integration.

## Run from source

```powershell
python -m pip install -r requirements.txt
python .\main.py
```

The project is offline-first for saved settings and local DNS management, but live DNS tests, external IP lookup, resolver benchmarking, and installer dependency acquisition naturally need network access.

## Run tests

```powershell
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

The Qt render smoke test runs only when PySide6 is installed. On headless machines, set `QT_QPA_PLATFORM=offscreen` before running tests. The Windows DNS safety harness is deliberately not part of normal test discovery; it must only be run in a disposable, snapshot-backed Windows VM with a dedicated test adapter.

## Build a one-file EXE on Windows

Install requirements and PyInstaller:

```cmd
python -m pip install -r requirements.txt
python -m pip install "PyInstaller>=6.22,<7"
```

Build the one-file executable:

```cmd
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "Raider DNS" --icon "assets\app_icon.ico" --version-file "installer\version_info.txt" --add-data "assets;assets" --add-data "COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt;licenses" --distpath "release" main.py
```

Output: `release\Raider DNS.exe`. PyInstaller one-file mode extracts supporting files into a temporary directory on launch, so startup can be slower than a one-folder build. The EXE's Details tab includes company, product, file-version and legal-copyright fields. Keep the copyright and third-party notices with any redistributed build.

## Build the installer

1. Build and test `release\Raider DNS.exe` on Windows.
2. Install Inno Setup and prepare the hash-verified DNSCrypt Proxy payload with `installer\prepare_dnscrypt_proxy.ps1`.
3. Open `installer\RaiderDNS_OneFile.iss` in Inno Setup Compiler and press **F9**, or run `build_onefile_installer.bat`.

Expected installer: `release\RaiderDNS_Setup_0.1.7_x64.exe`.

Installer components:

- **Raider DNS application:** required.
- **DNSCrypt Proxy:** optional and selected by default; users can deselect it in Custom setup.

Standard DNS and Windows-native DoH/DoT do not require DNSCrypt Proxy.

## GitHub publication checklist

1. Choose and add a license for the Raider DNS source code. No application `LICENSE` file is included yet; publishing code on GitHub does not automatically grant reuse or redistribution rights.
2. Review Qt/PySide6 licensing for the actual modules and DLLs included in the PyInstaller build. Retain the applicable complete license texts and notices.
3. Keep DNSCrypt Proxy's upstream license files intact in its installer payload.
4. Build and test the EXE and installer on a clean Windows VM. Test install, upgrade, optional DNSCrypt selection, uninstall, and DNS recovery preservation.
5. Test sing-box start/stop repeatedly, app close, tray exit, engine crash, and recovery after a forced VM reboot. Do not claim stable TUN support until those tests pass.
6. Consider code signing the EXE and installer before public distribution.
7. Check the Git working tree for personal configuration, logs, recovery snapshots, local binaries, and secrets before pushing.

## Third-party components

- **PySide6 / Qt for Python:** UI framework. Review its LGPL/GPL/commercial licensing requirements for the exact packaged modules. <https://doc.qt.io/qtforpython-6/commercial/index.html>
- **DNSCrypt Proxy:** optional external engine staged by the installer from the official upstream release. The pinned version and hash are recorded in `installer/prepare_dnscrypt_proxy.ps1`. <https://github.com/DNSCrypt/dnscrypt-proxy>
- **sing-box:** external executable and configuration supplied by the user; not included in the repository release or installer. <https://github.com/SagerNet/sing-box>

See `THIRD_PARTY_NOTICES.md`, `LICENSE_STATUS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `RELEASE_AUDIT_0.1.7.md`, and `TEST_REPORT_0.1.7.md` before publishing.
