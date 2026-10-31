# Raider DNS v0.1.7 — Stability and release audit

## Executive summary

v0.1.7 is a focused stability release based on the v0.1.6.4 TESTFIX source. The primary change targets Windows networking disruption associated with closing Raider DNS while the external sing-box TUN engine is active. The app now starts the long-lived sing-box process with a hidden console lifecycle instead of `CREATE_NO_WINDOW`, requests a PID-specific non-forced shutdown, refuses to close if the stop cannot be confirmed, and checks for unexpected sing-box exits while the application is running.

The project also isolates its Qt worker pool, strengthens DNSCrypt process-stop error handling, and preserves the original Plasma Stream appearance (4 ribbons / 11 filaments).

**Release classification: Windows release candidate; not certified production-stable.** The code-level regression suite passes, but the decisive TUN/WinTun shutdown and recovery tests require a real Windows machine or disposable Windows VM. This audit does not claim the network-driver issue is conclusively resolved on every Windows/driver combination.

## Findings and changes

### 1. sing-box / WinTun shutdown

The prior long-lived process used a no-console creation mode. The upstream sing-box Windows issue tracker documents a WinTun cleanup failure in which forcibly terminating the process bypassed the normal cleanup path, and describes using a hidden console window instead of `CREATE_NO_WINDOW`, followed by a non-forced PID stop request. Reference: https://github.com/SagerNet/sing-box/issues/3806.

v0.1.7 changes:

- The long-running TUN process is launched with `STARTF_USESHOWWINDOW` and `SW_HIDE`; the TUN `Popen` call does not use `CREATE_NO_WINDOW`.
- The app writes an atomic session record containing the PID, exact executable path, exact config path, schema version, and UTC start time.
- Normal stop uses `taskkill.exe /PID <pid>` without `/F` or `/T`. It waits for the Popen handle or verified process identity to report exit.
- A live TUN process is never force-killed by Raider DNS. If normal shutdown is not confirmed, the session record is retained and the app stays open.
- At startup, recovery inspects only the PID recorded by Raider DNS and verifies executable and config paths before requesting stop. It does not search/kill all processes named `sing-box.exe`.
- If the process has already disappeared, the app warns that routes/adapters may need inspection. It does not remove unknown VPN/TUN adapters, default routes, or driver devices automatically.
- The app blocks a new TUN start when a stale session was just discovered until the user has been warned to inspect network state.
- A lightweight 2.5-second monitor checks the child process while the tunnel is active. Unexpected exit is reported, and the journal is retained for recovery.

### 2. Application close workflow

- Tunnel shutdown is performed by the bounded background worker pool, not by blocking the UI thread.
- Periodic network/health/activity/Plasma timers pause during the close-time tunnel cleanup.
- The central UI is disabled while the shutdown transaction is in progress.
- When graceful shutdown fails, the UI and previously active periodic timers are restored and the application remains open.
- A successful stop is not blocked by the cleanup worker's final Qt signal bookkeeping tick.
- If the process is already gone and network cleanup cannot be verified, the user is offered the choice to keep the app open for Diagnostics or close anyway.

### 3. DNSCrypt Proxy lifecycle

- The log file handle used for process startup is scoped using a context manager, including process-creation failure paths.
- `stdin` is detached from the interactive session; stdout remains discarded and stderr is written to the app log.
- A second timeout during shutdown now returns a failure result and retains the process object instead of leaking `TimeoutExpired` out of the controller.
- A successful stop is reported only after the process handle confirms exit.
- The existing adapter-loopback dependency check remains mandatory before manual engine stop. Raider DNS intentionally may leave the proxy running after the UI closes if adapters still rely on loopback DNS.

### 4. Worker scheduling and UI performance

- The main window now owns a dedicated `QThreadPool` capped by `MAX_CONCURRENT_NETWORK_TASKS`, rather than modifying Qt's process-wide global pool.
- The Plasma Stream remains unchanged in visual density: 4 broad ribbons and 11 fine filaments. The 25 FPS coarse timer and 24-point maximum per sampled path remain as bounded rendering controls.
- Plasma animation is stopped when the visual is hidden; it is also paused during tunnel shutdown and restored if close is cancelled.
- No real FPS/CPU benchmark could be conducted in this headless build environment. UI performance claims remain pending a Windows GUI measurement.

### 5. Packaging and release metadata

- Application/file/product version updated to 0.1.7 / 0.1.7.0.
- New `installer/RaiderDNS_OneFile.iss` packages the single-file EXE and readable legal notices, with optional DNSCrypt Proxy selected by default.
- New `build_onefile_installer.bat` compiles the one-file installer without running tests; it checks that the EXE and verified DNSCrypt payload already exist.
- DNSCrypt Proxy remains hash-pinned by `installer/prepare_dnscrypt_proxy.ps1`.
- `README.md`, `CHANGELOG_0.1.7.md`, copyright notices, release manifest and test/audit reports updated.

## Validation performed

- `python -m compileall -q main.py raider_dns tests`: passed.
- `python -m unittest discover -s tests -q`: 193 tests collected; 192 passed; 1 skipped (optional Qt paint smoke test; PySide6 not installed in the build environment).
- Includes new regression coverage for graceful sing-box stop, preserving session state after stop timeout, unexpected process exit monitoring, stale-session start protection, DNSCrypt process stop timeouts, private worker-pool ownership, and UI close/timer recovery.
- Static guards confirm external `subprocess.run`, `urlopen`, and socket connection calls in application source have explicit timeouts and no `shell=True` use.
- Final source archive contains 90 files; ZIP CRC validation passed; compile and all tests were rerun successfully after extracting the archive (193 collected, 192 passed, 1 skipped).

## Not validated here — required Windows release gates

This build environment is Linux with Python 3.13 and no PySide6 installation. The following have **not** been validated:

1. Actual Windows console-close delivery to sing-box when launched by the PyInstaller windowed executable.
2. WinTun driver cleanup, default route restoration, adapter state and physical network recovery after normal close.
3. App close, system tray Exit, manual Stop button, engine crash, external process termination, and machine reboot recovery on real Windows.
4. UAC/elevation behavior and exact PowerShell/CIM process inspection under Windows 10/11.
5. Real standard DNS, Windows DoH, DoT, DNSCrypt local query, and DNS recovery operations.
6. Qt interactive GUI rendering, measured FPS/CPU/RAM, long-running responsiveness, and animation behavior on the user's PC.
7. PyInstaller EXE creation, Inno Setup compilation, clean install/upgrade/uninstall and the optional DNSCrypt checkbox.
8. Code signing and Windows SmartScreen reputation.

The build environment's global `pip check` also reports an unrelated conflict: installed `moviepy 2.2.1` expects Pillow `<12`, while Pillow `12.3.0` is installed. `moviepy` is not a Raider DNS project dependency; this global environment warning is not evidence of a Raider DNS runtime dependency failure.

## Architecture / maintenance notes

`raider_dns/ui/main_window.py` remains a large UI module. A structural MVVM/service extraction could improve maintainability, but a broad refactor was intentionally avoided in this stability release. Keep future changes incremental and cover engine lifecycle code with tests.

## Release recommendation

Publish v0.1.7 as a source release candidate or preview. Do not claim the TUN/driver issue is permanently fixed or the app is production-certified until the Windows validation checklist in `NETWORK_SHUTDOWN_RECOVERY_0.1.7.md` passes on the intended Windows versions and hardware. Resolve the application license choice and Qt/PySide distribution obligations before redistributing the binary installer publicly.
