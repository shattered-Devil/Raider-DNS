# Raider DNS v0.1.7

## Stability and network recovery

- Changed the long-running sing-box TUN process startup from `CREATE_NO_WINDOW` to a hidden console (`STARTF_USESHOWWINDOW` + `SW_HIDE`) so Windows can deliver the normal console-close lifecycle required by sing-box/WinTun cleanup.
- Kept sing-box shutdown PID-specific and non-forced. If Windows does not confirm process exit, Raider DNS retains the process/session record and refuses to close normally rather than force-killing the TUN engine.
- Added a 2.5-second lightweight process liveness monitor for active sing-box sessions. Unexpected exits are reported and leave the recovery record intact.
- Stale TUN session state blocks an immediate new tunnel start until the prior session has been inspected. The app does not automatically delete unknown VPN adapters, routes, or drivers.
- Tunnel cleanup during application exit runs in the background; periodic jobs pause and the UI is disabled during the short shutdown phase. If shutdown fails, the UI and previously active timers are restored.
- The Qt worker pool is now owned by the Raider DNS main window instead of using/changing the process-wide global pool.

## Engine lifecycle

- DNSCrypt Proxy process log handles now use a scoped context manager.
- DNSCrypt shutdown reports a second timeout cleanly and retains the process reference instead of allowing an uncaught timeout exception.
- DNSCrypt's existing adapter-loopback dependency check remains in place before manual stop.

## UI and performance

- Preserved the full Plasma Stream design: four ribbons and eleven filaments.
- Kept visibility-aware 25 FPS animation and bounded 24-sample paths.
- No visual elements were removed to obtain performance improvements.

## Packaging and versioning

- Bumped application, Windows file and product version metadata to 0.1.7.
- Added a dedicated one-file Inno Setup script and a manual installer compiler helper.
- Updated README, notices, versioned release manifest and test documentation.

## Limitations

- Windows TUN/WinTun shutdown, crash recovery, routes, adapters, DNSCrypt runtime, UAC, and GUI performance must be validated on a real Windows 10/11 x64 installation or disposable VM.
- The code deliberately does not force-delete unknown routes or virtual adapters after an unexpected engine exit. That requires exact Windows device/route ownership evidence and should not be guessed.
- The app-level license remains unselected; review Qt/PySide6 obligations and all third-party licenses before public binary distribution.
