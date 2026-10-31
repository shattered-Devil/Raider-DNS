# Changelog — Raider DNS

All notable application changes are documented here. Detailed historical release notes are in [`docs/changelogs/`](docs/changelogs/).

## [0.1.7] — 2026-10-31

### Stability and network recovery
- Changed long-running sing-box startup to a hidden-console lifecycle rather than `CREATE_NO_WINDOW`.
- Kept shutdown PID-specific and non-forced; the app refuses normal close if process exit cannot be confirmed.
- Added persistent exact-process session records, startup inspection, unexpected-exit monitoring, and a stale-session start guard.
- Moved tunnel cleanup into a bounded background close workflow and restored timers/UI if shutdown fails.
- Moved to an application-owned bounded Qt worker pool.
- Hardened DNSCrypt process logging and shutdown timeout handling.

### UI and performance
- Preserved four broad Plasma Stream ribbons and eleven fine filaments.
- Retained visibility-aware 25 FPS animation and bounded 24-segment paths.

### Packaging
- Updated application and Windows product/file metadata to 0.1.7.
- Added a dedicated one-file Inno Setup script and manual installer helper.

### Known limitations
- Real Windows WinTun cleanup, adapter/route restoration, DNS transports, UAC, GUI performance, and installer behavior still require Windows testing.
- Application-level license remains unselected.

## Previous versions

See the versioned changelogs in [`docs/changelogs/`](docs/changelogs/), including v0.1.6.4 and earlier.
