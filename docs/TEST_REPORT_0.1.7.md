# Raider DNS v0.1.7 — Automated test report

## Environment

- Build/test OS: Linux (headless)
- Python: 3.13
- PySide6: not installed
- Windows PowerShell / WinTun / Windows adapter stack: unavailable

## Results

| Check | Result |
|---|---|
| `python -m compileall -q main.py raider_dns tests` | Passed |
| `python -m unittest discover -s tests -q` | 193 collected; 192 passed; 1 skipped |
| Qt paint/render smoke test | Skipped because PySide6 is unavailable |
| Source archive integrity | Passed; 90 files; ZIP CRC validation clean |
| Tests from extracted source archive | Passed; 193 collected; 192 passed; 1 skipped |

## New v0.1.7 coverage

- Sing-box graceful stop requests target the recorded PID and omit `/F` and `/T`.
- A failed graceful stop preserves the Popen reference and recovery journal.
- An already-exited child PID is not sent to taskkill, avoiding accidental PID-reuse termination.
- Session records are atomically written and read.
- Recovery acts only on the exact process executable/config identity.
- Invalid recovery records never authorize process termination.
- Unexpected engine exits are reported while the session journal is retained.
- Stale tunnel state blocks an immediate new TUN start until network review is requested.
- DNSCrypt shutdown does not report success after an unconfirmed second timeout.
- The Qt worker pool is app-owned and bounded.
- The UI close flow pauses periodic jobs during tunnel shutdown and restores them if shutdown fails.
- Plasma Stream visual counts remain four ribbons and eleven filaments.
- Release version and installer metadata match v0.1.7.

## Archive validation

The final release ZIP was extracted into a fresh directory. ZIP CRC validation completed with no corrupt entries; compilation passed; the full test suite passed from the extracted archive (193 collected, 192 passed, 1 skipped). The archive contains 90 files. The final ZIP SHA-256 is provided in the accompanying checksum file.

## Important limitations

The tests are mainly unit tests, mocked process/IO tests, and static source guards. They do not prove Windows WinTun cleanup or real network connectivity. A Windows VM test is required for those behaviors. The Qt smoke test was skipped, so no GUI render or FPS claim is made.
