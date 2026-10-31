# Contributing

Thanks for helping improve Raider DNS. Changes should be small, reviewable, and preserve existing working behavior.

## Before changing code

- Read `README.md`, `RELEASE_AUDIT_0.1.7.md`, and the relevant changelog.
- Avoid broad rewrites. Keep DNS mutation and recovery logic inside the service layer rather than duplicating PowerShell commands in UI code.
- Do not silently weaken validation, transaction locking, recovery snapshots, adapter read-back, rollback, or DNSCrypt loopback checks.
- Never add private network information, user configuration, activity logs, DNS recovery snapshots, credentials, or third-party executables to a commit.

## Development checks

Run from the repository root:

```powershell
python -m pip install -r requirements.txt
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

For headless Qt test runs, set `QT_QPA_PLATFORM=offscreen`. The Windows CI workflow runs the test suite on Windows with the Qt runtime installed.

## DNS safety

Any change to system DNS must include tests for successful read-back, partial failure, rollback, recovery persistence, and the case where the selected resolver is unreachable despite correct adapter settings. Do not use the opt-in Windows DNS safety harness outside a disposable, snapshot-backed Windows VM.

## Pull requests

Describe the problem, the behavior change, tests run, platform limitations, and whether real Windows networking was exercised. Include screenshots for material UI changes. Never claim that mocked tests prove real adapter behavior.
