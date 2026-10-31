# Raider DNS — Requirements

## End-user requirements

| Item | Requirement |
|---|---|
| OS | Windows 10/11 x64; Windows 11 recommended. Check current Windows 10 servicing/lifecycle status before claiming ongoing support. |
| Architecture | 64-bit Windows |
| Permissions | Standard user for viewing; elevation may be required for adapter DNS and network changes. |
| Internet | Required for live resolver tests, public-IP lookup, external benchmarks, and retrieving the optional DNSCrypt build payload. |
| DNSCrypt | Optional. DNSCrypt Proxy is installed only if selected in the installer. |
| sing-box | Not bundled. TUN mode needs a separately obtained compatible executable and configuration. |

## Source development requirements

- Python 3.11 or newer.
- PySide6 `>=6.7,<7.0` as declared in `Source Code/requirements.txt`.
- Git for source control.
- Windows is required to test actual adapter, PowerShell, UAC, and TUN behavior.

Install and run:

```powershell
cd "Source Code"
python -m pip install -r requirements.txt
python .\main.py
```

## Build requirements

- PyInstaller `>=6.22,<7` for the one-file executable.
- Inno Setup 6 or newer for the Windows installer (use the installer script included in `Source Code/installer/`).
- Internet access or a previously verified DNSCrypt Proxy package for preparing the optional engine payload.

## Validation commands

```powershell
cd "Source Code"
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

Set `QT_QPA_PLATFORM=offscreen` for headless Qt test runs where needed. The opt-in Windows DNS safety harness must only run in a disposable, snapshot-backed Windows VM with a dedicated test adapter.
