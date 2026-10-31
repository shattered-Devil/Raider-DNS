# Build from source (Windows)

Run commands from the `Source Code` directory. Use a clean Windows build machine for release packaging.

## 1. Install runtime dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install "PyInstaller>=6.22,<7"
```

## 2. Run compile and tests

```powershell
python -m compileall -q main.py raider_dns tests
python -m unittest discover -s tests -v
```

Do not treat a passing mocked test suite as proof of real Windows adapter or WinTun behavior.

## 3. Build one-file app executable

```cmd
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "Raider DNS" --icon "assets\app_icon.ico" --version-file "installer\version_info.txt" --add-data "assets;assets" --add-data "COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt;licenses" --distpath "release" main.py
```

Expected: `Source Code\release\Raider DNS.exe`. Test this executable on Windows before packaging.

## 4. Prepare DNSCrypt Proxy

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\installer\prepare_dnscrypt_proxy.ps1"
```

The script retrieves the pinned Windows x64 archive and verifies its SHA-256 before staging the optional component. Do not replace the checksum verification with an unverified archive.

## 5. Build the installer

Install Inno Setup 6 or newer, then open `installer\RaiderDNS_OneFile.iss` in Inno Setup Compiler and compile (F9), or use the included `build_onefile_installer.bat`.

Expected installer: `Source Code\release\RaiderDNS_Setup_0.1.7_x64.exe`.

## 6. Test the actual release artifacts

On a clean Windows VM, test installation, optional DNSCrypt selection, launch, upgrade, uninstall, DNS recovery, and sing-box lifecycle. Test actual WinTun route cleanup before describing the TUN feature as stable.
