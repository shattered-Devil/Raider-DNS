# Raider DNS v0.2 beta — Release notes

Raider DNS v0.2 beta reorganizes the application around Dashboard, DNS Providers and Settings while retaining the prior DNS configuration and recovery safeguards.

### Main changes

- The old Network Intelligence and Profiles tabs are gone. Network status, managed-engine monitoring and saved network-profile context are on Dashboard; reusable DNS profiles are managed from DNS Providers.
- No adapter/Wi-Fi hardware inventory or separate Network Recovery panel is displayed.
- Settings preference toggles use explicit Raider theme accent colors for every theme. Their checked, unchecked, knob and focus colors are assigned directly by the active theme instead of inheriting the operating system's default blue palette.
- Tooltips appear after a fixed 750 ms delay.
- Persian is selectable under Settings → Appearance and switches the application layout to RTL.
- The navigation uses nine distinct, larger SVG icons.
- Engine Supervisor monitors DNSCrypt Proxy and sing-box process state and reports unexpected stops without automatically restarting or killing processes.
- Diagnostic recovery recommendations are non-destructive and remain within the existing troubleshooting workflow.
- Activity history retention is configurable from 500 to 5,000 local records.

### Important limitations

This is a source beta, not a Windows-validated production build. The available environment can run Python compilation and automated service/source tests, but does not provide the Windows network stack, UAC, PySide6 GUI rendering, Inno Setup or representative sing-box/DNSCrypt runtime. Validate the release on a disposable Windows test machine before relying on changes to system DNS or TUN routes.

Persian translation covers the application interface and RTL layout. Operating-system, third-party engine and provider-supplied error messages can remain in their original language.

### Hotfix 0.2.0-beta.1

- Fixed an application startup blocker caused by a missing `_QtQTableWidget` import alias.
- Added a regression test to prevent the wrapper base-class import from regressing.


### Hotfix 0.2.0-beta.2 — managed tunnel engines

- sing-box is an installer-managed required component. The app discovers only its bundled copy under `engines\sing-box\sing-box.exe`; the executable-path picker and legacy `singbox_path` setting are removed. The JSON profile remains user-selected.
- Added an engine status badge, managed-engine explanation, profile-folder action, JSON profile selection, and distinct theme-aware Validate / Start / Stop actions for the Connections page.
- DNSCrypt's Connections card now uses its managed local-engine status, generated configuration location, and styled secure-config / restore-and-stop actions. DNSCrypt feature controls use the same visual system.
- Added a maintainer staging script that copies the complete official sing-box CLI package, verifies the executable hash, and requires the upstream license before either Inno Setup installer can include the required component.
- Added profile checks that reject TUN profiles explicitly setting `dns_mode: disabled`. DNS routing and its resolver remain controlled by the user profile; on sing-box 1.14+, `hijack` is the default TUN DNS mode when `auto_route` is enabled. Live DNS leak verification is still required.
- Kept the version at **0.2.0-beta**. This is not a new version-number increment.

### Build requirement for maintainers

The source ZIP does not contain `sing-box.exe`. Before running `build_onefile_installer.bat`, extract the complete official Windows CLI distribution into `engines\sing-box\`, so `engines\sing-box\sing-box.exe` and its upstream `LICENSE` are present. The installer includes it as the required **sing-box TUN Engine** component. Do not distribute user profiles or secrets in the engine folder.


### Theme-aware switch color correction (same v0.2 beta version)

- Removed reliance on the operating system's `QPalette.Highlight` color for custom switches, which could appear blue regardless of the selected Raider theme.
- Added explicit checked-track, unchecked-track and knob colors for Dark, Light, Light Mild, Paper, Warm Sand, Mist Blue, Midnight, Ocean and High Contrast.
- Reapplies the palette values after each theme stylesheet change.
- This is a v0.2 beta maintenance update; the application version remains `0.2.0-beta`.

### Installer component clarification

- DNSCrypt Proxy and sing-box are both mandatory installer components. They are installed with Raider DNS but are not automatically started or activated.


### Hotfix — bundled sing-box discovery

A regression in frozen builds allowed the controller to fall back to the source checkout's `engines\sing-box` folder when the installed application did not contain the engine. Frozen builds now search only package-owned locations: beside the executable and the PyInstaller extraction root. Source-checkout discovery remains available only when running unfrozen Python. The application version remains `0.2.0-beta`.
