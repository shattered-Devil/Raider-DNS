# Changelog — Raider DNS v0.2 beta

## Navigation and Dashboard
- Removed the dedicated Network Intelligence and Profiles pages.
- Consolidated the connection overview, exact-match profile context and managed-engine state into Dashboard.
- Kept the dashboard focused on the current connection; adapter/Wi-Fi hardware inventory and the separate Network Recovery panel are not displayed.
- Increased navigation icon size and added unique SVG icons for all nine pages.

## DNS Providers
- Integrated reusable DNS profiles into the DNS Providers page.
- Preserved profile creation, apply, delete, import and export workflows.
- Kept exact-match network profiles opt-in and local to the device.

## Settings and localization
- Converted applicable preference checkboxes to theme-aware on/off switches.
- Fixed delayed tooltips to 750 ms and removed the tooltip-delay preference.
- Added Persian interface selection and right-to-left layout.
- Added a configurable local activity-history retention limit (100–5,000 entries).

## Engine lifecycle and network recovery
- Extended the Engine Supervisor to observe DNSCrypt Proxy and sing-box process state.
- Distinguishes a deliberate stop from an unexpected process exit.
- Emits deduplicated failure alerts on new unexpected-stop transitions.
- Does not automatically restart engines, terminate unrelated processes, or infer upstream/tunnel health from process existence.
- Kept network recovery advice non-destructive and integrated evidence-based guidance into the existing Diagnostics troubleshooting summary.
- Migrates legacy recovery history to a bounded, coarse schema that removes adapter names, SSIDs, gateway addresses and raw diagnostic details.

## Safety and maintenance
- Preserved transactional DNS apply/restore, read-back verification and rollback paths.
- Removed the obsolete adapter/Wi-Fi/PnP hardware-inventory collector from the source tree; connectivity diagnostics inspect only the selected link and DNS/connectivity behavior.
- Preserved the Plasma Stream density of four ribbons and eleven filaments.


## v0.2 beta maintenance update (version unchanged)
- Replaced operating-system inherited switch highlight colors with explicit Raider theme colors for all nine themes.
- Switch checked track, unchecked track, knob and focus outline now update whenever the application theme changes.
- Consolidated the source ZIP documentation to one current changelog, release-notes file and test report; retained required legal notices, contribution/security guidance and the current release manifest.
- Removed obsolete duplicate historical reports and unused Nuitka/launcher build scripts. Retained both supported Inno Setup paths: one-file and onedir.
- Confirmed DNSCrypt Proxy and sing-box are mandatory installer components, though neither engine is auto-started.


### sing-box packaged discovery hotfix (same v0.2 beta version)

- Frozen builds now search only beside the packaged executable and the PyInstaller extraction directory.
- Frozen builds no longer fall back to the maintainer's source checkout, so a local `engines\sing-box\sing-box.exe` cannot make a missing installer payload appear installed.
- Non-frozen source runs continue to discover the engine under the project `engines\sing-box` directory.
- Added regression coverage for both frozen-package isolation and source-checkout discovery.


### v0.2 beta packaging-safety test fix (version unchanged)

- Corrected the release-safety guard so it does not mistake local, Git-ignored installer staging inputs for binaries committed to the source repository.
- Explicitly verifies ignore rules for the maintainer-provided sing-box package, downloaded/staged DNSCrypt payload, PyInstaller build outputs, and release outputs.
- Source archives continue to exclude all compiled engine binaries.
