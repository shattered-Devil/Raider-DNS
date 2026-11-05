# Test report — Raider DNS v0.2 beta

Environment: source validation in a non-Windows environment. The automated suite and Python compilation run here; PySide6 GUI painting and real Windows networking are not executed.

Latest validation: **273 tests collected; 272 passed; 1 optional Qt-render test skipped** because the PySide6 GUI runtime is unavailable in this environment. `python -m compileall -q main.py raider_dns tests` passed.

The suite includes regression checks for all nine theme-specific switch color palettes, active-theme switch refresh, frozen/source sing-box executable discovery isolation, release metadata, installer component requirements, DNS transaction safety, DNSCrypt lifecycle, sing-box tunnel management, Persian RTL translation, recovery-history sanitization and process/network timeout guards.

Not run: actual Qt painting on Windows, theme switching at live GUI runtime, DPI scaling, UAC, Windows adapter DNS changes, DoH/DoT, DNSCrypt loopback, sing-box TUN routing/cleanup, installer compilation, installation, upgrade and uninstall. Validate these on a disposable Windows 10/11 test machine before public distribution.


## v0.2 beta Qt smoke-test compatibility follow-up

- Updated the Plasma Qt render smoke test to render directly into a `QImage` using `QWidget.render(QPaintDevice)`. This avoids the Qt 6 `QWidget.render(QPainter, targetOffset, ...)` overload requirement that caused a TypeError when the target offset was omitted.
- Added a structural regression test that prevents reintroducing the invalid one-argument `QPainter` overload.
- The smoke test now hides and disposes of its widget in a `finally` block so an assertion failure cannot leave its animation timer running.
- The Qt rendering test remains optional in environments without PySide6; Windows CI with the project requirements installed should execute it.


Packaging-safety clarification: installer staging inputs under `engines/sing-box/` and generated payloads under `installer/payload/` (plus PyInstaller `build/`, `dist/`, and `release/` outputs) are permitted locally but are explicitly Git-ignored. The release-safety tests reject compiled binaries elsewhere in the application source and verify these ignore rules. The source ZIP itself excludes engine executables and DLLs.


## v0.2 beta local engine-staging regression fix

- The release-safety test previously rejected local installer inputs after the maintainer staged DNSCrypt and sing-box binaries. That made a valid installer workspace fail a later test/build rerun.
- Updated the guard to permit binaries only in documented Git-ignored staging/output locations: `engines/sing-box/`, `installer/payload/`, `installer/downloads/`, `build/`, `dist/`, and `release/`.
- Added checks that every permitted staging/output location and sing-box binary pattern is covered by `.gitignore`; when run inside a Git checkout, the test also checks `git ls-files` and rejects binaries already tracked. Compiled binaries remain excluded from the source ZIP and must not be committed to Git.
- Tested the guard with representative files at the three paths reported by the Windows test output, plus a PyInstaller release output; the guard passes while those files remain in approved ignored locations.
- Final source validation: **273 tests collected; 272 passed; 1 optional Qt-render test skipped**.
