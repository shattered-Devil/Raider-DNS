Raider DNS v0.2 beta — sing-box engine staging folder
Copyright © 2026 Nima Zahedi GitHub: Shattered-Devil

PLACE THE OFFICIAL SING-BOX WINDOWS CORE HERE.

Expected executable:
  engines\sing-box\sing-box.exe

IMPORTANT:
- Extract the COMPLETE contents of the official sing-box Windows CLI ZIP into
  this folder. Do not copy only sing-box.exe if the archive also contains DLLs,
  licenses, or supporting files.
- Keep the upstream LICENSE file in this folder (usually named LICENSE).
- Keep all upstream notices and companion files unchanged.
- Use a build that matches the target architecture supported by this installer.
- Do not place user profiles, server credentials, subscription files, or private
  keys in this distributable folder. Store profile JSON files under the user's
  Raider DNS profile directory instead.

Raider DNS and its installer discover the core automatically from:
  <Raider DNS application folder>\engines\sing-box\sing-box.exe

The installer installs sing-box as a required component named:
  sing-box TUN Engine

The application does not download an engine automatically and does not scan
arbitrary folders or PATH for another executable. If this component is not
installed, the traffic-tunnel controls report that the engine is missing.

Upstream project: https://github.com/SagerNet/sing-box
Upstream license: GPL-3.0-or-later with an additional term. Include the complete
upstream LICENSE file and applicable source/redistribution materials with any
redistributed binary. Review the upstream license before distributing a build.
Raider DNS is an independent project and is not endorsed by the upstream project.
