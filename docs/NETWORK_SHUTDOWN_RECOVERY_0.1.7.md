# Network shutdown and recovery notes — Raider DNS v0.1.7

## Why this changed

The sing-box TUN engine can create a virtual interface and alter Windows routes. On Windows, starting a console application with `CREATE_NO_WINDOW` can prevent it from receiving the normal console-close lifecycle. A forced process termination can skip engine cleanup and leave tunnel adapter/route state behind. The upstream sing-box Windows discussion describes this WinTun cleanup failure mode and the hidden-window workaround: https://github.com/SagerNet/sing-box/issues/3806.

## v0.1.7 behavior

1. Raider DNS starts sing-box as a console process with `STARTF_USESHOWWINDOW` and `SW_HIDE`; it does not use `CREATE_NO_WINDOW` for the long-running TUN process.
2. The app writes a durable record containing the exact PID, executable path, and config path.
3. Normal shutdown requests termination by that PID without `/F` or `/T` and waits for the process handle to report exit.
4. The app does not call `Popen.terminate()` or `Popen.kill()` on a live sing-box TUN process.
5. If graceful shutdown cannot be confirmed, the app remains open, preserves the session record and permits another stop/recovery attempt.
6. While a tunnel runs, a low-cost timer checks the `Popen` handle. An unexpected engine exit is reported and the recovery journal is retained.
7. On next launch, Raider DNS verifies the exact process image and config path before it requests shutdown. It never kills by executable name.

## Why routes are not deleted automatically

A TUN interface or default route may belong to another VPN client, virtualization tool, or network manager. Deleting routes by a broad name, adapter alias, or route prefix can break unrelated network software. If the sing-box process has already disappeared, Raider DNS warns the user and leaves network repair to Diagnostics/manual inspection unless the project has an exact, verified ownership snapshot.

## Windows validation checklist

Use a disposable Windows 11 VM with a snapshot and a test adapter. Do not begin this validation on the only machine used for work.

- Start a known-good sing-box TUN configuration as administrator.
- Confirm that the process is alive and the TUN adapter/default route are as expected.
- Stop using the Raider DNS Stop button; verify sing-box exits without `/F` and connectivity returns.
- Exit Raider DNS while the tunnel is active; verify the app waits for the graceful stop and then closes.
- Repeat from the system tray Exit action.
- Force-close the app only in the disposable VM; restart Raider DNS and verify exact PID/config recovery behavior.
- Kill sing-box externally in the VM; verify the in-app liveness warning and Diagnostics behavior.
- Confirm that unrelated VPN adapters/routes are never modified.
- Repeat on supported Windows versions and with third-party VPN/security software installed.

Do not market the TUN functionality as production-stable until this checklist has passed on actual Windows systems.
