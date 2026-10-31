# Installation and first launch

## Download

Use the latest release at: https://github.com/shattered-Devil/Raider-DNS/releases/latest

Download `RaiderDNS_Setup_0.1.7_x64.exe` and verify it against the `SHA256SUMS.txt` uploaded with the same release.

## Install

1. Run the installer on Windows x64. The installer may request administrator approval because the application manages system network settings.
2. Choose Full or Custom installation. The application is required. DNSCrypt Proxy is optional and selected by default; deselect it if you do not need DNSCrypt.
3. Finish installation and launch Raider DNS.
4. Review the selected adapter and current network status before changing DNS.
5. Keep the previous DNS recovery option available when testing new providers.

## Before testing sing-box TUN

Use a disposable Windows VM with a snapshot. TUN mode can create a virtual adapter and change routes. Test Start, Stop, application close, tray Exit, unexpected engine exit, and reboot recovery. Do not force-kill a live TUN process as a normal stop path. If Raider DNS says shutdown is unconfirmed, leave the application open and use the recovery/diagnostics guidance.

## Before uninstalling

Restore the previous DNS configuration. Stop DNSCrypt only after confirming that no adapter depends on its loopback resolver. Stop the sing-box tunnel gracefully and confirm the process has exited. The uninstaller does not remove unknown VPN routes or adapters.

## Troubleshooting

- If DNS configuration is correct but a resolver is unreachable, the application may report connectivity as unverified. Check upstream/firewall/VPN policy separately from adapter read-back.
- If DNSCrypt is unavailable, verify the optional component was selected or configure a valid external engine path.
- If a prior TUN session is reported as stale, inspect the exact process and adapter/route state before starting another tunnel. Do not delete arbitrary VPN interfaces.
- For bugs, provide sanitized logs and the Windows build. Remove public IP addresses, private hostnames, usernames, and other identifying network details.
