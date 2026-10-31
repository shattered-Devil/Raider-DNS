# Security policy

## Supported release

Security fixes are developed against the latest published Raider DNS release. Older source snapshots may not receive updates.

## Reporting a vulnerability

Please do not publish exploit details, a working proof of concept, adapter configuration dumps, or private network information in a public issue.

Use GitHub's **Report a vulnerability** / private vulnerability reporting feature for this repository when it is enabled. If private reporting is unavailable, contact the maintainer privately through the contact method listed on their GitHub profile and request a secure channel before sending technical details.

Include the affected version, Windows version/build, impact, and minimal reproduction information. Redact public IP addresses, private hostnames, device names, account details, and recovery-file contents unless specifically required through a private channel.

## Safe testing

Raider DNS can modify machine-wide network settings. Do not test experimental DNS mutations, rollback failures, or the Windows DNS safety harness on a primary workstation. Use a disposable Windows VM with a snapshot and a dedicated virtual network adapter.
