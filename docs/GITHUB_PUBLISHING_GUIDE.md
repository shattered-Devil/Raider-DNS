# GitHub repository and v0.1.7 release publishing guide

## Repository settings

Suggested repository: `shattered-Devil/Raider-DNS` (Public), default branch `main`. Create it empty: do not pre-create a README, `.gitignore`, or license because this package supplies its own files.

Description:

> Windows DNS management and network diagnostics for Windows 10/11, with encrypted DNS, resolver benchmarking, and DNS recovery tools.

Suggested topics: `dns`, `dns-management`, `dns-over-https`, `dns-over-tls`, `dnscrypt`, `network-diagnostics`, `pyside6`, `python`, `windows`.

## Push the prepared repository

Extract `Raider-DNS-GitHub-Repository_v0.1.7.zip`. Open CMD in the extracted `Raider-DNS-GitHub-Repository` folder and run:

```cmd
git init
git branch -M main
git add .
git status
git diff --cached --stat
```

Review the staged files. Confirm there are no executables, installer outputs, local databases, activity logs, DNS recovery snapshots, credentials, `.env` files, or personal network data. Then commit and push:

```cmd
git commit -m "Initial Raider DNS repository - v0.1.7 RC"
git remote add origin https://github.com/shattered-Devil/Raider-DNS.git
git push -u origin main
```

If you choose a different repository owner/name, replace the remote URL and the hard-coded README release/issues links before pushing.

## Check GitHub Actions

After the push, open the repository's **Actions** tab and inspect the `Windows CI` workflow. It tests the source project under `Source Code/` on Windows with Python 3.11 and 3.14. Resolve failures before publishing the release. The CI run does not test actual DNS changes, UAC, external VPN coexistence, or live WinTun driver cleanup.

## Create the release

1. Open **Releases** → **Draft a new release**.
2. Create tag `v0.1.7`, targeting `main`.
3. Title it `Raider DNS v0.1.7 — Release Candidate`.
4. Paste the contents of `RELEASE_NOTES_v0.1.7.md`.
5. Attach the Windows installer you built and tested: `RaiderDNS_Setup_0.1.7_x64.exe`.
6. Optionally attach the separately tested portable EXE: `Raider DNS.exe`.
7. Generate and attach `SHA256SUMS.txt` (see below).
8. Mark the release as a **Pre-release** until the Windows networking/WinTun checklist and license review are completed.

Do not attach an executable that you have not tested. The project source archive is available from GitHub's repository/tag source downloads; an additional `RaiderDNS_PySide6_0.1.7.zip` can be attached if you want to provide the original source bundle.

## Generate checksums on Windows

Run in PowerShell from the folder containing your final assets. Adjust filenames if yours differ:

```powershell
$files = @("RaiderDNS_Setup_0.1.7_x64.exe", "Raider DNS.exe")
$lines = foreach ($file in $files) {
    if (Test-Path $file) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        "$hash  $file"
    }
}
$lines | Set-Content -Encoding ascii SHA256SUMS.txt
```

If you did not test a standalone EXE, remove it from `$files` and do not upload it.

## Add screenshots

Capture the final tested app and place safe screenshots under `Assets/Screenshots/`. Redact public IP addresses, private hostnames, adapter names, device identifiers, profile names, and recovery paths. Update the screenshot section in the root `README.md` with relative image links.

## Licensing gate

Do not add a guessed `LICENSE` file. `LICENSE_STATUS.md` explains that the application license has not been selected. Public visibility does not grant reuse rights. Review the exact PySide6/Qt modules and binaries in the installer, the relevant Qt license obligations, Python notices, DNSCrypt Proxy's upstream license, and the sing-box license (sing-box is not bundled). Resolve this before advertising the app as open-source or distributing binaries broadly.
