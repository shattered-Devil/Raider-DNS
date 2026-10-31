# Third-party components and notices

This application uses or can integrate with the following third-party components. Maintainers must keep the corresponding upstream notices and license texts with redistributed builds.

## PySide6 / Qt for Python

Raider DNS uses PySide6 and the Qt Core, GUI, and Widgets APIs. Qt for Python is available under open-source LGPLv3/GPLv3 terms or commercial licensing; some Qt modules are GPL-only. The exact license obligations depend on the Qt modules and binaries collected into a release. Review the official Qt licensing material before redistributing the PyInstaller output:

- <https://doc.qt.io/qtforpython-6/commercial/index.html>
- <https://doc.qt.io/Qt-6/licensing.html>
- <https://www.qt.io/development/open-source-lgpl-obligations>

The installer build should retain Qt and PySide shared libraries as separately replaceable files where required by the applicable license and include the relevant license texts and notices. This notice alone does not establish LGPL/GPL compliance.

## DNSCrypt Proxy

The Windows installer optionally stages DNSCrypt Proxy v2.1.20 from its official upstream Windows x64 release. `installer/prepare_dnscrypt_proxy.ps1` verifies the published archive SHA-256 before extraction and preserves upstream package files. The staging script also ensures an upstream license file and writes a third-party notice. Do not remove the upstream license or copyright notices.

Upstream: <https://github.com/DNSCrypt/dnscrypt-proxy>

## sing-box

The Connections page can launch an externally supplied sing-box executable and configuration for the TUN integration. Raider DNS does not bundle or redistribute sing-box in this source package or installer. Users who provide the executable are responsible for obtaining it from the official project and complying with its license.

Upstream: <https://github.com/SagerNet/sing-box>

## PyInstaller

PyInstaller is a build-time tool. Its license includes an exception allowing generated application bundles to be distributed under the application's chosen license, subject to the licenses of bundled dependencies. See the upstream license documentation:

- <https://pyinstaller.org/en/stable/license.html>
