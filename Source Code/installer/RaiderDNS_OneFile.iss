#define MyAppName "Raider DNS"
#define MyAppVersion "0.1.7"
#define MyAppPublisher "Nima Zahedi"
#define MyAppExeName "Raider DNS.exe"

[Setup]
AppId={{7D6AC0C8-33EA-4BA0-8D1E-6B39F34FCB2A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppCopyright=Copyright (C) 2026 Nima Zahedi
DefaultDirName={autopf}\Raider DNS
DefaultGroupName=Raider DNS
DisableProgramGroupPage=no
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\release
OutputBaseFilename=RaiderDNS_Setup_0.1.7_x64
SetupIconFile=..\assets\app_icon.ico
UninstallDisplayIcon={app}\Raider DNS.exe
VersionInfoVersion=0.1.7
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Raider DNS Windows DNS Management and Network Diagnostics installer
VersionInfoProductName=Raider DNS
VersionInfoProductVersion={#MyAppVersion}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
InfoBeforeFile=INSTALLATION_NOTES.txt
Uninstallable=yes

[Types]
Name: "full"; Description: "Full installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "app"; Description: "Raider DNS application (required)"; Types: full custom; Flags: fixed
Name: "dnscrypt"; Description: "DNSCrypt Proxy engine (recommended; selected by default)"; Types: full custom

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\release\Raider DNS.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: app
Source: "..\COPYRIGHT_AND_THIRD_PARTY_NOTICES.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion; Components: app
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}\licenses"; Flags: ignoreversion; Components: app
Source: "..\LICENSE_STATUS.md"; DestDir: "{app}\licenses"; Flags: ignoreversion; Components: app
Source: "payload\dnscrypt-proxy\*"; DestDir: "{app}\engines\dnscrypt-proxy"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: dnscrypt

[Icons]
Name: "{autoprograms}\Raider DNS"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Raider DNS"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Raider DNS"; Flags: nowait postinstall skipifsilent

[Code]
procedure InitializeWizard();
begin
  WizardSelectComponents('app,dnscrypt');
end;

function InitializeUninstall(): Boolean;
begin
  Result := MsgBox(
    'Before uninstalling Raider DNS, restore the previous Windows DNS settings and stop DNSCrypt Proxy only after confirming that no adapter still uses loopback DNS. Stop any active sing-box TUN tunnel using Raider DNS first.' + #13#10 + #13#10 +
    'The uninstaller does not change adapter DNS settings or remove unknown VPN/TUN routes. Removing an engine while Windows still depends on it can interrupt networking.' + #13#10 + #13#10 +
    'Have you completed these checks?',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;
