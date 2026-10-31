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
VersionInfoCopyright=Copyright (C) 2026 Nima Zahedi
VersionInfoDescription=Raider DNS installer
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
Source: "..\dist\Raider DNS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: app
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
  { Keep the optional DNSCrypt component selected by default, including when the
    user chooses the custom setup type. They can still deselect it on the page. }
  WizardSelectComponents('app,dnscrypt');
end;

function InitializeUninstall(): Boolean;
begin
  { Removing a local DNSCrypt executable while an adapter still points at
    127.0.0.1/::1 can interrupt name resolution. The app does not silently
    rewrite adapter DNS during uninstall, so ask the user to restore it first. }
  Result := MsgBox(
    'Before uninstalling Raider DNS, open the application and use Restore Previous DNS Settings if you have DNSCrypt Proxy enabled. Stop DNSCrypt Proxy and any active sing-box tunnel as well.' + #13#10 + #13#10 +
    'The uninstaller does not change your Windows adapter DNS settings. If an adapter still points to 127.0.0.1 or ::1, uninstalling the engine can leave DNS unavailable.' + #13#10 + #13#10 +
    'Have you restored your DNS settings and stopped the external engines?',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;
