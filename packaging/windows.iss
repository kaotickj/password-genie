[Setup]
AppId={{753C1B9B-2BDC-4E3D-A9A7-B6328827E2E1}
AppName=Password Genie
AppVersion={#AppVersion}
AppPublisher=Kaotick Jay
DefaultDirName={localappdata}\Programs\PasswordGenie
DefaultGroupName=Password Genie
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=PasswordGenie-{#AppVersion}-windows-amd64-setup
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\PasswordGenie.exe
Compression=lzma2
SolidCompression=yes
[Files]
Source: "..\dist\PasswordGenie\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Password Genie"; Filename: "{app}\PasswordGenie.exe"
Name: "{autodesktop}\Password Genie"; Filename: "{app}\PasswordGenie.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
[Run]
Filename: "{app}\PasswordGenie.exe"; Description: "Launch Password Genie"; Flags: nowait postinstall skipifsilent
