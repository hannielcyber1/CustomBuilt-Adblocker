; Inno Setup Script for ShieldNet Windows Installer
; Compiles a professional signed Windows installer

#define MyAppName "ShieldNet"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ShieldNet Open Source Privacy Project"
#define MyAppURL "https://github.com/shieldnet/shieldnet"
#define MyAppExeName "ShieldNet.exe"

[Setup]
AppId={{D1A8663F-5582-4EBE-A89E-7589DC289710}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=dist
OutputBaseFilename=ShieldNet-Setup-v{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start ShieldNet automatically on Windows startup"; GroupDescription: "Startup Options:"

[Files]
Source: "..\..\windows\*"; DestDir: "{app}\windows"; Flags: ignoreversion recursesubdirs
Source: "..\..\shared\*"; DestDir: "{app}\shared"; Flags: ignoreversion recursesubdirs
Source: "..\..\blocklists\*"; DestDir: "{app}\blocklists"; Flags: ignoreversion recursesubdirs
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\windows\desktop\app.py"; IconFilename: "{app}\windows\desktop\shieldnet.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\windows\desktop\app.py"; IconFilename: "{app}\windows\desktop\shieldnet.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\windows\installer\service_install.bat"; Description: "Register and start background DNS protection service"; Flags: runascurrentuser postinstall nowait
Filename: "python.exe"; Parameters: """{app}\windows\desktop\app.py"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: postinstall skipifsilent nowait

[UninstallRun]
Filename: "{app}\windows\installer\service_uninstall.bat"; Flags: runhidden
