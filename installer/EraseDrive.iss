; EraseDrive Inno Setup script
;
; Build:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\EraseDrive.iss
; Or via the wrapper:
;   .\installer\build-installer.ps1
;
; The wrapper also handles Authenticode signing (signtool.exe) when the
; ERASEDRIVE_SIGNING_PFX env var points to a valid .pfx file.

#define MyAppName        "EraseDrive"
#define MyAppVersion     "3.1.0"
#define MyAppPublisher   "DarkHorse InfoSec"
#define MyAppURL         "https://erasedrive.io"
#define MyAppExeName     "EraseDrive.bat"

[Setup]
AppId={{D8B7A2E0-4F1C-4F8B-9D33-9C9A6B5F8E12}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\DarkHorse\EraseDrive
DefaultGroupName=DarkHorse\EraseDrive
DisableProgramGroupPage=yes
LicenseFile=
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=EraseDrive-Setup-{#MyAppVersion}
SetupIconFile=..\logo.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\logo.ico
UninstallDisplayName={#MyAppName} {#MyAppVersion}
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\EraseDrive\*";          DestDir: "{app}\EraseDrive";        Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\Start-EraseDrive.ps1";  DestDir: "{app}";                   Flags: ignoreversion
Source: "..\logo.ico";              DestDir: "{app}";                   Flags: ignoreversion
Source: "..\logo.png";              DestDir: "{app}";                   Flags: ignoreversion
Source: "..\README.md";             DestDir: "{app}";                   Flags: ignoreversion
Source: "EraseDrive.bat";           DestDir: "{app}";                   Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\logo.ico"; WorkingDir: "{app}"
Name: "{group}\{#MyAppName} (Read Me)";    Filename: "{app}\README.md";       WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}";    Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}";      Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\logo.ico"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent shellexec

[Code]
function InitializeSetup(): Boolean;
var
  PSVersion: String;
  PSMajor, PSMinor: Integer;
  DotPos: Integer;
begin
  Result := True;
  if not RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine', 'PowerShellVersion', PSVersion) then
  begin
    MsgBox(
      'EraseDrive requires Windows PowerShell 5.1 or higher.' + #13#10 +
      'PowerShell was not detected on this system.',
      mbError, MB_OK);
    Result := False;
    Exit;
  end;

  DotPos := Pos('.', PSVersion);
  if DotPos = 0 then
  begin
    MsgBox('Could not parse PowerShell version: ' + PSVersion, mbError, MB_OK);
    Result := False;
    Exit;
  end;

  PSMajor := StrToIntDef(Copy(PSVersion, 1, DotPos - 1), 0);
  PSMinor := StrToIntDef(Copy(PSVersion, DotPos + 1, Length(PSVersion)), 0);

  if (PSMajor < 5) or ((PSMajor = 5) and (PSMinor < 1)) then
  begin
    MsgBox(
      'EraseDrive requires Windows PowerShell 5.1 or higher.' + #13#10 +
      'Detected: ' + PSVersion,
      mbError, MB_OK);
    Result := False;
  end;
end;
