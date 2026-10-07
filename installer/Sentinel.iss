#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef PayloadDirectory
  #error PayloadDirectory is required
#endif
#ifndef AuxiliaryDirectory
  #error AuxiliaryDirectory is required
#endif
#ifndef Runtime
  #error Runtime is required
#endif
#ifndef OutputDirectory
  #error OutputDirectory is required
#endif

[Setup]
AppId={{D388A691-58D4-490F-A497-080F2DD66C83}
AppName=Sentinel
AppVersion={#AppVersion}
AppPublisher=ErzenXz
AppPublisherURL=https://github.com/ErzenXz/Sentinel
AppSupportURL=https://github.com/ErzenXz/Sentinel/issues
AppUpdatesURL=https://github.com/ErzenXz/Sentinel/releases
DefaultDirName={localappdata}\Programs\Sentinel
DefaultGroupName=Sentinel
PrivilegesRequired=lowest
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousPrivileges=no
MinVersion=10.0.19041
#if Runtime == "win-arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible and not arm64
ArchitecturesInstallIn64BitMode=x64compatible
#endif
SetupArchitecture=x86
AppMutex={code:RunningMutexes}
CloseApplications=no
RestartApplications=no
WizardStyle=modern dynamic
Compression=lzma2/fast
SolidCompression=yes
OutputDir={#OutputDirectory}
OutputBaseFilename=Sentinel-{#AppVersion}-{#Runtime}-setup
VersionInfoVersion={#AppVersion}
UninstallDisplayIcon={app}\Sentinel.exe
UninstallDisplayName=Sentinel
LicenseFile=..\LICENSE
InfoBeforeFile=preview.txt
Uninstallable=yes
AllowCancelDuringInstall=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#PayloadDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Sentinel\Sentinel"; Filename: "{app}\Sentinel.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Sentinel"; Filename: "{app}\Sentinel.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Code]
#include AuxiliaryDirectory + "\CleanupScript.iss"

var TransitionHandle: THandle;

function CreateTransitionMutex(SecurityAttributes: UINT_PTR; InitialOwner: BOOL; Name: String): THandle;
external 'CreateMutexW@kernel32.dll stdcall';
function CloseTransitionHandle(Handle: THandle): BOOL;
external 'CloseHandle@kernel32.dll stdcall';

procedure ExplainFailure(Message: String);
begin
  Log(Message);
  SuppressibleMsgBox(Message, mbError, MB_OK, IDOK);
end;

function ProfileKey: String;
begin
  Result := GetSHA256OfString(UTF8Encode(ExpandConstant('{localappdata}\Sentinel')));
end;

function RunningMutexes(Param: String): String;
var Key: String;
begin
  Key := ProfileKey;
  { Include the previous UI's per-session profile mutex as well. }
  Result := 'Global\Sentinel.Run.v1.' + Key + ',Local\Sentinel-' + Uppercase(Copy(Key, 1, 24));
end;

function BeginTransition: Boolean;
var ErrorCode: LongInt;
begin
  TransitionHandle := CreateTransitionMutex(0, False, 'Global\Sentinel.Setup.v1.' + ProfileKey);
  ErrorCode := DLLGetLastError;
  Result := (TransitionHandle <> 0) and (ErrorCode <> 183);
  if not Result then begin
    ExplainFailure('Sentinel is already being installed or removed, or its installation guard is unavailable. Wait and retry.');
    if TransitionHandle <> 0 then CloseTransitionHandle(TransitionHandle);
    TransitionHandle := 0;
  end;
end;

function InitializeSetup: Boolean;
var Previous: String; PreviousVersion, NextVersion: Int64;
begin
  Result := BeginTransition;
  if not Result then Exit;
  if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{D388A691-58D4-490F-A497-080F2DD66C83}_is1', 'DisplayVersion', Previous) then begin
    if not StrToVersion(Previous, PreviousVersion) or not StrToVersion('{#AppVersion}', NextVersion) then begin
      ExplainFailure('The installed version could not be read. Remove Sentinel through Windows Settings before reinstalling. Your local data will be preserved.');
      Result := False;
    end else if ComparePackedVersion(PreviousVersion, NextVersion) > 0 then begin
      ExplainFailure('A newer Sentinel version is already installed. Download the same or a newer version to repair it.');
      Result := False;
    end;
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := BeginTransition;
end;

procedure EndTransition;
begin
  if TransitionHandle <> 0 then CloseTransitionHandle(TransitionHandle);
  TransitionHandle := 0;
end;

procedure DeinitializeSetup;
begin
  EndTransition;
end;

procedure DeinitializeUninstall;
begin
  EndTransition;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var ScriptPath, Arguments: String; ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then begin
    ScriptPath := ExpandConstant('{tmp}\Sentinel-remove-task.ps1');
    if not SaveStringToFile(ScriptPath, CleanupPowerShell, False) then begin
      ExplainFailure('Could not prepare scheduled-scan cleanup. No program files were removed.');
      Abort;
    end;
    Arguments := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath + '" -ExpectedScanner "' + ExpandConstant('{app}\Sentinel.Scanner.exe') + '"';
    if not Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'), Arguments, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then begin
      ExplainFailure('Could not remove this installation''s daily scan. No program files were removed. Check Task Scheduler and retry.');
      Abort;
    end;
  end;
end;
