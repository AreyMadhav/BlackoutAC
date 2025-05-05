[Setup]
AppName=BlackoutAC Installer
AppVersion=1.0
DefaultDirName={autopf}\BlackoutAC
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=BlackoutAC_Installer
Compression=lzma
SolidCompression=yes

[Files]
; These will be extracted to the temp folder and manually copied later
Source: "AntiCheatDLL.dll"; Flags: dontcopy
Source: "GameLoader.exe"; Flags: dontcopy
Source: "ProxyDLL.dll"; Flags: dontcopy

[Code]
var
  GameExePath: string;

function InitializeSetup(): Boolean;
begin
  Result := GetOpenFileName('Select your game executable', GameExePath, '', 'Executable files (*.exe)|*.exe|All files (*.*)|*.*', '');
  if not Result then
  begin
    MsgBox('Game EXE selection cancelled. Setup cannot continue.', mbError, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  GameDir: string;
begin
  if CurStep = ssPostInstall then
  begin
    GameDir := ExtractFileDir(GameExePath);

    // Copy AntiCheatDLL.dll
    FileCopy(ExpandConstant('{tmp}\AntiCheatDLL.dll'), GameDir + '\AntiCheatDLL.dll', False);
    // Copy GameLoader.exe
    FileCopy(ExpandConstant('{tmp}\GameLoader.exe'), GameDir + '\GameLoader.exe', False);
    // Copy ProxyDLL.dll as UnityPlayer.dll
    FileCopy(ExpandConstant('{tmp}\ProxyDLL.dll'), GameDir + '\UnityPlayer.dll', False);

    MsgBox('BlackoutAC was successfully installed to: ' + GameDir, mbInformation, MB_OK);
  end;
end;
