unit Unit1;

interface

uses
  Ring0,
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, StrUtils,
  RusCod,
  PsAPI,
  tlhelp32,
  ComCtrls, Menus,
  ProcList, DrvMgr, Stealth, UList,
  ExtCtrls, CoolTrayIcon, ImgList;

type
  TForm1 = class(TForm)
    grp1: TGroupBox;
    grp2: TGroupBox;
    tmr1: TTimer;
    PortsList: TListBox;
    chk1: TCheckBox;
    grp3: TGroupBox;
    mmo1: TMemo;
    chk2: TCheckBox;
    lbl1: TLabel;
    grp4: TGroupBox;
    mmo2: TMemo;
    lbl2: TLabel;
    Timer1: TTimer;
    grp5: TGroupBox;
    Splitter1: TSplitter;
    ListView1: TListView;
    Panel1: TPanel;
    Button1: TButton;
    Button2: TButton;
    CheckBox2: TCheckBox;
    CheckBox3: TCheckBox;
    CheckBox4: TCheckBox;
    CheckBox5: TCheckBox;
    CheckBox6: TCheckBox;
    CheckBox7: TCheckBox;
    CheckBox8: TCheckBox;
    CheckBox1: TCheckBox;
    CheckBox10: TCheckBox;
    CheckBox11: TCheckBox;
    CheckBox12: TCheckBox;
    CheckBox13: TCheckBox;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    Button6: TButton;
    CheckBox9: TCheckBox;
    CheckBox14: TCheckBox;
    ListBox1: TListBox;
    Timer2: TTimer;
    PopupMenu1: TPopupMenu;
    Kill1: TMenuItem;
    spl1: TSplitter;
    spl2: TSplitter;
    chk3: TCheckBox;
    TrayIcon1: TCoolTrayIcon;
    ImageList4: TImageList;
    ImageList3: TImageList;
    PopupMenu2: TPopupMenu;
    ShowWindow1: TMenuItem;
    N1: TMenuItem;
    Exit1: TMenuItem;
    chk4: TCheckBox;
    procedure Kill1Click(Sender: TObject);
    procedure tmr1Timer(Sender: TObject);
    procedure chk1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure FormCanResize(Sender: TObject; var NewWidth, NewHeight: Integer; var Resize: Boolean);
    procedure chk3Click(Sender: TObject);
    procedure ShowWindow1Click(Sender: TObject);
    procedure Exit1Click(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormActivate(Sender: TObject);
    procedure chk4Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
     MyPid: dword;
     MyEPROCESS: dword;
     SessionEnding: Boolean;
     Output, Errors, TMP: TStringList;
     procedure WMQueryEndSession(var Message: TMessage); message WM_QUERYENDSESSION;
  public
    { Public declarations }
  end;

function GetProcessImageFileName(hProcess: THandle; 
                                 lpImageFileName: LPTSTR;
                                 nSize: DWORD): DWORD; stdcall;
                                 external 'PSAPI.dll' 
                                 name 'GetProcessImageFileNameA';

function CreateProcessWithLogonW(
  lpUsername: PWideChar;    
  lpDomain: PWideChar;    
  lpPassword: PWideChar;    
  dwLogonFlags: DWORD;    
  lpApplicationName: PWideChar;    
  lpCommandLine: PWideChar;    
  dwCreationFlags: DWORD;    
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;    
  const lpStartupInfo: _STARTUPINFOA;    
  var lpProcessInfo: PROCESS_INFORMATION): BOOL; stdcall; external 'advapi32.dll' name 'CreateProcessWithLogonW';

var
  Form1: TForm1;
  RusCod1: TRusCod;
  List: PListStruct;
  Sel: integer;
  sItem: TListItem;
  drPath: string;

const
  drName = 'phunter';


implementation

{$R *.dfm}

procedure TForm1.WMQueryEndSession(var Message: TMessage);
begin
  SessionEnding := True;
  Message.Result := 1;
  Application.Terminate;
end;

function DevicePathToWin32Path(path:string):string;
var
  c:char;
  s:string;
  i:integer;
  _path : String;
begin
  _path := path;
  i:=posex('\', path, 2);
  i:=posex('\', path, i+1);
  result:=copy(path, i, length(path));
  delete(path, i, length(path));
  for c:='A' to 'Z' do
  begin
    setlength(s, 1000);
    if querydosdevice(pchar(string(c)+':'), pchar(s), 1000)<>0 then
    begin
      s:=pchar(s);
      if sametext(path, s) then
      begin
        result:=c+':'+result;
        exit;
      end;
    end;
  end;
  result := _path;
end;

//  Пока наш процесс не получит отладочные привилегии,
//  весь этот код работать не будет
// =============================================================================
function SetDebugPriv : Boolean;
var
  Token : THandle;
  tkp : TTokenPrivileges;
  ReturnLength : DWORD;
begin
  Result := false;
  // Получаем токен текущего процесса
  if OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, Token) then
  begin
    // Получаем Luid привилегии
    if LookupPrivilegeValue(nil, PChar('SeDebugPrivilege'), tkp.Privileges[0].Luid) then
    begin
      // Заполняем необходимые параметры
      tkp.PrivilegeCount := 1;
      tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      // Включаем привилегию
      Result := AdjustTokenPrivileges(Token, false, tkp, 0, nil, ReturnLength);
      CloseHandle(Token);
    end;
  end;
end;

//  Функция внедряет библиотеку в удаленный процесс с PID равным ProcessID
//  Для успешного внедрения нужно передать адрес функции LoadLibrary
//  и путь к загружаемой библиотеке.
//  Строку с путем необходимо разместить в адресном пространстве удаленного процесса
// =============================================================================
procedure InjectDll0(PID: dword;  DLL: pChar);
var
  BytesWritten, hProcess, hThread, TID: Cardinal;
  Parameters: pointer;
  pThreadStartRoutine: Pointer;
begin
  hProcess := OpenProcess(PROCESS_ALL_ACCESS,  False,  PID);
  Parameters := VirtualAllocEx( hProcess, nil, Length(DLL)+1, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  WriteProcessMemory(hProcess,Parameters,Pointer(DLL  ),Length(DLL)+1,BytesWritten);
  pThreadStartRoutine := GetProcAddress(GetModuleHandle('KERNEL32.DLL'), 'LoadLibraryA');
  hThread := CreateRemoteThread(hProcess,  nil,  0,  pThreadStartRoutine,  Parameters,  0,  TID);
  CloseHandle(hProcess);
end;

Function InjectDll2(ProcessID: DWORD; LibraryName: String): Integer;
const
  MAX_LIBRARYNAME   =  MAX_PATH;
  MAX_FUNCTIONNAME  =  255;
  MIN_INSTRSIZE     =  5;
Type
  PLibRemote        =  ^TLibRemote;
  TLibRemote        =  packed record
     ProcessID:     DWORD;
     LibraryName:   Array [0..MAX_LIBRARYNAME] of Char;
     LibraryHandle: HMODULE;
  end;
var  hKernel:       HMODULE;
     hProcess:      THandle;
     hThread:       THandle;
     dwNull:        Cardinal;
     lpRemote:      PLibRemote;
     lpLibRemote:   PChar;
Begin
     // Set default result of (-1), which means the injection failed
     result:=(-1);
     // Check library name and version of OS we are running on
     if (Length(LibraryName) > 0) and ((GetVersion and $80000000) = 0)then
     begin
        Result := 2;
        // Attempt to open the process
        hProcess:=OpenProcess(PROCESS_ALL_ACCESS, False, ProcessID);
        // Check process handle
        if (hProcess <> 0) then
        begin
           // Resource protection
           try
              Result:= 3;
              // Get module handle for kernel32
              hKernel:=GetModuleHandle('kernel32.dll');
              // Check handle
              if (hKernel <> 0) then
              begin
               Result := 4;
                 // Allocate memory in other process
                 lpLibRemote:=VirtualAllocEx(hProcess, nil, Succ(Length(LibraryName)), MEM_COMMIT, PAGE_READWRITE);
                 // Check memory pointer
                 if Assigned(lpLibRemote) then
                 begin
                    // Resource protection
                    try
                      Result := 5;
                       // Write the library name to the memory in other process
                       WriteProcessMemory(hProcess, lpLibRemote, PChar(LibraryName), Length(LibraryName), dwNull);
                       // Create the remote thread
                       hThread:=CreateRemoteThread(hProcess, nil, 0, GetProcAddress(hKernel, 'LoadLibraryA'), lpLibRemote, 0, dwNull);
                      // Check the thread handle
                       if (hThread <> 0) then
                       begin
                          // Resource protection
                          try
                             // Allocate a new remote injection record
                             lpRemote:=AllocMem(SizeOf(TLibRemote));
                             // Set process id
                             lpRemote^.ProcessID:=ProcessID;
                             // Copy library name
                             StrPLCopy(lpRemote^.LibraryName, LibraryName, MAX_LIBRARYNAME);
                             // Wait for the thread to complete
                             WaitForSingleObject(hThread, INFINITE);
                             // Fill in the library handle
                             GetExitCodeThread(hThread, DWORD(lpRemote^.LibraryHandle));
                             // Add to list
                             result:=1;
                          finally
                             // Close the thread handle
                             CloseHandle(hThread);
                          end;
                       end;
                    finally
                       // Free allocated memory
                       VirtualFree(lpLibRemote, 0, MEM_RELEASE);
                    end;
                 end;
              end;
           finally
              // Close the process handle
              CloseHandle(hProcess);
           end;
        end;
     end;
End;

function InjectDll1(TargetProcessID : DWORD; dllName : string): boolean;
var
  LibName  : pointer;
  hProcess , ThreadHandle : Thandle;
  BytesWritten , TheadID : DWORD;
begin
 result := false;
 hProcess := OpenProcess( PROCESS_ALL_ACCESS, FALSE, TargetProcessID );
 if (hProcess = 0) then exit;
  // alocate and write the dll name to the remote process
 LibName := VirtualAllocEx(hProcess , 0, length(dllName) + 5  , MEM_COMMIT , PAGE_READWRITE) ;
 if ( LibName <> nil) then
 begin
    WriteProcessMemory(hProcess , LibName, pchar(dllName) , length(dllName) , BytesWritten );
 end ;
 ThreadHandle := CreateRemoteThread( hProcess , nil , 0,   GetProcAddress(LoadLibrary('kernel32.dll'), 'LoadLibraryA') , LibName ,0 , TheadID );
 result := ThreadHandle <> 0;
 WaitForSingleObject( ThreadHandle , INFINITE);  //wait for the thread to execute
 // free the memory we allocated for the dll name
 VirtualFreeEx( hProcess , LibName ,  0 , MEM_RELEASE);
 CloseHandle(hProcess);
end;

function OnSystemAccount(): Boolean;
const  
  cnMaxNameLen = 254;   
var  
  sName: string;   
  dwNameLen: DWORD;   
begin
  dwNameLen := cnMaxNameLen - 1;   
  SetLength(sName, cnMaxNameLen);   
  GetUserName(PChar(sName), dwNameLen);   
  SetLength(sName, dwNameLen);   
  if UpperCase(Trim(sName)) = 'SYSTEM' then Result := True    
  else    
    Result := False;
end;

procedure GirnyyPos(Text,Str:string;Canvas:TCanvas;Left,Top:integer);
var s,s1,s2,s3:string; 
Tek:integer; 
begin 
Tek:=Left; 
s:=Text; 
s1:=copy(s,1,pos(Str,s)-1); 
delete(s,1,pos(Str,s)); 
s2:=Str; 
delete(s,1,length(Str)); 
s3:=s;
Canvas.TextOut(Tek,Top,s1);
Tek:=Tek+Canvas.TextWidth(s1); 
Canvas.Font.Style:=Canvas.Font.Style+[fsBold]; 
Canvas.TextOut(Tek,Top,s2); 
Tek:=Tek+Canvas.TextWidth(s2); 
Canvas.Font.Style:=Canvas.Font.Style-[fsBold]; 
Canvas.TextOut(Tek,Top,s3); 
end;

function GetDosOutput(ACommandLine : string; AWorkingDirectory : string): string;
var
  SecurityAttributes : TSecurityAttributes;
  StartupInfo : TStartupInfo;
  ProcessInformation: TProcessInformation;
  StdOutPipeRead, StdOutPipeWrite: THandle;
  WasOK: Boolean;
  Buffer: array[0..255] of AnsiChar;
  BytesRead: Cardinal;
  Handle: Boolean;
begin
  Result := '';
  SecurityAttributes.nLength := SizeOf(TSecurityAttributes);
  SecurityAttributes.bInheritHandle := True;
  SecurityAttributes.lpSecurityDescriptor := nil;
  CreatePipe(StdOutPipeRead, StdOutPipeWrite, @SecurityAttributes, 0);
  try
    FillChar(StartupInfo, SizeOf(TStartupInfo), 0);
    StartupInfo.cb := SizeOf(TStartupInfo);
    StartupInfo.dwFlags := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
    StartupInfo.wShowWindow := SW_HIDE;
    StartupInfo.hStdInput := StdOutPipeRead;
    StartupInfo.hStdOutput := StdOutPipeWrite;
    StartupInfo.hStdError := StdOutPipeWrite;
    FillChar(ProcessInformation, SizeOf(ProcessInformation), 0);
    Handle := CreateProcess(
      nil,
      PChar(ACommandLine),
      nil,
      nil,
      True,
      0,
      nil,
      PChar(AWorkingDirectory),
      StartupInfo,
      ProcessInformation
    );
    CloseHandle(StdOutPipeWrite);
    if Handle then
      try
        repeat
          WasOK := ReadFile(StdOutPipeRead, Buffer, 255, BytesRead, nil);
          if BytesRead > 0 then
          begin
            Buffer[BytesRead] := #0;
            Result := Result + Buffer;
          end;
        until not WasOK or (BytesRead = 0);
        WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
      finally
        CloseHandle(ProcessInformation.hThread);
        CloseHandle(ProcessInformation.hProcess);
      end;
  finally
    CloseHandle(StdOutPipeRead);
  end;
end;

//------------------------------------------------------------------------------
function GetConsoleOutput(const Command: String; var Output, Errors: TStringList): Boolean;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  SecurityAttr: TSecurityAttributes;
  PipeOutputRead: THandle;
  PipeOutputWrite: THandle;
  PipeErrorsRead: THandle;
  PipeErrorsWrite: THandle;
  Succeed: Boolean;
  Buffer: array [0..255] of Char;
  NumberOfBytesRead: DWORD;
  Stream: TMemoryStream;
begin
//------------------------------------------------------------------------------
  FillChar(ProcessInfo, SizeOf(TProcessInformation), 0);
  FillChar(SecurityAttr, SizeOf(TSecurityAttributes), 0);
  SecurityAttr.nLength := SizeOf(SecurityAttr);
  SecurityAttr.bInheritHandle := true;
  SecurityAttr.lpSecurityDescriptor := nil;
  CreatePipe(PipeOutputRead, PipeOutputWrite, @SecurityAttr, 0);
  CreatePipe(PipeErrorsRead, PipeErrorsWrite, @SecurityAttr, 0);
  FillChar(StartupInfo, SizeOf(TStartupInfo), 0); 
  StartupInfo.cb:=SizeOf(StartupInfo); 
  StartupInfo.hStdInput := 0; 
  StartupInfo.hStdOutput := PipeOutputWrite; 
  StartupInfo.hStdError := PipeErrorsWrite; 
  StartupInfo.wShowWindow := sw_Hide; 
  StartupInfo.dwFlags := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
  if  CreateProcess(nil, PChar(command), nil, nil, true, 
  CREATE_DEFAULT_ERROR_MODE or CREATE_NEW_CONSOLE or NORMAL_PRIORITY_CLASS, nil, nil, 
  StartupInfo, ProcessInfo) then begin 
    result:=true;
    CloseHandle(PipeOutputWrite); 
    CloseHandle(PipeErrorsWrite);
    Stream := TMemoryStream.Create;
    try 
      while true do begin 
        succeed := ReadFile(PipeOutputRead, Buffer, 255, NumberOfBytesRead, nil); 
        if not succeed then break; 
        Stream.Write(Buffer, NumberOfBytesRead); 
      end; 
      Stream.Position := 0; 
      Output.LoadFromStream(Stream); 
    finally 
      Stream.Free; 
    end;
    CloseHandle(PipeOutputRead);
    Stream := TMemoryStream.Create; 
    try 
      while true do begin
        succeed := ReadFile(PipeErrorsRead, Buffer, 255, NumberOfBytesRead, nil);
        if not succeed then break; 
        Stream.Write(Buffer, NumberOfBytesRead);
      end; 
      Stream.Position := 0; 
      Errors.LoadFromStream(Stream); 
    finally
      Stream.Free;
    end;
    CloseHandle(PipeErrorsRead);
    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
    CloseHandle(ProcessInfo.hProcess);
  end 
  else begin 
    result:=false; 
    CloseHandle(PipeOutputRead); 
    CloseHandle(PipeOutputWrite); 
    CloseHandle(PipeErrorsRead); 
    CloseHandle(PipeErrorsWrite); 
  end;
//------------------------------------------------------------------------------
end;

function IsRunning(sName: string): boolean; //sName
var
  han: THandle;
  ProcStruct: PROCESSENTRY32;
  sID: string;
begin
  Result := false;
  han := CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
  if han = 0 then exit;
  ProcStruct.dwSize := sizeof(PROCESSENTRY32);
  if Process32First(han, ProcStruct) then
  begin
    repeat
      sID := ExtractFileName(ProcStruct.szExeFile);
      if uppercase(copy(sId, 1, length(sName))) = uppercase(sName) then
      begin
        Result := true;
        Break;
      end;
    until not Process32Next(han, ProcStruct);
  end;
  CloseHandle(han);
end;

function ProcessFileName(PID: DWORD): string;
var
 Handle: THandle;
begin
 Result := '';
 Handle := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, PID);
 if Handle <> 0 then
   try
     SetLength(Result, MAX_PATH);
     SetLength(Result, GetModuleFileNameEx(Handle, 0, PChar(Result), MAX_PATH));
   finally
     CloseHandle(Handle);
   end;
end;

function GetPathFromPID(const PID: cardinal): string;
var
  hProcess: THandle;
  path: array[0..MAX_PATH - 1] of char;
begin
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, false, PID);
  if hProcess <> 0 then
    try
      if GetModuleFileNameEx(hProcess, 0, path, MAX_PATH) = 0 then
        RaiseLastOSError;
      result := path;
    finally
      CloseHandle(hProcess)
    end
  else
    RaiseLastOSError;
end;

function EnableDebugPrivilege(const value: Boolean): Boolean;
    const
      SE_DEBUG_NAME = 'SeDebugPrivilege';
    var
      hToken : THandle;
      tp : TOKEN_PRIVILEGES;
      d : DWORD;
begin
      Result := False;
      if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, hToken) then
       try
         if not LookupPrivilegeValue(Nil, SE_DEBUG_NAME, tp.Privileges[0].Luid) then exit;
          tp.PrivilegeCount := 1;
         if value then
          tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED//$00000002
         else
          tp.Privileges[0].Attributes := SE_PRIVILEGE_USED_FOR_ACCESS;//$80000000;
          AdjustTokenPrivileges(hToken, False, tp, SizeOf(TOKEN_PRIVILEGES), Nil, d);
          Result:= GetLastError = ERROR_SUCCESS;
       finally
         CloseHandle(hToken);
       end;
end;

procedure TForm1.tmr1Timer(Sender: TObject);
var
i,y,z: integer;
s,s1,s2: string;
stat: Boolean;
hProcess: integer;
begin
TrayIcon1.IconList := ImageList4;
TrayIcon1.CycleInterval := 50;
TrayIcon1.CycleIcons := True;
if chk1.Checked then begin
tmr1.Enabled:=False;
TMP:= TStringList.Create;
Output := TStringList.Create;
Errors := TStringList.Create;  //b
if GetConsoleOutput('netstat -ano', Output, Errors) then
begin
PortsList.Items.Text := RusCod1.DosToWin(Output.Text);
TMP.Text:=PortsList.Items.Text;
TMP.Text:=StringReplace(TMP.Text,' ','',[rfReplaceAll]);
for i:=0 to TMP.Count-1 do begin
    s:=TMP.Strings[i];
    y:=Pos('ESTABLISHED',s);
    if y > 0 then begin
    stat:=True;
    s1:=TMP.Strings[i];
    Delete(s1,y-1,12);
    Insert('PID: ',s1,y);
    mmo1.Lines.Add('> '+Trim(s1));
    z:=Pos('ESTABLISHED',s);
    if z > 0 then begin
    Delete(s,1,z+10);
    s:=Trim(s);
    s1:=ProcessFileName(StrToInt(s));
    s2:=ExtractFileName(s1);
    mmo1.Lines.Add('> '+s2+' PID -> '+s+' Path: '+s1);
    if mmo2.Lines.IndexOf(s2) = -1 then begin
    if chk2.Checked then begin
       stat:=False;
       WinExec(PChar('taskkill /F /PID '+s), SW_HIDE);
       lbl1.Font.Color:=clGreen;
       chk2.Font.Color:=clGreen;
       hProcess := OpenProcess(PROCESS_TERMINATE, false, StrToInt(s));
       if hProcess > 0 then begin
          TrayIcon1.IconList := ImageList3;
          TrayIcon1.CycleInterval := 300;
          TrayIcon1.CycleIcons := True;
          mmo1.Lines.Add('> Kill process: '+s);
          TerminateProcess(hProcess, 0);
          CloseHandle(hProcess);
       end else mmo1.Lines.Add('> Can not open process '+s);
    end else chk2.Checked:=True;
    end else stat:=True;
    end;
    if not stat then begin
       lbl1.Caption:='KILL';
       lbl1.Font.Color:=clRed;
       chk2.Font.Color:=clRed;
    end else begin
       lbl1.Caption:='WITE';
       lbl1.Font.Color:=clGreen;
       chk2.Font.Color:=clGreen;
    end;
    mmo2.Repaint;
    mmo2.Refresh;
    Form1.Repaint;
    Form1.Refresh;
end;
end;
TMP.Free;
Errors.Destroy;
Output.Destroy;
tmr1.Enabled:=True;
end;
end;
end;

procedure TForm1.chk1Click(Sender: TObject);
var 
  TokenHandle: THandle; 
  NewState, PreviousState: TTokenPrivileges; 
  ReturnLength: DWORD; 
begin
  if chk1.Checked then begin
  if FileExists('allow.sts') then begin
     mmo2.Lines.Clear;
     mmo2.Lines.LoadFromFile('allow.sts');
  end;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, TokenHandle) then
    RaiseLastWin32Error;
  try
    NewState.PrivilegeCount := 1;
    if not LookupPrivilegeValue(nil, 'SeTcbPrivilege', NewState.Privileges[0].LUID) then
    RaiseLastWin32Error;
    NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    ReturnLength := 0;
    if not AdjustTokenPrivileges(TokenHandle, False, NewState, SizeOf(NewState), PreviousState, ReturnLength) then
    RaiseLastWin32Error;
    // Do something here with the aquired priviledge
    if not AdjustTokenPrivileges(TokenHandle, False, PreviousState, ReturnLength, NewState, ReturnLength) then
    RaiseLastWin32Error;
  finally
    CloseHandle(TokenHandle);
  end;
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  si: _STARTUPINFOA;    
  pi: Process_Information;
  ProcessID: DWORD;   
  ProcessHandle: THandle;   
  ThreadHandle: THandle;
begin
  EnableDebugPrivilege(True);
  if FileExists('allow.sts') then mmo2.Lines.LoadFromFile('allow.sts');
  ListView1.DoubleBuffered := true;
  ListView1.ControlStyle:=ListView1.ControlStyle + [csOpaque];
  drPath := ExtractFilePath(paramstr(0)) + 'phunter.sys';
  InitialzeRing0Library(CALL_GATE);
  //приоритет моего приложения
  ProcessID := GetCurrentProcessID;
  ProcessHandle := OpenProcess(PROCESS_SET_INFORMATION,
    false, ProcessID);
  SetPriorityClass(ProcessHandle, REALTIME_PRIORITY_CLASS);
  ThreadHandle := GetCurrentThread;
  SetThreadPriority(ThreadHandle, THREAD_PRIORITY_TIME_CRITICAL);
  //===========================================================//
  ZeroMemory(@Si, Sizeof(si));
  si.cb := SizeOf(si);
  CreateProcessWithLogonw('SYSTEM', nil, '', 1, nil, PWideChar(ParamStr(0)), 0, nil, nil, si, pi);
  MyPid := GetCurrentProcessId();
  Button1.Click;
  TrayIcon1.IconVisible := not TrayIcon1.IconVisible;
  TrayIcon1.MinimizeToTray := True;
  MyEPROCESS := HideProcess(MyPid);
  if MyEPROCESS <= 0 then Exit;
  //FreeRing0Library();
  if OnSystemAccount then
     lbl2.Caption:='ОК'
  else
     lbl2.Caption:='NO';
     chk1.Checked:=True;
     chk2.Checked:=True;
end;

procedure TForm1.Kill1Click(Sender: TObject);
var
 Item: TListItem;
 hProcess: integer;
begin
 Item := ListView1.Selected;
 if Item <> nil then
   begin
    hProcess := OpenProcess(PROCESS_TERMINATE, false, StrToInt(Item.SubItems.Strings[0]));
    if hProcess > 0 then
     begin
       TerminateProcess(hProcess, 0);
       CloseHandle(hProcess);
     end else ShowMessage('Can not open process!');
   end;
end;

function GetState(Process: PProcessRecord): string;
begin
 if Process^.Visible then Result := 'Visible' else
   if Process^.SignalState = 1 then Result := 'Deleted' else Result := 'Hidden';
end;

procedure TForm1.Timer1Timer(Sender: TObject);
var
 Process: PProcessRecord;
 Item: TListItem;
 State, DrvText: string;
 r: integer;
 Data: PListStruct;
begin
  FreeListWidthData(List);
  List := nil;
  GetFullProcessesInfo(List);
  Data := List;
  for r := 0 to ListView1.Items.Count - 1 do
    begin
      if Data <> nil then
       begin
        Item := ListView1.Items.Item[r];
        Process := Data^.pData;
        State := GetState(Process);
        if (lstrcmp(PChar(Item.Caption), Process^.ProcessName) <> 0) or
           (Item.SubItems.Strings[0] <> IntToStr(Process^.ProcessId)) or
           (Item.SubItems.Strings[1] <> IntToStr(Process^.ParrentPID)) or
           (Item.SubItems.Strings[2] <> IntToHex(Process^.pEPROCESS, 8)) or
           (Item.SubItems.Strings[3] <> State) then
          begin
            Item.Caption := Process^.ProcessName;
            Item.SubItems.Strings[0] := IntToStr(Process^.ProcessId);
            Item.SubItems.Strings[1] := IntToStr(Process^.ParrentPID);
            Item.SubItems.Strings[2] := IntToHex(Process^.pEPROCESS, 8);
            Item.SubItems.Strings[3] := State;
          end;
        Data := Data^.pNext;
       end else ListView1.Items.Delete(ListView1.Items.Count - 1);
    end;

    while (Data <> nil) do
     begin
       Item := ListView1.Items.Add;
       Process := Data^.pData;                                                                         
       Item.Caption := Process^.ProcessName;
       Item.SubItems.Append(IntToStr(Process^.ProcessId));
       Item.SubItems.Append(IntToStr(Process^.ParrentPID));
       Item.SubItems.Append(IntToHex(Process^.pEPROCESS, 8));
       State := GetState(Process);
       Item.SubItems.Append(State);
       Data := Data^.pNext;
    end;
  FreeListWidthData(List);
  DrvText := DrvGetLogString();
  if DrvText <> '' then ListBox1.Items.Text := ListBox1.Items.Text + DrvText;
end;

procedure TForm1.Button1Click(Sender: TObject);
var
 Res: boolean;
 r: dword;
begin
  Button2.Enabled := true;
  Button1.Enabled := false;
  Button3.Enabled := false;
  Button4.Enabled := false;
  Button5.Enabled := false;
  Button6.Enabled := false;

  for r := 0 to Panel1.ControlCount - 1 do
   if Panel1.Controls[r].ClassType = TCheckBox then
     TCheckBox(Panel1.Controls[r]).Enabled := false;

  if CheckBox10.Checked or CheckBox11.Checked or
     CheckBox1.Checked  or CheckBox12.Checked or
     CheckBox13.Checked or CheckBox9.Checked or CheckBox14.Checked then
    begin
      InstallDriver(drName, PChar(drPath));
      LoadDriver(drName);
      Res := OpenDriver();
        if Res then
          begin
            if CheckBox12.Checked then SetSwapcontextHook();
            if CheckBox13.Checked then SetSyscallHook();
          end else
          begin
            ShowMessage('Driver not loaded!');
            CheckBox10.Checked := false;
            CheckBox11.Checked := false;
            CheckBox1.Checked  := false;
            CheckBox12.Checked := false;
            CheckBox13.Checked := false;
          end;
    end;
  Timer1.Enabled  := true;
end;

procedure TForm1.Button2Click(Sender: TObject);
var
 r: dword;
begin
  Timer1.Enabled  := false;
  Button2.Enabled := false;
  Button1.Enabled := true;
  Button3.Enabled := true;
  Button4.Enabled := true;
  Button5.Enabled := true;
  Button6.Enabled := true;

  for r := 0 to Panel1.ControlCount - 1 do
   if Panel1.Controls[r].ClassType = TCheckBox then
     TCheckBox(Panel1.Controls[r]).Enabled := true;

  UnhookAll();

  CloseHandle(hDriver);
  hDriver := 0;
  ListView1.Items.Clear;
end;

procedure TForm1.Button6Click(Sender: TObject);
var
 r: dword;
begin
  for r := 0 to Panel1.ControlCount - 1 do
   if Panel1.Controls[r].ClassType = TCheckBox then
     TCheckBox(Panel1.Controls[r]).Checked := false;
end;

procedure TForm1.Button3Click(Sender: TObject);
begin
 CheckBox2.Checked  := true;
 CheckBox3.Checked  := true;
 CheckBox4.Checked  := true;
 CheckBox5.Checked  := true;
 CheckBox6.Checked  := true;
 CheckBox7.Checked  := true;
 CheckBox8.Checked  := true;
 CheckBox9.Checked  := false;
 CheckBox10.Checked := false;
 CheckBox11.Checked := false;
 CheckBox1.Checked  := false;
 CheckBox12.Checked := false;
 CheckBox13.Checked := false;
 CheckBox14.Checked := false;
end;

procedure TForm1.Button4Click(Sender: TObject);
begin
 CheckBox2.Checked  := true;
 CheckBox3.Checked  := true;
 CheckBox4.Checked  := true;
 CheckBox5.Checked  := true;
 CheckBox6.Checked  := true;
 CheckBox7.Checked  := true;
 CheckBox8.Checked  := true;
 CheckBox10.Checked := true;
 CheckBox11.Checked := true;
 CheckBox1.Checked  := true;
 CheckBox12.Checked := false;
 CheckBox13.Checked := false;
 CheckBox9.Checked  := false;
 CheckBox14.Checked := false;
end;

procedure TForm1.Button5Click(Sender: TObject);
begin
 CheckBox2.Checked  := true;
 CheckBox3.Checked  := true;
 CheckBox4.Checked  := true;
 CheckBox5.Checked  := true;
 CheckBox6.Checked  := true;
 CheckBox7.Checked  := true;
 CheckBox8.Checked  := true;
 CheckBox10.Checked := true;
 CheckBox11.Checked := true;
 CheckBox1.Checked  := true;
 CheckBox12.Checked := true;
 CheckBox13.Checked := true;
 CheckBox9.Checked  := true;
 CheckBox14.Checked := true;
end;

procedure TForm1.FormCanResize(Sender: TObject; var NewWidth,
  NewHeight: Integer; var Resize: Boolean);
begin
 Resize := NewWidth = Form1.Width;
end;

procedure TForm1.chk3Click(Sender: TObject);
begin
  if chk3.Checked then mmo1.Lines.Clear;
end;

procedure TForm1.ShowWindow1Click(Sender: TObject);
begin
  TrayIcon1.ShowMainForm;
  Form1.WindowState:=wsMaximized;
end;

procedure TForm1.Exit1Click(Sender: TObject);
begin
  TrayIcon1.MinimizeToTray := False;
  Close;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  CanClose := ((not TrayIcon1.MinimizeToTray) or SessionEnding);
  if not CanClose then
  begin
    TrayIcon1.HideMainForm;
    TrayIcon1.IconVisible := True;
  end;
end;

procedure TForm1.FormActivate(Sender: TObject);
begin
  if SetDebugPriv then
     lbl2.Caption:='ОК'
  else
     lbl2.Caption:='NO';
end;

procedure TForm1.chk4Click(Sender: TObject);
begin
  if chk4.Checked then mmo1.Lines.SaveToFile('LogIP.txt');
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  if chk4.Checked then mmo1.Lines.SaveToFile('LogIP.txt');
end;

end.
