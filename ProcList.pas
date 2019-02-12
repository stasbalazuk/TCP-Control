unit ProcList;

interface

uses
 windows, advApiHook, NativeAPI, TlHelp32, UList, SysUtils;

type
  PProcessRecord = ^TProcessRecord;
  TProcessRecord = packed record
    Visible: boolean;
    SignalState: dword;
    Present: boolean;
    ProcessId: dword;
    ParrentPID: dword;
    pEPROCESS: dword;
    ProcessName: array [0..255] of Char;
  end;    


procedure GetFullProcessesInfo(var List: PListStruct);
function  OpenDriver(): boolean;
function  SetSwapcontextHook(): boolean;
function  SetSyscallHook(): boolean;
function  UnhookAll(): boolean;
function  DrvGetLogString(): string;

var
 hDriver: dword = 0;
 
implementation

uses
  Unit1;

type
 JOBOBJECTINFOCLASS  =
 (
    JobObjectBasicAccountingInformation = 1,
    JobObjectBasicLimitInformation,
    JobObjectBasicProcessIdList,
    JobObjectBasicUIRestrictions,
    JobObjectSecurityLimitInformation,
    JobObjectEndOfJobTimeInformation,
    JobObjectAssociateCompletionPortInformation,
    MaxJobObjectInfoClass
 );

 PJOBOBJECT_BASIC_PROCESS_ID_LIST = ^JOBOBJECT_BASIC_PROCESS_ID_LIST;
 JOBOBJECT_BASIC_PROCESS_ID_LIST  = packed record
    NumberOfAssignedProcesses,
    NumberOfProcessIdsInList: dword;
    ProcessIdList: array [0..0] of dword;
 end;


function QueryInformationJobObject(hJob: dword; JobObjectInfoClass: JOBOBJECTINFOCLASS;
                                   lpJobObjectInfo: pointer;
                                   bJobObjectInfoLength: dword;
                                   lpReturnLength: pdword): bool; stdcall; external 'kernel32.dll';


const
 MSG_BUFF_SIZE = 4096;
 
 BASE_IOCTL = (FILE_DEVICE_UNKNOWN shl 16) or (FILE_READ_ACCESS shl 14) or METHOD_BUFFERED;
 IOCTL_SET_SWAPCONTEXT_HOOK  = BASE_IOCTL  or (1 shl 2);
 IOCTL_SWAPCONTEXT_UNHOOK    = BASE_IOCTL  or (2 shl 2);
 IOCTL_SET_SYSCALL_HOOK      = BASE_IOCTL  or (3 shl 2);
 IOCTL_SYSCALL_UNHOOK        = BASE_IOCTL  or (4 shl 2);
 IOCTL_GET_EXTEND_PSLIST     = BASE_IOCTL  or (5 shl 2);
 IOCTL_GET_NATIVE_PSLIST     = BASE_IOCTL  or (6 shl 2);
 IOCTL_GET_EPROCESS_PSLIST   = BASE_IOCTL  or (7 shl 2);
 IOCTL_SCAN_THREADS          = BASE_IOCTL  or (8 shl 2);
 IOCTL_SCAN_PSP_CID_TABLE    = BASE_IOCTL  or (9 shl 2);
 IOCTL_HANDLETABLES_LIST     = BASE_IOCTL  or (10 shl 2);
 IOCTL_GET_MESSAGES          = BASE_IOCTL  or (11 shl 2);

var
 CsrPid: dword;
 Version: TOSVersionInfo;
 Res: boolean = false;
 IsWin2K: boolean = false;
 ZwQuerySystemInfoCall: function(ASystemInformationClass: dword;
                                 ASystemInformation: Pointer;
                                 ASystemInformationLength: dword;
                                 AReturnLength: pdword): dword; stdcall;

{
 Получение списка процессов через ToolHelp API.
}
procedure GetToolHelpProcessList(var List: PListStruct);
var
 Snap: dword;
 Process: TPROCESSENTRY32;
 NewItem: PProcessRecord;
begin
  Snap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if Snap <> INVALID_HANDLE_VALUE then
     begin
      Process.dwSize := SizeOf(TPROCESSENTRY32);
      if Process32First(Snap, Process) then
         repeat
          GetMem(NewItem, SizeOf(TProcessRecord));
          ZeroMemory(NewItem, SizeOf(TProcessRecord));
          NewItem^.ProcessId  := Process.th32ProcessID;
          NewItem^.ParrentPID := Process.th32ParentProcessID;
          lstrcpy(@NewItem^.ProcessName, Process.szExeFile);
          AddItem(List, NewItem);
         until not Process32Next(Snap, Process);
      CloseHandle(Snap);
     end;
end;

{
  Получение списка процессов через ZwQuerySystemInformation.
}
procedure GetNativeProcessList(var List: PListStruct);
var
 Info: PSYSTEM_PROCESSES;
 NewItem: PProcessRecord;
 Mem: pointer;
begin
  Info := GetInfoTable(SystemProcessesAndThreadsInformation);
  Mem := Info;
  if Info = nil then Exit;
  repeat
   GetMem(NewItem, SizeOf(TProcessRecord));
   ZeroMemory(NewItem, SizeOf(TProcessRecord));
   lstrcpy(@NewItem^.ProcessName,
           PChar(WideCharToString(Info^.ProcessName.Buffer)));
   NewItem^.ProcessId  := Info^.ProcessId;
   NewItem^.ParrentPID := Info^.InheritedFromProcessId;
   AddItem(List, NewItem);
   Info := pointer(dword(info) + info^.NextEntryDelta);
  until Info^.NextEntryDelta = 0;
  VirtualFree(Mem, 0, MEM_RELEASE);
end;

{
  Получение списка процессов по списку открытых хэндлов.
  Возвращает только ProcessId.
}
procedure GetHandlesProcessList(var List: PListStruct);
var
 Info: PSYSTEM_HANDLE_INFORMATION_EX;
 NewItem: PProcessRecord;
 r: dword;
 OldPid: dword;
begin
  OldPid := 0;
  Info := GetInfoTable(SystemHandleInformation);
  if Info = nil then Exit;
  for r := 0 to Info^.NumberOfHandles do
    if Info^.Information[r].ProcessId <> OldPid then
     begin
       OldPid := Info^.Information[r].ProcessId;
       GetMem(NewItem, SizeOf(TProcessRecord));
       ZeroMemory(NewItem, SizeOf(TProcessRecord));
       NewItem^.ProcessId   := OldPid;
       AddItem(List, NewItem);
     end;
  VirtualFree(Info, 0, MEM_RELEASE);
end;

function IsPidAdded(List: PListStruct; Pid: dword): boolean;
begin
  Result := false;
  while (List <> nil) do
    begin
      if PProcessRecord(List^.pData)^.ProcessId = Pid then
        begin
          Result := true;
          Exit;
        end;
      List := List^.pNext;
    end;
end;

function IsEprocessAdded(List: PListStruct; pEPROCESS: dword): boolean;
begin
  Result := false;
  while (List <> nil) do
    begin
      if PProcessRecord(List^.pData)^.pEPROCESS = pEPROCESS then
        begin
          Result := true;
          Exit;
        end;
      List := List^.pNext;
    end;
end;

Procedure CopyListWithData(var NewList: PListStruct; List: PListStruct);
var
 NewItem: PProcessRecord;
begin
  while (List <> nil) do
    begin
      GetMem(NewItem, SizeOf(TProcessRecord));
      ZeroMemory(NewItem, SizeOf(TProcessRecord));
      NewItem^ := PProcessRecord(List^.pData)^;
      NewItem^.Visible := false;
      AddItem(NewList, NewItem);
      List := List^.pNext;
    end;
end;

function FindProcess(List: PListStruct; Pid, pEPROCESS: dword): PProcessRecord;
var
 Process: PProcessRecord;
begin
  Result := nil;
  while (List <> nil) do
    begin
      Process := List^.pData;
      if ( ((pEPROCESS <> 0) and (Process^.pEPROCESS = pEPROCESS)) or
           ((Pid <> 0) and (Process^.ProcessId = Pid)) or
           ((Pid = 0) and (pEPROCESS = 0) and (Process^.pEPROCESS = 0)
           and (Process^.ProcessId = 0))  ) then
        begin
          Result := Process;
          Exit;
        end;
      List := List^.pNext;
    end;  
end;

procedure MergeList(var List: PListStruct; List2: PListStruct);
var
 Process, Process2: PProcessRecord;
begin
  while (List2 <> nil) do
    begin
      Process := List2^.pData;
      Process2 := FindProcess(List, Process^.ProcessId, Process^.pEPROCESS);
      if Process2 = nil then AddItem(List, Process) else
        begin
         if Process2^.ProcessId   = 0  then Process2^.ProcessId   := Process^.ProcessId;
         if Process2^.pEPROCESS   = 0  then Process2^.pEPROCESS   := Process^.pEPROCESS;
         if Process2^.ParrentPID  = 0  then Process2^.ParrentPID  := Process^.ParrentPID;
         if Process2^.ProcessName = '' then Process2^.ProcessName := Process^.ProcessName;
         if Process2^.SignalState = 0  then Process2^.SignalState := Process^.SignalState;
        end;
      List2 := List2^.pNext;
    end;
end;

procedure MakeVisible(AllProc: PListStruct; CmpList: PListStruct);
var
 Process: PProcessRecord;
begin
  while (AllProc <> nil) do
    begin
      Process := AllProc^.pData;
      Process.Visible := FindProcess(CmpList, Process^.ProcessId, Process^.pEPROCESS) <> nil;
      AllProc := AllProc^.pNext;
    end;
end; 

{
  Получение списка процессов по списку окон.
  Возвращает только ProcessId.
}
procedure GetWindowsProcessList(var List: PListStruct);

 function EnumWindowsProc(hwnd: dword; PList: PPListStruct): bool; stdcall;
 var
  ProcId: dword;
  NewItem: PProcessRecord;
 begin
  GetWindowThreadProcessId(hwnd, ProcId);
   if not IsPidAdded(PList^, ProcId) then
    begin
     GetMem(NewItem, SizeOf(TProcessRecord));
     ZeroMemory(NewItem, SizeOf(TProcessRecord));
     NewItem^.ProcessId   := ProcId;
     AddItem(PList^, NewItem);
  end;
  Result := true;
 end;

begin
 EnumWindows(@EnumWindowsProc, dword(@List));
end;


{
  Системный вызов ZwQuerySystemInformation для Windows XP.
}
Function XpZwQuerySystemInfoCall(ASystemInformationClass: dword;
                                 ASystemInformation: Pointer;
                                 ASystemInformationLength: dword;
                                 AReturnLength: pdword): dword; stdcall;
asm
 pop ebp
 mov eax, $AD
 call @SystemCall
 ret $10
 @SystemCall:
 mov edx, esp
 sysenter
end;

{
  Системный вызов ZwQuerySystemInformation для Windows 2000.
}
Function Win2kZwQuerySystemInfoCall(ASystemInformationClass: dword;
                                    ASystemInformation: Pointer;
                                    ASystemInformationLength: dword;
                                    AReturnLength: pdword): dword; stdcall;
asm
 pop ebp
 mov eax, $97
 lea edx, [esp + $04]
 int $2E
 ret $10
end;

{
  Получение списка процессов через системный вызов
  ZwQuerySystemInformation.
}
procedure GetSyscallProcessList(var List: PListStruct);
var
 Info: PSYSTEM_PROCESSES;
 NewItem: PProcessRecord;
 mPtr: pointer;
 mSize: dword;
 St: NTStatus;
begin
 mSize := $4000; 
 repeat
  GetMem(mPtr, mSize);
  St := ZwQuerySystemInfoCall(SystemProcessesAndThreadsInformation,
                              mPtr, mSize, nil);
  if St = STATUS_INFO_LENGTH_MISMATCH then
    begin 
      FreeMem(mPtr);
      mSize := mSize * 2;
    end;
 until St <> STATUS_INFO_LENGTH_MISMATCH;
 if St = STATUS_SUCCESS then
  begin
    Info := mPtr;
    repeat
     GetMem(NewItem, SizeOf(TProcessRecord));
     ZeroMemory(NewItem, SizeOf(TProcessRecord));
     lstrcpy(@NewItem^.ProcessName,
             PChar(WideCharToString(Info^.ProcessName.Buffer)));
     NewItem^.ProcessId  := Info^.ProcessId;
     NewItem^.ParrentPID := Info^.InheritedFromProcessId;
     Info := pointer(dword(info) + info^.NextEntryDelta);
     AddItem(List, NewItem);
    until Info^.NextEntryDelta = 0;
  end;
 FreeMem(mPtr);
end;

{
 Получение списка процессов через проверку хэнжлов в других процессах.
}
procedure GetProcessesFromHandles(var List: PListStruct; Processes, Jobs, Threads: boolean);
var
 HandlesInfo: PSYSTEM_HANDLE_INFORMATION_EX;
 ProcessInfo: PROCESS_BASIC_INFORMATION;
 hProcess : dword;
 tHandle: dword;
 r, l     : integer;
 NewItem: PProcessRecord;
 Info: PJOBOBJECT_BASIC_PROCESS_ID_LIST;
 Size: dword;
 THRInfo: THREAD_BASIC_INFORMATION;
begin
 HandlesInfo := GetInfoTable(SystemHandleInformation);
 if HandlesInfo <> nil then
 for r := 0 to HandlesInfo^.NumberOfHandles do
   if HandlesInfo^.Information[r].ObjectTypeNumber in [OB_TYPE_PROCESS, OB_TYPE_JOB, OB_TYPE_THREAD] then
    begin
      hProcess  := OpenProcess(PROCESS_DUP_HANDLE, false,
                               HandlesInfo^.Information[r].ProcessId);
                               
      if DuplicateHandle(hProcess, HandlesInfo^.Information[r].Handle,
                         INVALID_HANDLE_VALUE, @tHandle, 0, false,
                         DUPLICATE_SAME_ACCESS) then
            begin
             case HandlesInfo^.Information[r].ObjectTypeNumber of
               OB_TYPE_PROCESS : begin
                                  if Processes and (HandlesInfo^.Information[r].ProcessId = CsrPid) then
                                  if ZwQueryInformationProcess(tHandle, ProcessBasicInformation,
                                                            @ProcessInfo,
                                                            SizeOf(PROCESS_BASIC_INFORMATION),
                                                            nil) = STATUS_SUCCESS then
                                   if not IsPidAdded(List, ProcessInfo.UniqueProcessId) then
                                     begin
                                       GetMem(NewItem, SizeOf(TProcessRecord));
                                       ZeroMemory(NewItem, SizeOf(TProcessRecord));
                                       NewItem^.ProcessId   := ProcessInfo.UniqueProcessId;
                                       NewItem^.ParrentPID  := ProcessInfo.InheritedFromUniqueProcessId;
                                       AddItem(List, NewItem);
                                     end; 
                                 end;

               OB_TYPE_JOB     : begin
                                  if Jobs then
                                   begin
                                    Size := SizeOf(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 4 * 1000;
                                    GetMem(Info, Size);
                                    Info^.NumberOfAssignedProcesses := 1000;
                                    if QueryInformationJobObject(tHandle, JobObjectBasicProcessIdList,
                                                                 Info, Size, nil) then
                                       for l := 0 to Info^.NumberOfProcessIdsInList - 1 do
                                         if not IsPidAdded(List, Info^.ProcessIdList[l]) then
                                           begin
                                            GetMem(NewItem, SizeOf(TProcessRecord));
                                            ZeroMemory(NewItem, SizeOf(TProcessRecord));
                                            NewItem^.ProcessId   := Info^.ProcessIdList[l];
                                            AddItem(List, NewItem);
                                           end;
                                    FreeMem(Info);
                                   end;
                                  end;

               OB_TYPE_THREAD  : begin
                                  if Threads then
                                  if ZwQueryInformationThread(tHandle, THREAD_BASIC_INFO,
                                                              @THRInfo,
                                                              SizeOf(THREAD_BASIC_INFORMATION),
                                                              nil) = STATUS_SUCCESS then
                                    if not IsPidAdded(List, THRInfo.ClientId.UniqueProcess) then
                                     begin
                                       GetMem(NewItem, SizeOf(TProcessRecord));
                                       ZeroMemory(NewItem, SizeOf(TProcessRecord));
                                       NewItem^.ProcessId   := THRInfo.ClientId.UniqueProcess;
                                       AddItem(List, NewItem);
                                     end;
                                 end;

             end;
             CloseHandle(tHandle);
            end;
          CloseHandle(hProcess);
        end;
 VirtualFree(HandlesInfo, 0, MEM_RELEASE);
end;

procedure DrvGetNativeProcList(var List: PListStruct);
var
 Mem: pointer;
 Process: PProcessRecord;
 NewItem: PProcessRecord;
 Size, Bytes: dword;
begin
 Size := 4096;
 repeat
   GetMem(Mem, Size);
   if DeviceIoControl(hDriver, IOCTL_GET_NATIVE_PSLIST, nil, 0, Mem, Size, Bytes, nil) then Break;
   FreeMem(Mem);
   Mem := nil;
   Size := Size * 2;
 until GetLastError() <> 24;
 Process := Mem;
 if Process <> nil then
  begin         
   while Process^.Present do
     begin
       GetMem(NewItem, SizeOf(TProcessRecord));
       ZeroMemory(NewItem, SizeOf(TProcessRecord));
       NewItem^ := Process^;
       AddItem(List, NewItem);
       Inc(Process);
      end;
   FreeMem(Mem);
 end;
end;


procedure DrvGetEprocessProcList(var List: PListStruct);
var
 Mem: pointer;
 Process: PProcessRecord;
 NewItem: PProcessRecord;
 Size, Bytes: dword;
begin
 Size := 4096;
 repeat
   GetMem(Mem, Size);
   if DeviceIoControl(hDriver, IOCTL_GET_EPROCESS_PSLIST, nil, 0, Mem, Size, Bytes, nil) then Break;
   FreeMem(Mem);
   Mem := nil;
   Size := Size * 2;
 until GetLastError() <> 24;
 Process := Mem;
 if Process <> nil then
  begin
   while Process^.Present do
     begin
       GetMem(NewItem, SizeOf(TProcessRecord));
       ZeroMemory(NewItem, SizeOf(TProcessRecord));
       NewItem^ := Process^;
       AddItem(List, NewItem);
       Inc(Process);
      end;
   FreeMem(Mem);
 end;
end;


procedure DrvGetHooksProcList(var List: PListStruct);
var
 Mem: pointer;
 Process: PProcessRecord;
 NewItem: PProcessRecord;
 Size, Bytes: dword;
begin
 Size := 4096;
 repeat
   GetMem(Mem, Size);
   if DeviceIoControl(hDriver, IOCTL_GET_EXTEND_PSLIST, nil, 0, Mem, Size, Bytes, nil) then Break;
   FreeMem(Mem);
   Mem := nil;
   Size := Size * 2;
 until GetLastError() <> 24;
 Process := Mem;
 if Process <> nil then
  begin
   while Process^.Present do
     begin
       GetMem(NewItem, SizeOf(TProcessRecord));
       ZeroMemory(NewItem, SizeOf(TProcessRecord));
       NewItem^ := Process^;
       AddItem(List, NewItem);
       Inc(Process);
      end;
   FreeMem(Mem);
 end;
end;

function DrvGetLogString(): string;
var
 Buff: array[0..MSG_BUFF_SIZE] of Char;
 Bytes: dword;
begin
  if DeviceIoControl(hDriver, IOCTL_GET_MESSAGES, nil, 0, @Buff, MSG_BUFF_SIZE, Bytes, nil)
   then Result := Buff else Result := '';
end;

function SetSyscallHook(): boolean;
var
 Bytes: dword;
begin
 Result := DeviceIoControl(hDriver, IOCTL_SET_SYSCALL_HOOK, nil, 0, nil, 0, Bytes, nil);
end;

function SetSwapcontextHook(): boolean;
var
 Bytes: dword;
begin
 Result := DeviceIoControl(hDriver, IOCTL_SET_SWAPCONTEXT_HOOK, nil, 0, nil, 0, Bytes, nil);
end;

function UnhookAll(): boolean;
var
 Bytes: dword;
begin
 Result := DeviceIoControl(hDriver, IOCTL_SWAPCONTEXT_UNHOOK, nil, 0, nil, 0, Bytes, nil) and
           DeviceIoControl(hDriver, IOCTL_SYSCALL_UNHOOK,     nil, 0, nil, 0, Bytes, nil);
end;

function GetNameByPid(Pid: dword): string;
var
 hProcess, Bytes: dword;
 Info: PROCESS_BASIC_INFORMATION;
 ProcessParametres: pointer;
 ImagePath: TUnicodeString;
 ImgPath: array[0..MAX_PATH] of WideChar;
begin
 Result := '';
 ZeroMemory(@ImgPath, MAX_PATH * SizeOf(WideChar));
 hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, false, Pid);
 if ZwQueryInformationProcess(hProcess, ProcessBasicInformation, @Info,
                              SizeOf(PROCESS_BASIC_INFORMATION), nil) = STATUS_SUCCESS then
  begin
   if ReadProcessMemory(hProcess, pointer(dword(Info.PebBaseAddress) + $10),
                        @ProcessParametres, SizeOf(pointer), Bytes) and
      ReadProcessMemory(hProcess, pointer(dword(ProcessParametres) + $38),
                        @ImagePath, SizeOf(TUnicodeString), Bytes)  and
      ReadProcessMemory(hProcess, ImagePath.Buffer, @ImgPath,
                        ImagePath.Length, Bytes) then
        begin
          Result := ExtractFileName(WideCharToString(ImgPath));
        end;
   end;
 CloseHandle(hProcess);
end;

procedure LookupProcNames(List: PListStruct);
var
 Process: PProcessRecord;
begin
  while (List <> nil) do
    begin
      Process := List^.pData;
      if (Process^.ProcessName = '') and (Process^.ProcessId <> 0) then
          lstrcpy(Process^.ProcessName, PChar(GetNameByPid(Process^.ProcessId)));
      List := List^.pNext;
    end;
end;

procedure GetFullProcessesInfo(var List: PListStruct);
var
 TLHelpList:        PListStruct;
 NativeList:        PListStruct;
 SyscallList:       PListStruct;
 HandlesList:       PListStruct;
 WindowsList:       PListStruct;
 AllProcesses:      PListStruct;
 HandlesSearchList: PListStruct;
 DrvNativeList:     PListStruct;
 DrvEprocList:      PListStruct;
 DrvHooksList:      PListStruct;
 Bytes: dword;
 
begin
 TLHelpList        := nil;
 NativeList        := nil;
 SyscallList       := nil;
 HandlesList       := nil;
 WindowsList       := nil;
 AllProcesses      := nil;
 HandlesSearchList := nil;
 DrvNativeList     := nil;
 DrvEprocList      := nil;
 DrvHooksList      := nil;
      
 GetToolHelpProcessList(TLHelpList);

 if form1.CheckBox2.Checked then GetNativeProcessList(NativeList);
 if form1.CheckBox3.Checked then GetSyscallProcessList(SyscallList);
 if form1.CheckBox4.Checked then GetHandlesProcessList(HandlesList);
 if form1.CheckBox5.Checked then GetWindowsProcessList(WindowsList);

 if form1.CheckBox6.Checked or form1.CheckBox7.Checked or form1.CheckBox8.Checked then
   GetProcessesFromHandles(HandlesSearchList, form1.CheckBox6.Checked,
                           form1.CheckBox8.Checked, form1.CheckBox7.Checked);

 if hDriver <> 0 then
   begin
     if form1.CheckBox1.Checked  then DeviceIoControl(hDriver, IOCTL_SCAN_THREADS, nil, 0, nil, 0, Bytes, nil);
     if form1.CheckBox9.Checked  then DeviceIoControl(hDriver, IOCTL_SCAN_PSP_CID_TABLE, nil, 0, nil, 0, Bytes, nil);
     if form1.CheckBox14.Checked then DeviceIoControl(hDriver, IOCTL_HANDLETABLES_LIST, nil, 0, nil, 0, Bytes, nil);
     if form1.CheckBox10.Checked then DrvGetNativeProcList(DrvNativeList);
     if form1.CheckBox11.Checked then DrvGetEprocessProcList(DrvEprocList); 
     DrvGetHooksProcList(DrvHooksList);
   end;

 MergeList(AllProcesses, TLHelpList);
 MergeList(AllProcesses, NativeList);
 MergeList(AllProcesses, SyscallList);
 MergeList(AllProcesses, HandlesList);
 MergeList(AllProcesses, WindowsList);
 MergeList(AllProcesses, HandlesSearchList);

 MergeList(AllProcesses, DrvNativeList);
 MergeList(AllProcesses, DrvEprocList);
 MergeList(AllProcesses, DrvHooksList);

 CopyListWithData(List, AllProcesses);

 LookupProcNames(List);

 MakeVisible(List, TLHelpList);

 FreeListWidthData(TLHelpList);
 FreeListWidthData(NativeList);
 FreeListWidthData(SyscallList);
 FreeListWidthData(HandlesList);
 FreeListWidthData(WindowsList);
 FreeListWidthData(HandlesSearchList);
 FreeListWidthData(DrvNativeList);
 FreeListWidthData(DrvEprocList);
 FreeListWidthData(DrvHooksList);
end;

function OpenDriver(): boolean;

begin
  hDriver := CreateFile('\\.\phunter', GENERIC_READ, 0, nil, OPEN_EXISTING, 0, 0);
  Result  := hDriver <> INVALID_HANDLE_VALUE;
  if not Result then hDriver := 0;
end;           

initialization
 Version.dwOSVersionInfoSize := SizeOf(TOSVersionInfo);
 GetVersionEx(Version);
 if Version.dwMajorVersion = 5 then
  case Version.dwBuildNumber of
   2195 : begin // Windows 2000
            Res     := true;
            IsWin2K := true;
            ZwQuerySystemInfoCall := Win2kZwQuerySystemInfoCall;
          end;
   2600 : begin // Windows XP
            Res     := true;
            ZwQuerySystemInfoCall := XpZwQuerySystemInfoCall;
          end;
  end;
 {if not Res then
   begin
     MessageBox(0, 'Not supported OS version!', 'Error!', 0);
     ExitProcess(0);
   end;}
 EnableDebugPrivilege();
 CsrPid := GetProcessId('csrss.exe');
end.
