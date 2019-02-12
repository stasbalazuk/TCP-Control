library DllInjection; 



uses 

  SysUtils, 

  windows, 

  shellapi; 



Type 



 TInjectDllData = record 

    pLoadLibrary     : pointer;  //pointer to the loadLibrary function 

    pGetProcAddress  : pointer;  //pointer to the GetProcAddress function 

    pGetModuleHandle : pointer;  //pointer to the GetModulhandle function 

    lib_name     : pointer;      //pointer to the name of the dll we will load 

  end; 



 TProcessEntry32 = record 

      dwSize              : DWORD; 

      cntUsage            : DWORD; 

      th32ProcessID       : DWORD; 

      th32DefaultHeapID   : DWORD; 

      th32ModuleID        : DWORD; 

      cntThreads          : DWORD; 

      th32ParentProcessID : DWORD; 

      pcPriClassBase      : integer; 

      dwFlags             : DWORD; 

      szExeFile           : array [0..MAX_PATH-1] of char; 

end; 



 function InjectDllToTarget(dllName : string; TargetProcessID : DWORD ; code : pointer; CodeSize : integer ): boolean; 

 procedure InjectedProc( parameter : Pointer ) ; stdcall; 

 function CreateToolhelp32Snapshot (dwFlags,th32ProcessID: cardinal) : cardinal; 

 function Process32First(hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; 

 function Process32Next(hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; 

 function FindProcess( Name : string) : dword; 

 procedure GetDebugPrivs; 

 procedure killbyPID( PID : DWORD); 



 Var 

 pCreateToolhelp32Snapshot : function (dwFlags,th32ProcessID: cardinal) : cardinal; stdcall = nil; 

 pProcess32First :  function (hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; stdcall = nil; 

 pProcess32Next  :  function (hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; stdcall = nil; 



const 

   TH32CS_SnapProcess = 2; 

   SE_DEBUG_NAME = 'SeDebugPrivilege' ; 



implementation 



procedure InjectedProc( parameter : Pointer ) ; stdcall; 

var InjectDllData : TInjectDllData; 

begin 

  InjectDllData :=  TInjectDllData(parameter^); 

  asm 

   push InjectDllData.lib_name 

   call InjectDllData.pLoadLibrary 

 { 

   you could easily call a function inside the library we just loaded 

 } 

  end; 

end; 



function InjectDllToTarget(dllName : string; TargetProcessID : DWORD ; code : pointer; CodeSize : integer ): boolean; 

 var 

  InitDataAddr , WriteAddr : pointer; 

  hProcess  , ThreadHandle : Thandle; 

  BytesWritten , TheadID : DWORD; 

  InitData : TInjectDllData; 

begin 

 result := false; 



 // it would probably be a good idea to set these 

 // from the IAT rather than assuming kernel32.dll 

 // is loaded in the same place in the remote process 

 InitData.pLoadLibrary      := GetProcAddress(LoadLibrary('kernel32.dll'), 'LoadLibraryA'); 

 InitData.pGetProcAddress   := GetProcAddress(LoadLibrary('kernel32.dll'), 'GetProcAddress'); 

 InitData.pGetModuleHandle  := GetProcAddress(LoadLibrary('kernel32.dll'), 'GetModuleHandleA'); 





 hProcess := OpenProcess( PROCESS_ALL_ACCESS, FALSE, TargetProcessID ); 

 if (hProcess = 0) then exit; 



// write the initdata strucutre to the remote prcess 

 InitDataAddr := VirtualAllocEx(hProcess , 0, sizeof(InitData)  , MEM_COMMIT , PAGE_READWRITE) ; 

 if ( InitDataAddr <> nil) then 

 begin 

  WriteProcessMemory(hProcess , InitDataAddr , (@InitData) , sizeof(InitData) , BytesWritten ); 

 end ; 



 // alocate and write the dll name to the remote process 

 InitData.lib_name := VirtualAllocEx(hProcess , 0, length(dllName) + 5  , MEM_COMMIT , PAGE_READWRITE) ; 

 if ( InitData.lib_name <> nil) then 

 begin 

    WriteProcessMemory(hProcess ,  InitData.lib_name , pchar(dllName) , length(dllName) , BytesWritten ); 

 end ; 



// write our proc that loads the dll into the remote process 

// then execute it 

 WriteAddr := VirtualAllocEx(hProcess , 0, CodeSize , MEM_COMMIT , PAGE_READWRITE) ; 

 if (WriteAddr <> nil) then 

 begin 

   WriteProcessMemory(hProcess , WriteAddr , code , CodeSize , BytesWritten ); 



   if BytesWritten = CodeSize then 

   begin 

      ThreadHandle := CreateRemoteThread( hProcess , nil , 0, WriteAddr , InitDataAddr ,0 , TheadID ); 



     WaitForSingleObject( ThreadHandle , INFINITE);  //wait for the thread to execute 



      VirtualFreeEx( hProcess , WriteAddr ,   0 , MEM_RELEASE); // free the memory we allocated 

      result := true; 

   end; 

 end; 



 // free the memory we allocated for the dll name 

 VirtualFreeEx( hProcess , InitDataAddr ,  0 , MEM_RELEASE); 

 VirtualFreeEx( hProcess , InitData.lib_name ,  0 , MEM_RELEASE); 

 CloseHandle(hProcess); 

end; 



procedure GetDebugPrivs; 

var 

  hToken: THandle; 

  tkp: TTokenPrivileges; 

  retval: dword; 

begin 



 if  (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or  TOKEN_QUERY, hToken)) then 

   begin 

     LookupPrivilegeValue(nil, SE_DEBUG_NAME  , tkp.Privileges[0].Luid); 

     tkp.PrivilegeCount := 1; 

     tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED; 

     AdjustTokenPrivileges(hToken, false, tkp, 0, nil, retval); 

   end; 

end; 





function FindProcess( Name : string) : dword; 

var 

   FSnapshotHandle : THandle; 

   FProcessEntry32 : TProcessEntry32; 

   ContinueLoop:BOOL; 

   hp : Thandle; 

begin 



   FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 

   FProcessEntry32.dwSize:=Sizeof(FProcessEntry32); 

   ContinueLoop := Process32First(FSnapshotHandle,FProcessEntry32); 

   while ContinueLoop do 

   begin 

     if Name = FProcessEntry32.szExeFile  then 

        begin 

           result := FProcessEntry32.th32ProcessID ; 

           CloseHandle(FSnapshotHandle); 

           exit; 

        end; 



       ContinueLoop := Process32Next(FSnapshotHandle,FProcessEntry32); 

   end; 

   CloseHandle(FSnapshotHandle); 

end; 



function TestToolhelpFunctions : boolean; 

var c1 : cardinal; 

begin 

  c1:=GetModuleHandle('kernel32'); 

  @pCreateToolhelp32Snapshot:=GetProcAddress(c1,'Cre  ateToolhelp32Snapshot'); 

  @pProcess32First          :=GetProcAddress(c1,'Process32First'          ); 

  @pProcess32Next           :=GetProcAddress(c1,'Process32Next'           ); 

  result := (@pCreateToolhelp32Snapshot<>nil) and (@pProcess32First<>nil) and (@pProcess32Next<>nil); 

end; 





 function CreateToolhelp32Snapshot (dwFlags,th32ProcessID: cardinal) : cardinal; 

 begin 

   result := 0; 

   if @pCreateToolhelp32Snapshot = nil then if not TestToolhelpFunctions then exit; 

   result := pCreateToolhelp32Snapshot( dwFlags , th32ProcessID ); 

 end; 



 function Process32First(hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; 

 begin 

   result := false; 

   if @pProcess32First = nil then if not TestToolhelpFunctions then exit; 

   result := pProcess32First(hSnapshot,lppe); 

 end; 



 function Process32Next(hSnapshot: cardinal; var lppe: TProcessEntry32) : bool; 

 begin 

    result := false; 

    if @pProcess32Next = nil then if not TestToolhelpFunctions then exit; 

    result := pProcess32Next(hSnapshot,lppe); 

 end; 



 procedure killbyPID( PID : DWORD); 

var hp : THANDLE; 

begin 

 hp := OpenProcess( PROCESS_TERMINATE , false, PID) ; 

 TerminateProcess(hp,0); 

end; 

end.