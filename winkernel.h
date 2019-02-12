#ifndef _WINKERNEL_
#define _WINKERNEL_

#pragma pack (push, 1)

typedef PVOID* PNTPROC;

typedef struct _SYSTEM_SERVICE_TABLE
{
    PNTPROC ServiceTable; 
    PULONG  CounterTable; 
    ULONG   ServiceLimit; 
    PUCHAR  ArgumentTable; 
}
SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


typedef struct _SERVICE_DESCRIPTOR_TABLE 
{
   SYSTEM_SERVICE_TABLE ntoskrnl;  
   SYSTEM_SERVICE_TABLE win32k;    
   SYSTEM_SERVICE_TABLE iis;
   SYSTEM_SERVICE_TABLE unused;    
}
SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#define SYSCALL(function) KeServiceDescriptorTable->ntoskrnl.ServiceTable[function];

// handle table constants
#define WIN2K_TABLE_ENTRY_LOCK_BIT    0x80000000
#define TABLE_LEVEL_MASK              3
#define XP_TABLE_ENTRY_LOCK_BIT       1

typedef NTSTATUS (*NtOpenPrcPointer) (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS (*ZwVirtualMemoryPtr)(
             IN HANDLE  ProcessHandle,
             IN PVOID   BaseAddress,
             IN PVOID   Buffer,
             IN ULONG   BufferLength,
             OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS (*ZwClosePtr)(IN HANDLE Handle);

typedef NTSTATUS (*NtTerminatePrcPointer)(
	IN HANDLE ProcessHandle  OPTIONAL,
	IN NTSTATUS ExitStatus);

typedef NTSTATUS (*IoCreateFilePtr)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG Disposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength,
    IN CREATE_FILE_TYPE CreateFileType,
    IN PVOID ExtraCreateParameters OPTIONAL,
    IN ULONG Options) ;




typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation, 
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts, 
	SystemConfigurationInformation, 
	SystemProcessorTimes, 
	SystemGlobalFlag, 
	SystemNotImplemented2, 
	SystemModuleInformation, 
	SystemLockInformation,
	SystemNotImplemented3, 
	SystemNotImplemented4, 
	SystemNotImplemented5, 
	SystemHandleInformation, 
	SystemObjectInformation, 
	SystemPagefileInformation, 
	SystemInstructionEmulationCounts, 
	SystemInvalidInfoClass1, 
	SystemCacheInformation, 
	SystemPoolTagInformation, 
	SystemProcessorStatistics,
	SystemDpcInformation, 
	SystemNotImplemented6,
	SystemLoadImage, 
	SystemUnloadImage, 
	SystemTimeAdjustment, 
	SystemNotImplemented7, 
	SystemNotImplemented8, 
	SystemNotImplemented9,
	SystemCrashDumpInformation, 
	SystemExceptionInformation, 
	SystemCrashDumpStateInformation, 
	SystemKernelDebuggerInformation, 
	SystemContextSwitchInformation, 
	SystemRegistryQuotaInformation, 
	SystemLoadAndCallImage,
	SystemPrioritySeparation, 
	SystemNotImplemented10,
	SystemNotImplemented11, 
	SystemInvalidInfoClass2, 
	SystemInvalidInfoClass3, 
	SystemTimeZoneInformation, 
	SystemLookasideInformation, 
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession, 
	SystemInvalidInfoClass4, 
	SystemRangeStartInformation, 
	SystemVerifierInformation, 
	SystemAddVerifier, 
	SystemSessionProcessesInformation 
} SYSTEM_INFORMATION_CLASS;


typedef struct _THREAD_BASIC_INFORMATION 
{
	NTSTATUS ExitStatus;
	PNT_TIB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


typedef NTSTATUS (*ZwQuerySystemInformationPtr)(
           IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
           IN OUT PVOID SystemInformation,
           IN ULONG SystemInformationLength,
           OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS (*ZwQueryInformationThreadPtr)(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

typedef struct _SYSTEM_THREADS 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES 
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters; 
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;


typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG  Reserved[2];
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_EX
{
	ULONG ModulesCount;
	SYSTEM_MODULE_INFORMATION Modules[0];
} SYSTEM_MODULE_INFORMATION_EX, *PSYSTEM_MODULE_INFORMATION_EX;


typedef enum _OBJECT_INFORMATION_CLASS 
{
	ObjectBasicInformation, 
	ObjectNameInformation, 
	ObjectTypeInformation, 
	ObjectAllTypesInformation,
	ObjectHandleInformation 
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_INFORMATION 
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles; 
	SYSTEM_HANDLE_INFORMATION Information[1]; 
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;



typedef struct _PORT_MESSAGE 
{
	USHORT DataSize;
	USHORT MessageSize;
	USHORT MessageType;
	USHORT VirtualRangesOffset;
	CLIENT_ID ClientId;
	ULONG MessageId;
	ULONG SectionSize;
//	UCHAR Data [];
} PORT_MESSAGE,*PPORT_MESSAGE;

typedef struct _PORT_SECTION_WRITE 
{
	ULONG Length;
	HANDLE SectionHandle;
	ULONG SectionOffset;
	ULONG ViewSize;
	PVOID ViewBase;
	PVOID TargetViewBase;
} PORT_SECTION_WRITE,*PPORT_SECTION_WRITE;

typedef struct _PORT_SECTION_READ 
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ,*PPORT_SECTION_READ;

#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY_ENTRY 
{
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY 
{
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[NUMBER_HASH_BUCKETS];
    struct _OBJECT_DIRECTORY_ENTRY **LookupBucket;
    BOOLEAN LookupFound;
    USHORT SymbolicLinkUsageCount;
    struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP 
{
    ULONG ReferenceCount;
    POBJECT_DIRECTORY DosDevicesDirectory;
    ULONG DriveMap;
    UCHAR DriveType[32];
} DEVICE_MAP, *PDEVICE_MAP;

typedef struct _OBJECT_HEADER_NAME_INFO 
{
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;


typedef struct _OBJECT_HEADER 
{
    LONG PointerCount;
    union 
	{
        LONG HandleCount;
        PSINGLE_LIST_ENTRY SEntry;
    };
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;
    union 
	{
        PVOID ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

#define OBJECT_TO_OBJECT_HEADER(o) CONTAINING_RECORD((o), OBJECT_HEADER, Body);

#define OBJECT_HEADER_TO_NAME_INFO( oh ) ((POBJECT_HEADER_NAME_INFO) \
    ((oh)->NameInfoOffset == 0 ? NULL : ((PCHAR)(oh) - (oh)->NameInfoOffset)))

typedef struct _KAPC_STATE 
{
  LIST_ENTRY ApcListHead[2];
  PVOID Process;
  BOOLEAN KernelApcInProgress;
  BOOLEAN KernelApcPending;
  BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE;


typedef struct _Idt
{
	USHORT Size;
	ULONG  Base;
} TIdt;

typedef struct _EX_PUSH_LOCK 
{
	union
	{
		struct
		{
			ULONG Waiting   :0x01;
			ULONG Exclusive :0x01;
			ULONG Shared    :0x1E;
		};

		ULONG Value;
		PVOID Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _HANDLE_TRACE_DB_ENTRY 
{
	CLIENT_ID ClientId;
	HANDLE    Handle;
	ULONG     Type;
	PVOID     StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;

typedef PVOID PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TRACE_DEBUG_INFO 
{
	ULONG                 CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[4096];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE_ENTRY 
{
	union 
	{
		PVOID                    Object;
        ULONG                    ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;
		ULONG                    Value;
    };

	union 
	{
		union 
		{
			ACCESS_MASK GrantedAccess;

            struct 
			{
				USHORT GrantedAccessIndex;
                USHORT CreatorBackTraceIndex;
            };
        };

        LONG NextFreeTableEntry;
    };

} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _EXHANDLE 
{
	union 
	{
		struct 
		{
			ULONG TagBits : 02;
			ULONG Index   : 30;
        };

        HANDLE GenericHandleOverlay;
    };

} EXHANDLE, *PEXHANDLE;

typedef PVOID PHANDLE_TABLE;

typedef struct _XP_HANDLE_TABLE 
{
	ULONG                    TableCode;
	PEPROCESS                QuotaProcess;
	PVOID                    UniqueProcessId;
	EX_PUSH_LOCK             HandleTableLock[4];
	LIST_ENTRY               HandleTableList;
	EX_PUSH_LOCK             HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	LONG                     ExtraInfoPages;
	ULONG                    FirstFree;
	ULONG                    LastFree;
	ULONG                    NextHandleNeedingPool;
	LONG                     HandleCount;
	LONG                     Flags;
	UCHAR                    StrictFIFO;
} XP_HANDLE_TABLE, *PXP_HANDLE_TABLE;


typedef struct _WIN2K_HANDLE_TABLE 
{
	ULONG                 Flags;
	LONG                  HandleCount;
	PHANDLE_TABLE_ENTRY **Table;
	PEPROCESS             QuotaProcess;
    HANDLE                UniqueProcessId;
	LONG                  FirstFreeTableEntry;
    LONG                  NextIndexNeedingPool;
	ERESOURCE             HandleTableLock;
	LIST_ENTRY            HandleTableList;
	KEVENT                HandleContentionEvent;
} WIN2K_HANDLE_TABLE , *PWIN2K_HANDLE_TABLE ;



/***********************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

extern POBJECT_TYPE *ExEventPairObjectType;
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *PsJobType;
extern POBJECT_TYPE *LpcPortObjectType;
extern POBJECT_TYPE *LpcWaitablePortObjectType;
extern POBJECT_TYPE *IoDriverObjectType;
extern POBJECT_TYPE *IoDeviceObjectType;


extern 
PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

extern 
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern 
NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG Attributes,
    IN ULONG Options);

extern
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    IN HANDLE ObjectHandle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

extern
NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PLARGE_INTEGER SectionSize OPTIONAL,
    IN ULONG Protect,
    IN ULONG Attributes,
    IN HANDLE FileHandle);

extern
NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess(
	IN HANDLE hProcess,
	IN ULONG ExitCode);

extern
NTSYSAPI
NTSTATUS
NTAPI
NtConnectPort(
     OUT PHANDLE PortHandle,
     IN PUNICODE_STRING PortName,
     IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
     IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
     IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
     OUT PULONG MaxMessageSize OPTIONAL,
     IN OUT PVOID ConnectData OPTIONAL,
     IN OUT PULONG ConnectDataLength OPTIONAL);

extern
NTSYSAPI
NTSTATUS
NTAPI
NtRequestWaitReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage);

extern
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

extern
NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG Attributes,
    IN ULONG Options);

extern 
NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId (
    IN  HANDLE    UniqueThreadId,
    OUT PVOID Thread);

extern
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(IN HANDLE ProcessId, 
						   OUT PEPROCESS *Process);

extern 
NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId (
    IN  HANDLE    UniqueThreadId,
    OUT PVOID Thread);

extern
NTSTATUS ObOpenObjectByName (IN POBJECT_ATTRIBUTES ObjectAttributes,
							 IN POBJECT_TYPE ObjectType OPTIONAL, 
							 IN KPROCESSOR_MODE AccessMode,
							 IN OUT PACCESS_STATE AccessState OPTIONAL, 
							 IN ACCESS_MASK DesiredAccess OPTIONAL,
							 IN OUT PVOID ParseContext OPTIONAL, 
							 OUT PHANDLE Handle);

extern 
void KeInitializeApc(PKAPC Apc, PKTHREAD thread,
                     UCHAR state_index,
                     PKKERNEL_ROUTINE ker_routine,
                     PKRUNDOWN_ROUTINE rd_routine,
                     PKNORMAL_ROUTINE nor_routine,
                     UCHAR mode,
                     PVOID context);
                            
extern 
void KeInsertQueueApc(PKAPC APC,
                      PVOID SysArg1,
                      PVOID SysArg2,
                      UCHAR arg4);

extern
void KeAttachProcess(PEPROCESS Process);

extern
void KeDetachProcess(void);


extern 
NTKERNELAPI 
void KeStackAttachProcess(IN PVOID Process, OUT PKAPC_STATE ApcState);


extern 
NTKERNELAPI 
void KeUnstackDetachProcess(IN OUT PKAPC_STATE ApcState);

extern
NTKERNELAPI 
NTSTATUS KeSetAffinityThread(ULONG lParam1, ULONG lParam2);

extern 
PUSHORT NtBuildNumber;

extern
NTKERNELAPI
NTSTATUS
ObReferenceObjectByName	(
	IN PUNICODE_STRING	ObjectName,
	IN ULONG			Attributes,
	IN PACCESS_STATE	PassedAccessState OPTIONAL,
	IN ACCESS_MASK		DesiredAccess OPTIONAL,
	IN POBJECT_TYPE		ObjectType OPTIONAL,
	IN KPROCESSOR_MODE	AccessMode,
	IN OUT PVOID		ParseContext OPTIONAL,
	OUT	PVOID			*Object);

extern
NTKERNELAPI 
void KiDispatchInterrupt(void);

#ifdef __cplusplus
}
#endif

#endif